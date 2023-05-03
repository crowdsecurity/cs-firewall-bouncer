package cmd

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/backend"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/version"
)

const (
	name = "crowdsec-firewall-bouncer"
)

func backendCleanup(backend *backend.BackendCTX) {
	log.Info("Shutting down backend")
	if err := backend.ShutDown(); err != nil {
		log.Errorf("unable to shutdown backend: %s", err)
	}
}

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)

	select {
	case <-signalChan:
		return fmt.Errorf("received SIGTERM")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func deleteDecisions(backend *backend.BackendCTX, decisions []*models.Decision, config *cfg.BouncerConfig) {
	nbDeletedDecisions := 0
	for _, d := range decisions {
		if !slices.Contains(config.SupportedDecisionsTypes, strings.ToLower(*d.Type)) {
			log.Debugf("decisions for ip '%s' will not be deleted because its type is '%s'", *d.Value, *d.Type)
			continue
		}
		if err := backend.Delete(d); err != nil {
			if !strings.Contains(err.Error(), "netlink receive: no such file or directory") {
				log.Errorf("unable to delete decision for '%s': %s", *d.Value, err)
			}
			continue
		}
		log.Debugf("deleted '%s'", *d.Value)
		nbDeletedDecisions++
	}

	noun := "decisions"
	if nbDeletedDecisions == 1 {
		noun = "decision"
	}
	if nbDeletedDecisions > 0 {
		log.Debug("committing expired decisions")
		if err := backend.Commit(); err != nil {
			log.Errorf("unable to commit expired decisions %v", err)
			return
		}
		log.Debug("committed expired decisions")
		log.Infof("%d %s deleted", nbDeletedDecisions, noun)
	}
}

func addDecisions(backend *backend.BackendCTX, decisions []*models.Decision, config *cfg.BouncerConfig) {
	nbNewDecisions := 0
	for _, d := range decisions {
		if !slices.Contains(config.SupportedDecisionsTypes, strings.ToLower(*d.Type)) {
			log.Debugf("decisions for ip '%s' will not be added because its type is '%s'", *d.Value, *d.Type)
			continue
		}
		if err := backend.Add(d); err != nil {
			log.Errorf("unable to insert decision for '%s': %s", *d.Value, err)
			continue
		}

		log.Debugf("Adding '%s' for '%s'", *d.Value, *d.Duration)
		nbNewDecisions++
	}

	noun := "decisions"
	if nbNewDecisions == 1 {
		noun = "decision"
	}
	if nbNewDecisions > 0 {
		log.Debug("committing added decisions")
		if err := backend.Commit(); err != nil {
			log.Errorf("unable to commit add decisions %v", err)
			return
		}
		log.Debug("committed added decisions")
		log.Infof("%d %s added", nbNewDecisions, noun)
	}
}

func Execute() error {
	var err error
	configPath := flag.String("c", "", "path to crowdsec-firewall-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("V", false, "display version and exit")
	testConfig := flag.Bool("t", false, "test config and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Print(version.ShowStr())
		os.Exit(0)
	}

	log.Infof("crowdsec-firewall-bouncer %s", version.VersionStr())

	if configPath == nil || *configPath == "" {
		return fmt.Errorf("configuration file is required")
	}

	configBytes, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	config, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	backend, err := backend.NewBackend(config)
	if err != nil {
		return err
	}

	if *testConfig {
		log.Info("config is valid")
		os.Exit(0)
	}

	if err = backend.Init(); err != nil {
		return err
	}

	defer backendCleanup(backend)

	bouncer := &csbouncer.StreamBouncer{}
	err = bouncer.ConfigReader(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to configure bouncer: %w", err)
	}
	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.VersionStr())
	if err := bouncer.Init(); err != nil {
		return err
	}

	if bouncer.InsecureSkipVerify != nil {
		log.Debugf("InsecureSkipVerify is set to %t", *bouncer.InsecureSkipVerify)
	}

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("stream api init failed")
	})

	if config.PrometheusConfig.Enabled {
		if config.Mode == cfg.IptablesMode || config.Mode == cfg.NftablesMode {
			go backend.CollectMetrics()
			prometheus.MustRegister(metrics.TotalDroppedBytes, metrics.TotalDroppedPackets, metrics.TotalActiveBannedIPs)
		}
		prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			listenOn := net.JoinHostPort(
				config.PrometheusConfig.ListenAddress,
				config.PrometheusConfig.ListenPort,
			)
			log.Infof("Serving metrics at %s", listenOn+"/metrics")
			log.Error(http.ListenAndServe(listenOn, nil))
		}()
	}
	g.Go(func() error {
		log.Infof("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				return nil
			case decisions := <-bouncer.Stream:
				if decisions == nil {
					continue
				}
				deleteDecisions(backend, decisions.Deleted, config)
				addDecisions(backend, decisions.New, config)
			}
		}
	})

	if config.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("Failed to notify: %v", err)
		}
		g.Go(func() error {
			return HandleSignals(ctx)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}
