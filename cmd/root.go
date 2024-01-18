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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	csbouncer "github.com/blind-oracle/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/backend"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

const name = "crowdsec-firewall-bouncer"

func backendCleanup(backend *backend.BackendCTX) {
	log.Info("Shutting down backend")

	if err := backend.ShutDown(); err != nil {
		log.Errorf("while shutting down backend: %s", err)
	}
}

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return fmt.Errorf("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return fmt.Errorf("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func Execute() error {
	configPath := flag.String("c", "", "path to crowdsec-firewall-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("V", false, "display version and exit (deprecated)")
	flag.BoolVar(bouncerVersion, "version", *bouncerVersion, "display version and exit")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Print(version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		return fmt.Errorf("configuration file is required")
	}

	configBytes, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configBytes))
		return nil
	}

	config, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *verbose && log.GetLevel() < log.DebugLevel {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("Starting crowdsec-firewall-bouncer %s", version.String())

	backend, err := backend.NewBackend(config)
	if err != nil {
		return err
	}

	if err = backend.Init(); err != nil {
		return err
	}

	defer backendCleanup(backend)

	bouncer := &csbouncer.LiveBouncer{}

	err = bouncer.ConfigReader(bytes.NewReader(configBytes))
	if err != nil {
		return err
	}

	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.String())
	if err := bouncer.Init(); err != nil {
		return fmt.Errorf("unable to configure bouncer: %w", err)
	}

	if *testConfig {
		log.Info("config is valid")
		return nil
	}

	if bouncer.InsecureSkipVerify != nil {
		log.Debugf("InsecureSkipVerify is set to %t", *bouncer.InsecureSkipVerify)
	}

	g, ctx := errgroup.WithContext(context.Background())

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

	tickerIntervalDuration, err := time.ParseDuration(config.UpdateFrequency)
	if err != nil {
		return fmt.Errorf("unable to parse lapi update interval '%s': %w", config.UpdateFrequency, err)
	}

	g.Go(func() error {
		log.Infof("Processing decisions . . .")
		ticker := time.NewTicker(tickerIntervalDuration)
		for {
			select {
			case <-ctx.Done():
				return nil

			case <-ticker.C:
				decisions, err := bouncer.Get(config.DecisionsScopes, config.DecisionsType)
				if err != nil {
					log.Errorf("Unable to fetch decisions: %s", err)
					continue
				}

				log.Debugf("Got %d decisions", len(*decisions))

				added, deleted, err := backend.Set(*decisions)
				if err != nil {
					log.Errorf("Unable to set decisions: %s", err)
					continue
				}

				if added > 0 || deleted > 0 {
					err := backend.Commit()
					if err != nil {
						log.Errorf("Unable to commit decisions: %s", err)
						continue
					}

					log.Infof("Decisions added: %d, deleted: %d", added, deleted)
				}
			}
		}
	})

	if config.Daemon != nil {
		if *config.Daemon {
			log.Debug("Ignoring deprecated 'daemonize' option")
		} else {
			log.Warn("The 'daemonize' config option is deprecated and treated as always true")
		}
	}

	_ = csdaemon.NotifySystemd(log.StandardLogger())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}
