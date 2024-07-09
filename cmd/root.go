package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	io_prometheus_client "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/backend"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/metrics"
)

const bouncerType = "crowdsec-firewall-bouncer"

var metricsInterval time.Duration

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
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
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

		log.Debugf("deleted %s", *d.Value)

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

func getLabelValue(labels []*io_prometheus_client.LabelPair, key string) string {

	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

// metricsUpdater receives a metrics struct with basic data and populates it with the current metrics.
func metricsUpdater(met *models.RemediationComponentsMetrics) {
	log.Debugf("Updating metrics")

	//Most of the common fields are set automatically by the metrics provider
	//We only need to care about the metrics themselves

	promMetrics, err := prometheus.DefaultGatherer.Gather()

	if err != nil {
		log.Errorf("unable to gather prometheus metrics: %s", err)
		return
	}

	met.Metrics = append(met.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(metricsInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	})

	for _, metricFamily := range promMetrics {
		for _, metric := range metricFamily.GetMetric() {
			switch metricFamily.GetName() {
			case metrics.ActiveBannedIPsMetricName:
				labels := metric.GetLabel()
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("active_decisions"),
					Value: ptr.Of(metric.GetGauge().GetValue()),
					Labels: map[string]string{
						"origin":  getLabelValue(labels, "origin"),
						"ip_type": getLabelValue(labels, "ip_type"),
					},
					Unit: ptr.Of("ip"),
				})
			case metrics.DroppedBytesMetricName:
				labels := metric.GetLabel()
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("dropped"),
					Value: ptr.Of(metric.GetGauge().GetValue()),
					Labels: map[string]string{
						"origin":  getLabelValue(labels, "origin"),
						"ip_type": getLabelValue(labels, "ip_type"),
					},
					Unit: ptr.Of("byte"),
				})
			case metrics.DroppedPacketsMetricName:
				labels := metric.GetLabel()
				met.Metrics[0].Items = append(met.Metrics[0].Items, &models.MetricsDetailItem{
					Name:  ptr.Of("dropped"),
					Value: ptr.Of(metric.GetGauge().GetValue()),
					Labels: map[string]string{
						"origin":  getLabelValue(labels, "origin"),
						"ip_type": getLabelValue(labels, "ip_type"),
					},
					Unit: ptr.Of("packet"),
				})
			}
		}
	}
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
		return errors.New("configuration file is required")
	}

	configMerged, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configMerged))
		return nil
	}

	configExpanded := csstring.StrictExpand(string(configMerged), os.LookupEnv)

	config, err := cfg.NewConfig(strings.NewReader(configExpanded))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *verbose && log.GetLevel() < log.DebugLevel {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("Starting %s %s", bouncerType, version.String())

	backend, err := backend.NewBackend(config)
	if err != nil {
		return err
	}

	if err = backend.Init(); err != nil {
		return err
	}

	defer backendCleanup(backend)

	bouncer := &csbouncer.StreamBouncer{}

	err = bouncer.ConfigReader(strings.NewReader(configExpanded))
	if err != nil {
		return err
	}

	bouncer.UserAgent = fmt.Sprintf("%s/%s", bouncerType, version.String())
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

	g.Go(func() error {
		bouncer.Run(ctx)
		return errors.New("bouncer stream halted")
	})

	metricsInterval = *bouncer.MetricsInterval

	metricsProvider, err := csbouncer.NewMetricsProvider(bouncer.APIClient, bouncerType, metricsInterval, metricsUpdater, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("unable to create metrics provider: %w", err)
	}

	g.Go(func() error {
		return metricsProvider.Run(ctx)
	})

	if config.Mode == cfg.IptablesMode || config.Mode == cfg.NftablesMode || config.Mode == cfg.IpsetMode || config.Mode == cfg.PfMode {
		go backend.CollectMetrics()
		if config.Mode == cfg.IpsetMode {
			prometheus.MustRegister(metrics.TotalActiveBannedIPs)
		} else {
			prometheus.MustRegister(metrics.TotalDroppedBytes, metrics.TotalDroppedPackets, metrics.TotalActiveBannedIPs)
		}
	}

	prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)
	if config.PrometheusConfig.Enabled {
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

	if config.Daemon != nil {
		if *config.Daemon {
			log.Debug("Ignoring deprecated 'daemonize' option")
		} else {
			log.Warn("The 'daemonize' config option is deprecated and treated as always true")
		}
	}

	_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}
