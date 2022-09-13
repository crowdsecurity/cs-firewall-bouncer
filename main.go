package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/version"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"gopkg.in/tomb.v2"
)

const (
	name = "crowdsec-firewall-bouncer"
)

var t tomb.Tomb

var totalDroppedPackets = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fw_bouncer_dropped_packets",
	Help: "Denotes the number of total dropped packets because of rule(s) created by crowdsec",
})

var totalDroppedBytes = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fw_bouncer_dropped_bytes",
	Help: "Denotes the number of total dropped bytes because of rule(s) created by crowdsec",
})

var totalActiveBannedIPs = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fw_bouncer_banned_ips",
	Help: "Denotes the number of IPs which are currently banned",
})

func termHandler(sig os.Signal, backend *backendCTX) error {
	if err := backend.ShutDown(); err != nil {
		return err
	}
	return nil
}

func backendCleanup(backend *backendCTX) {
	if err := backend.ShutDown(); err != nil {
		log.Errorf("unable to shutdown backend: %s", err)
	}
}

func HandleSignals(backend *backendCTX) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGTERM)

	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				if err := termHandler(s, backend); err != nil {
					log.Fatalf("shutdown fail: %s", err)
				}
				exitChan <- 0
			}
		}
	}()

	code := <-exitChan
	log.Infof("Shutting down firewall-bouncer service")
	os.Exit(code)
}

func inSlice(s string, slice []string) bool {
	for _, str := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func main() {
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

	log.AddHook(&writer.Hook{ // Send logs with level fatal to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	log.Infof("crowdsec-firewall-bouncer %s", version.VersionStr())

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	config, err := newConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *testConfig {
		log.Info("config is valid")
		os.Exit(0)
	}

	configureLogging(config)

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	backend, err := newBackend(config)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if err := backend.Init(); err != nil {
		log.Fatalf(err.Error())
	}
	// No call to fatalf after this point
	defer backendCleanup(backend)

	bouncer := &csbouncer.StreamBouncer{}
	err = bouncer.Config(*configPath)
	if err != nil {
		log.Errorf("unable to configure bouncer: %s", err)
		return
	}
	bouncer.UserAgent = fmt.Sprintf("%s/%s", name, version.VersionStr())
	if err := bouncer.Init(); err != nil {
		log.Errorf(err.Error())
		return
	}

	if bouncer.InsecureSkipVerify != nil {
		log.Debugf("InsecureSkipVerify is set to %t", *bouncer.InsecureSkipVerify)
	}

	t.Go(func() error {
		bouncer.Run()
		return fmt.Errorf("stream api init failed")
	})

	if config.PrometheusConfig.Enabled {
		if config.Mode == IptablesMode || config.Mode == NftablesMode {
			go backend.CollectMetrics()
			prometheus.MustRegister(totalDroppedBytes, totalDroppedPackets, totalActiveBannedIPs)
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
	t.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Errorf("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				nbDeletedDecisions := 0
				for _, decision := range decisions.Deleted {
					if !inSlice(strings.ToLower(*decision.Type), config.SupportedDecisionsTypes) {
						log.Debugf("decisions for ip '%s' will not be deleted because its type is '%s'", *decision.Value, *decision.Type)
						continue
					}
					if err := backend.Delete(decision); err != nil {
						if !strings.Contains(err.Error(), "netlink receive: no such file or directory") {
							log.Errorf("unable to delete decision for '%s': %s", *decision.Value, err)
						}
					} else {
						log.Debugf("deleted '%s'", *decision.Value)
					}
					nbDeletedDecisions++
				}

				noun := "decisions"
				if nbDeletedDecisions == 1 {
					noun = "decision"
				}
				if nbDeletedDecisions > 0 {
					log.Debug("committing expired decisions")
					if err := backend.Commit(); err != nil {
						log.Errorf("unable to commit delete decisions %v", err)
					}
					log.Debug("committed expired decisions")
					log.Infof("%d %s deleted", nbDeletedDecisions, noun)
				}

				nbNewDecisions := 0
				for _, decision := range decisions.New {
					if !inSlice(strings.ToLower(*decision.Type), config.SupportedDecisionsTypes) {
						log.Debugf("decisions for ip '%s' will not be added because its type is '%s'", *decision.Value, *decision.Type)
						continue
					}
					if err := backend.Add(decision); err != nil {
						log.Errorf("unable to insert decision for '%s': %s", *decision.Value, err)
					} else {
						log.Debugf("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
					}
					nbNewDecisions++
				}

				noun = "decisions"
				if nbNewDecisions == 1 {
					noun = "decision"
				}
				if nbNewDecisions > 0 {
					log.Debug("committing added decisions")
					if err := backend.Commit(); err != nil {
						log.Errorf("unable to commit add decisions %v", err)
					}
					log.Debug("committed added decisions")
					log.Infof("%d %s added", nbNewDecisions, noun)
				}
			}
		}
	})
	if config.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("Failed to notify: %v", err)
		}
		go HandleSignals(backend)
	}

	err = t.Wait()

	if err != nil {
		log.Errorf("process return with error: %s", err)
	}
}
