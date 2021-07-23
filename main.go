package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/version"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"gopkg.in/tomb.v2"
)

const (
	name = "crowdsec-firewall-bouncer"
)

var t tomb.Tomb

func termHandler(sig os.Signal, backend *backendCTX) error {
	if err := backend.ShutDown(); err != nil {
		return err
	}
	return nil
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

func main() {
	var err error
	configPath := flag.String("c", "", "path to crowdsec-firewall-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")
	bouncerVersion := flag.Bool("V", false, "display version and exit")
	testConfig := flag.Bool("t", false, "test config and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.ShowStr())
		os.Exit(0)
	}

	log.Infof("crowdsec-firewall-bouncer %s", version.VersionStr())

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	config, err := NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *testConfig {
		if err := validateConfig(*config); err != nil {
			log.Fatalf("got error %s while validating config", err.Error())
		}
		log.Info("config is valid")
		return
	}

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
	bouncer := &csbouncer.StreamBouncer{
		APIKey:         config.APIKey,
		APIUrl:         config.APIUrl,
		TickerInterval: config.UpdateFrequency,
		UserAgent:      fmt.Sprintf("%s/%s", name, version.VersionStr()),
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	t.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Infoln("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				if len(decisions.Deleted) > 0 {
					log.Infof("deleting '%d' decisions", len(decisions.Deleted))
				}
				for _, decision := range decisions.Deleted {
					if err := backend.Delete(decision); err != nil {
						if !strings.Contains(err.Error(), "netlink receive: no such file or directory") {
							log.Errorf("unable to delete decision for '%s': %s", *decision.Value, err)
						}
					} else {
						log.Debugf("deleted '%s'", *decision.Value)
					}

				}
				if len(decisions.New) > 0 {
					log.Infof("adding '%d' decisions", len(decisions.New))
				}
				for _, decision := range decisions.New {
					if err := backend.Add(decision); err != nil {
						log.Errorf("unable to insert decision for '%s': %s", *decision.Value, err)
					} else {
						log.Debugf("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
					}
				}
			}
		}
	})

	if config.Daemon == true {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("Failed to notify: %v", err)
		}
		HandleSignals(backend)
	}

	err = t.Wait()
	if err != nil {
		log.Fatalf("process return with error: %s", err)
	}
}
