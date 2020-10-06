package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	log "github.com/sirupsen/logrus"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"gopkg.in/tomb.v2"
)

func reloadHandler(sig os.Signal) error {
	return nil
}

func termHandler(sig os.Signal) error {
	return nil
}

func HandleSignals() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGHUP,
		syscall.SIGTERM)

	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGHUP XXXX
			case syscall.SIGHUP:
				if err := reloadHandler(s); err != nil {
					log.Fatalf("Reload handler failure : %s", err)
				}
			// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				if err := termHandler(s); err != nil {
					log.Fatalf("Term handler failure : %s", err)
				}
				exitChan <- 0
			}
		}
	}()

	code := <-exitChan
	log.Warningf("Crowdsec service shutting down")
	os.Exit(code)
}

func main() {
	var t tomb.Tomb
	var err error

	configPath := flag.String("c", "", "path to firewall-bouncer.yaml")
	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("config file required")
	}
	config, err := NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	backend, err := newBackend(config.Mode)
	if err != nil {
		log.Fatalf(err.Error())
	}
	bouncer := &csbouncer.StreamBouncer{
		APIKey:         config.APIKey,
		APIUrl:         config.APIUrl,
		TickerInterval: config.UpdateFrequency,
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	t.Go(func() error {
		log.Printf("Processing new and old decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Infoln("terminating process")
				return nil
			case decision := <-bouncer.NewDecision:
				// Do some stuff with new decisions
				log.Debugf("new decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
				if err := backend.Add(&decision); err != nil {
					log.Errorf("unable to insert decision for '%s': %s", decision.Value, err)
				}

			case decision := <-bouncer.ExpiredDecision:
				// do some stuff with expired decisions
				log.Debugf("old decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)
				if err := backend.Delete(&decision); err != nil {
					log.Errorf("unable to insert decision for '%s': %s", decision.Value, err)
				}
			}
		}
	})

	if config.Daemon == true {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Errorf("Failed to notify: %v", err)
		}
		HandleSignals()
	}

	err = t.Wait()
	if err != nil {
		log.Fatalf("processing return with error: %s", err)
	}
}
