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

	configPath := flag.String("c", "", "path to firewall-bouncer.yaml")
	verbose := flag.Bool("v", false, "set verbose mode")

	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	config, err := NewConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	backend, err := newBackend(config.Mode)
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
			case decision := <-bouncer.NewDecision:
				// Do some stuff with new decisions
				if err := backend.Add(&decision); err != nil {
					log.Errorf("unable to insert decision for '%s': %s", *decision.Value, err)
				}

			case decision := <-bouncer.ExpiredDecision:
				// do some stuff with expired decisions
				if err := backend.Delete(&decision); err != nil {
					log.Errorf("unable to delete decision for '%s': %s", *decision.Value, err)
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
