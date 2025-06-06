package dryrun

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

type dryRun struct{}

func NewDryRun(_ *cfg.BouncerConfig) (types.Backend, error) {
	return &dryRun{}, nil
}

func (*dryRun) Init() error {
	log.Infof("backend.Init() called")
	return nil
}

func (*dryRun) Commit() error {
	log.Infof("backend.Commit() called")
	return nil
}

func (*dryRun) Add(decision *models.Decision) error {
	log.Infof("backend.Add() called with %s", *decision.Value)
	return nil
}

func (*dryRun) CollectMetrics() {
	log.Infof("backend.CollectMetrics() called")
}

func (*dryRun) Delete(decision *models.Decision) error {
	log.Infof("backend.Delete() called with %s", *decision.Value)
	return nil
}

func (*dryRun) ShutDown() error {
	log.Infof("backend.ShutDown() called")
	return nil
}
