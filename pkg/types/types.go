package types

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// HealthStatus represents the health state of a firewall backend.
type HealthStatus struct {
	Healthy     bool
	Details     map[string]bool // component name -> healthy status
	LastChecked time.Time
	Error       error
}

type Backend interface {
	Init() error
	ShutDown() error
	Add(decision *models.Decision) error
	Delete(decision *models.Decision) error
	Commit() error
	CollectMetrics()
	// CheckHealth verifies that the firewall infrastructure is intact.
	CheckHealth() HealthStatus
}
