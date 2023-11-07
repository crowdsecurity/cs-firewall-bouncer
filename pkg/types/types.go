package types

import (
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Backend interface {
	Init() error
	ShutDown() error
	Add(decision *models.Decision) error
	Delete(decision *models.Decision) error
	Commit() error
	CollectMetrics()
}
