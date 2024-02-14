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

type NftablesTargetConfig struct {
	Blacklist string `yaml:"blacklist"`
	SetOnly   bool   `yaml:"set-only"`
	Table     string `yaml:"table"`
	Chain     string `yaml:"chain"`
	Family    string `yaml:"family"`
	Protocol  string `yaml:"protocol"`
	Hook      string `yaml:"hook"`
	Priority  int    `yaml:"priority"`
}
