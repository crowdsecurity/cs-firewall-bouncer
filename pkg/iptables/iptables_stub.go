//go:build !linux
// +build !linux

package iptables

import (
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

func NewIPTables(config *cfg.BouncerConfig) (types.Backend, error) {
	return nil, nil
}
