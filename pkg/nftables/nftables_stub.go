//go:build !linux
// +build !linux

package nftables

import (
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

func NewNFTables(config *cfg.BouncerConfig) (types.backend, error) {
	return nil, nil
}
