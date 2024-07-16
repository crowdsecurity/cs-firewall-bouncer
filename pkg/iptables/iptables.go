//go:build linux
// +build linux

package iptables

import (
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/ipsetcmd"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

const (
	IPTablesDroppedPacketIdx = 0
	IPTablesDroppedByteIdx   = 1
)

type iptables struct {
	v4 *ipTablesContext
	v6 *ipTablesContext
}

func NewIPTables(config *cfg.BouncerConfig) (types.Backend, error) {
	var err error
	ret := &iptables{}

	defaultSet, err := ipsetcmd.NewIPSet("")

	if err != nil {
		return nil, err
	}

	allowedActions := []string{"DROP", "REJECT", "TARPIT"}

	target := strings.ToUpper(config.DenyAction)
	if target == "" {
		target = "DROP"
	}

	if !slices.Contains(allowedActions, target) {
		return nil, fmt.Errorf("invalid deny_action '%s', must be one of %s", config.DenyAction, strings.Join(allowedActions, ", "))
	}

	v4Sets := make(map[string]*ipsetcmd.IPSet)
	v6Sets := make(map[string]*ipsetcmd.IPSet)

	ipv4Ctx := &ipTablesContext{
		version:    "v4",
		SetName:    config.BlacklistsIpv4,
		SetType:    config.SetType,
		SetSize:    config.SetSize,
		Chains:     []string{},
		defaultSet: defaultSet,
		target:     target,
	}
	ipv6Ctx := &ipTablesContext{
		version:    "v6",
		SetName:    config.BlacklistsIpv6,
		SetType:    config.SetType,
		SetSize:    config.SetSize,
		Chains:     []string{},
		defaultSet: defaultSet,
		target:     target,
	}

	log.Tracef("using '%s' as deny_action", target)

	if config.Mode == cfg.IpsetMode {
		ipv4Ctx.ipsetContentOnly = true
		set, err := ipsetcmd.NewIPSet(config.BlacklistsIpv4)
		if err != nil {
			return nil, err
		}
		v4Sets["ipset"] = set
	} else {
		ipv4Ctx.iptablesBin, err = exec.LookPath("iptables")
		if err != nil {
			return nil, errors.New("unable to find iptables")
		}
		ipv4Ctx.Chains = config.IptablesChains
	}

	ipv4Ctx.ipsets = v4Sets
	ret.v4 = ipv4Ctx
	if config.DisableIPV6 {
		return ret, nil
	}

	if config.Mode == cfg.IpsetMode {
		ipv6Ctx.ipsetContentOnly = true
		set, err := ipsetcmd.NewIPSet(config.BlacklistsIpv6)
		if err != nil {
			return nil, err
		}
		v6Sets["ipset"] = set
	} else {
		ipv6Ctx.iptablesBin, err = exec.LookPath("ip6tables")
		if err != nil {
			return nil, errors.New("unable to find ip6tables")
		}
		ipv6Ctx.Chains = config.IptablesChains
	}

	ipv6Ctx.ipsets = v6Sets
	ret.v6 = ipv6Ctx

	return ret, nil
}

func (ipt *iptables) Init() error {
	var err error

	log.Printf("iptables for ipv4 initiated")

	// flush before init
	if err = ipt.v4.shutDown(); err != nil {
		return fmt.Errorf("iptables shutdown failed: %w", err)
	}

	if ipt.v6 != nil {
		log.Printf("iptables for ipv6 initiated")

		err = ipt.v6.shutDown() // flush before init
		if err != nil {
			return fmt.Errorf("iptables shutdown failed: %w", err)
		}
	}

	return nil
}

func (ipt *iptables) Commit() error {
	if ipt.v4 != nil {
		err := ipt.v4.commit()
		if err != nil {
			return fmt.Errorf("ipset for ipv4 commit failed: %w", err)
		}
	}

	if ipt.v6 != nil {
		err := ipt.v6.commit()
		if err != nil {
			return fmt.Errorf("ipset for ipv6 commit failed: %w", err)
		}
	}

	return nil
}

func (ipt *iptables) Add(decision *models.Decision) error {
	if strings.HasPrefix(*decision.Type, "simulation:") {
		log.Debugf("measure against '%s' is in simulation mode, skipping it", *decision.Value)
		return nil
	}

	if strings.Contains(*decision.Value, ":") {
		if ipt.v6 == nil {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
		ipt.v6.add(decision)
	} else {
		ipt.v4.add(decision)
	}
	return nil
}

func (ipt *iptables) ShutDown() error {
	err := ipt.v4.shutDown()
	if err != nil {
		return fmt.Errorf("iptables for ipv4 shutdown failed: %w", err)
	}

	if ipt.v6 != nil {
		err = ipt.v6.shutDown()
		if err != nil {
			return fmt.Errorf("iptables for ipv6 shutdown failed: %w", err)
		}
	}

	return nil
}

func (ipt *iptables) Delete(decision *models.Decision) error {
	done := false

	if strings.Contains(*decision.Value, ":") {
		if ipt.v6 == nil {
			log.Debugf("not deleting '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}

		if err := ipt.v6.delete(decision); err != nil {
			return errors.New("failed deleting ban")
		}

		done = true
	}

	if strings.Contains(*decision.Value, ".") {
		if err := ipt.v4.delete(decision); err != nil {
			return errors.New("failed deleting ban")
		}

		done = true
	}

	if !done {
		return fmt.Errorf("failed deleting ban: ip %s was not recognized", *decision.Value)
	}

	return nil
}
