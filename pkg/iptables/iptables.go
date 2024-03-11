//go:build linux
// +build linux

package iptables

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
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
	ret := &iptables{}

	ipv4Ctx := &ipTablesContext{
		Name:             "ipset",
		version:          "v4",
		SetName:          config.BlacklistsIpv4,
		SetType:          config.SetType,
		SetSize:          config.SetSize,
		StartupCmds:      [][]string{},
		ShutdownCmds:     [][]string{},
		CheckIptableCmds: [][]string{},
		Chains:           []string{},
	}
	ipv6Ctx := &ipTablesContext{
		Name:             "ipset",
		version:          "v6",
		SetName:          config.BlacklistsIpv6,
		SetType:          config.SetType,
		SetSize:          config.SetSize,
		StartupCmds:      [][]string{},
		ShutdownCmds:     [][]string{},
		CheckIptableCmds: [][]string{},
		Chains:           []string{},
	}

	allowedActions := []string{"DROP", "REJECT", "TARPIT"}

	target := strings.ToUpper(config.DenyAction)
	if target == "" {
		target = "DROP"
	}

	if !slices.Contains(allowedActions, target) {
		return nil, fmt.Errorf("invalid deny_action '%s', must be one of %s", config.DenyAction, strings.Join(allowedActions, ", "))
	}

	log.Tracef("using '%s' as deny_action", target)

	ipsetBin, err := exec.LookPath("ipset")
	if err != nil {
		return nil, errors.New("unable to find ipset")
	}

	ipv4Ctx.ipsetBin = ipsetBin
	if config.Mode == cfg.IpsetMode {
		ipv4Ctx.ipsetContentOnly = true
	} else {
		ipv4Ctx.iptablesBin, err = exec.LookPath("iptables")
		if err != nil {
			return nil, errors.New("unable to find iptables")
		}
		ipv4Ctx.Chains = config.IptablesChains
		for _, v := range config.IptablesChains {
			ipv4Ctx.StartupCmds = append(ipv4Ctx.StartupCmds,
				[]string{"-I", v, "-m", "set", "--match-set", ipv4Ctx.SetName, "src", "-j", target})
			ipv4Ctx.ShutdownCmds = append(ipv4Ctx.ShutdownCmds,
				[]string{"-D", v, "-m", "set", "--match-set", ipv4Ctx.SetName, "src", "-j", target})
			ipv4Ctx.CheckIptableCmds = append(ipv4Ctx.CheckIptableCmds,
				[]string{"-C", v, "-m", "set", "--match-set", ipv4Ctx.SetName, "src", "-j", target})
			if config.DenyLog {
				ipv4Ctx.StartupCmds = append(ipv4Ctx.StartupCmds,
					[]string{"-I", v, "-m", "set", "--match-set", ipv4Ctx.SetName, "src", "-j", "LOG", "--log-prefix", config.DenyLogPrefix})
				ipv4Ctx.ShutdownCmds = append(ipv4Ctx.ShutdownCmds,
					[]string{"-D", v, "-m", "set", "--match-set", ipv4Ctx.SetName, "src", "-j", "LOG", "--log-prefix", config.DenyLogPrefix})
				ipv4Ctx.CheckIptableCmds = append(ipv4Ctx.CheckIptableCmds,
					[]string{"-C", v, "-m", "set", "--match-set", ipv4Ctx.SetName, "src", "-j", "LOG", "--log-prefix", config.DenyLogPrefix})
			}
		}
	}

	ret.v4 = ipv4Ctx
	if config.DisableIPV6 {
		return ret, nil
	}

	ipv6Ctx.ipsetBin = ipsetBin
	if config.Mode == cfg.IpsetMode {
		ipv6Ctx.ipsetContentOnly = true
	} else {
		ipv6Ctx.iptablesBin, err = exec.LookPath("ip6tables")
		if err != nil {
			return nil, errors.New("unable to find ip6tables")
		}
		ipv6Ctx.Chains = config.IptablesChains
		for _, v := range config.IptablesChains {
			ipv6Ctx.StartupCmds = append(ipv6Ctx.StartupCmds,
				[]string{"-I", v, "-m", "set", "--match-set", ipv6Ctx.SetName, "src", "-j", target})
			ipv6Ctx.ShutdownCmds = append(ipv6Ctx.ShutdownCmds,
				[]string{"-D", v, "-m", "set", "--match-set", ipv6Ctx.SetName, "src", "-j", target})
			ipv6Ctx.CheckIptableCmds = append(ipv6Ctx.CheckIptableCmds,
				[]string{"-C", v, "-m", "set", "--match-set", ipv6Ctx.SetName, "src", "-j", target})
			if config.DenyLog {
				ipv6Ctx.StartupCmds = append(ipv6Ctx.StartupCmds,
					[]string{"-I", v, "-m", "set", "--match-set", ipv6Ctx.SetName, "src", "-j", "LOG", "--log-prefix", config.DenyLogPrefix})
				ipv6Ctx.ShutdownCmds = append(ipv6Ctx.ShutdownCmds,
					[]string{"-D", v, "-m", "set", "--match-set", ipv6Ctx.SetName, "src", "-j", "LOG", "--log-prefix", config.DenyLogPrefix})
				ipv6Ctx.CheckIptableCmds = append(ipv6Ctx.CheckIptableCmds,
					[]string{"-C", v, "-m", "set", "--match-set", ipv6Ctx.SetName, "src", "-j", "LOG", "--log-prefix", config.DenyLogPrefix})
			}
		}
	}

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

	// Create iptable to rule to attach the set
	if err = ipt.v4.CheckAndCreate(); err != nil {
		return fmt.Errorf("iptables init failed: %w", err)
	}

	if ipt.v6 != nil {
		log.Printf("iptables for ipv6 initiated")

		err = ipt.v6.shutDown() // flush before init
		if err != nil {
			return fmt.Errorf("iptables shutdown failed: %w", err)
		}

		// Create iptable to rule to attach the set
		if err := ipt.v6.CheckAndCreate(); err != nil {
			return fmt.Errorf("iptables init failed: %w", err)
		}
	}

	return nil
}

func (ipt *iptables) Commit() error {
	return nil
}

func (ipt *iptables) Add(decision *models.Decision) error {
	done := false

	if strings.HasPrefix(*decision.Type, "simulation:") {
		log.Debugf("measure against '%s' is in simulation mode, skipping it", *decision.Value)
		return nil
	}

	// we now have to know if ba is for an ipv4 or ipv6 the obvious way
	// would be to get the len of net.ParseIp(ba) but this is 16 internally
	// even for ipv4. so we steal the ugly hack from
	// https://github.com/asaskevich/govalidator/blob/3b2665001c4c24e3b076d1ca8c428049ecbb925b/validator.go#L501
	if strings.Contains(*decision.Value, ":") {
		if ipt.v6 == nil {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}

		if err := ipt.v6.add(decision); err != nil {
			return fmt.Errorf("failed inserting ban ip '%s' for iptables ipv4 rule", *decision.Value)
		}

		done = true
	}

	if strings.Contains(*decision.Value, ".") {
		if err := ipt.v4.add(decision); err != nil {
			return fmt.Errorf("failed inserting ban ip '%s' for iptables ipv6 rule", *decision.Value)
		}

		done = true
	}

	if !done {
		return fmt.Errorf("failed inserting ban: ip %s was not recognized", *decision.Value)
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
