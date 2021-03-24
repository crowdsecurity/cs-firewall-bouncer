package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type iptables struct {
	v4 *ipTablesContext
	v6 *ipTablesContext
}

var iptablesCtx = &iptables{}

func newIPTables(config *bouncerConfig) (interface{}, error) {
	var err error
	var ret *iptables = &iptables{}
	ipv4Ctx := &ipTablesContext{
		Name:             "ipset",
		version:          "v4",
		SetName:          "crowdsec-blacklists",
		StartupCmds:      [][]string{},
		ShutdownCmds:     [][]string{},
		CheckIptableCmds: [][]string{},
	}
	ipv6Ctx := &ipTablesContext{
		Name:             "ipset",
		version:          "v6",
		SetName:          "crowdsec6-blacklists",
		StartupCmds:      [][]string{},
		ShutdownCmds:     [][]string{},
		CheckIptableCmds: [][]string{},
	}

	var target string
  if strings.EqualFold(n.DenyAction, "REJECT") {
		target = "REJECT"
	} else {
		target = "DROP"
	}

	ipsetBin, err := exec.LookPath("ipset")
	if err != nil {
		return nil, fmt.Errorf("unable to find ipset")
	}
	ipv4Ctx.ipsetBin = ipsetBin
	if config.Mode == "ipset" {
		ipv4Ctx.ipsetContentOnly = true
	} else {
		ipv4Ctx.iptablesBin, err = exec.LookPath("iptables")
		if err != nil {
			return nil, fmt.Errorf("unable to find iptables")
		}
		for _, v := range config.IptablesChains {
			if config.DenyLog {
				ipv4Ctx.StartupCmds = append(ipv4Ctx.StartupCmds,
				[]string{"-I", v, "-m", "set", "--match-set", "crowdsec-blacklists", "src", "--log-prefix", config.DenyLogPrefix, "-j", "LOG"})
				ipv4Ctx.ShutdownCmds = append(ipv4Ctx.ShutdownCmds,
				[]string{"-D", v, "-m", "set", "--match-set", "crowdsec-blacklists", "src", "--log-prefix", config.DenyLogPrefix, "-j", "LOG"})
				ipv4Ctx.CheckIptableCmds = append(ipv4Ctx.CheckIptableCmds,
				[]string{"-C", v, "-m", "set", "--match-set", "crowdsec-blacklists", "src", "--log-prefix", config.DenyLogPrefix, "-j", "LOG"})
			}
			ipv4Ctx.StartupCmds = append(ipv4Ctx.StartupCmds,
				[]string{"-I", v, "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", target})
			ipv4Ctx.ShutdownCmds = append(ipv4Ctx.ShutdownCmds,
				[]string{"-D", v, "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", target})
			ipv4Ctx.CheckIptableCmds = append(ipv4Ctx.CheckIptableCmds,
				[]string{"-C", v, "-m", "set", "--match-set", "crowdsec-blacklists", "src", "-j", target})
		}
	}
	ret.v4 = ipv4Ctx
	if config.DisableIPV6 {
		return ret, nil
	}
	ipv6Ctx.ipsetBin = ipsetBin
	if config.Mode == "ipset" {
		ipv6Ctx.ipsetContentOnly = true
	} else {
		ipv6Ctx.iptablesBin, err = exec.LookPath("ip6tables")
		if err != nil {
			return nil, fmt.Errorf("unable to find ip6tables")
		}
		for _, v := range config.IptablesChains {
			if config.DenyLog {
				ipv6Ctx.StartupCmds = append(ipv4Ctx.StartupCmds,
				[]string{"-I", v, "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "--log-prefix", config.DenyLogPrefix, "-j", "LOG"})
				ipv6Ctx.ShutdownCmds = append(ipv4Ctx.ShutdownCmds,
				[]string{"-D", v, "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "--log-prefix", config.DenyLogPrefix, "-j", "LOG"})
				ipv6Ctx.CheckIptableCmds = append(ipv4Ctx.CheckIptableCmds,
				[]string{"-C", v, "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "--log-prefix", config.DenyLogPrefix, "-j", "LOG"})
			}
			ipv6Ctx.StartupCmds = append(ipv6Ctx.StartupCmds,
				[]string{"-I", v, "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"})
			ipv6Ctx.ShutdownCmds = append(ipv6Ctx.ShutdownCmds,
				[]string{"-D", v, "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"})
			ipv6Ctx.CheckIptableCmds = append(ipv6Ctx.CheckIptableCmds,
				[]string{"-C", v, "-m", "set", "--match-set", "crowdsec6-blacklists", "src", "-j", "DROP"})
		}
	}
	ret.v6 = ipv6Ctx

	return ret, nil
}

func (ipt *iptables) Init() error {
	var err error

	log.Printf("iptables for ipv4 initiated")
	// flush before init
	if err := ipt.v4.shutDown(); err != nil {
		return fmt.Errorf("iptables shutdown failed: %s", err.Error())
	}

	// Create iptable to rule to attach the set
	if err := ipt.v4.CheckAndCreate(); err != nil {
		return fmt.Errorf("iptables init failed: %s", err.Error())
	}

	if ipt.v6 != nil {
		log.Printf("iptables for ipv6 initiated")
		err = ipt.v6.shutDown() // flush before init
		if err != nil {
			return fmt.Errorf("iptables shutdown failed: %s", err.Error())
		}

		// Create iptable to rule to attach the set
		if err := ipt.v6.CheckAndCreate(); err != nil {
			return fmt.Errorf("iptables init failed: %s", err.Error())
		}
	}
	return nil
}

func (ipt *iptables) Add(decision *models.Decision) error {
	done := false

	if strings.HasPrefix(*decision.Type, "simulation:") {
		log.Debugf("measure against '%s' is in simulation mode, skipping it", *decision.Value)
		return nil
	}

	//we now have to know if ba is for an ipv4 or ipv6
	//the obvious way would be to get the len of net.ParseIp(ba) but this is 16 internally even for ipv4.
	//so we steal the ugly hack from https://github.com/asaskevich/govalidator/blob/3b2665001c4c24e3b076d1ca8c428049ecbb925b/validator.go#L501
	if strings.Contains(*decision.Value, ":") {
		if ipt.v6 != nil {
			if err := ipt.v6.add(decision); err != nil {
				return fmt.Errorf("failed inserting ban ip '%s' for iptables ipv4 rule", *decision.Value)
			}
			done = true
		} else {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	}
	if strings.Contains(*decision.Value, ".") {
		if err := ipt.v4.add(decision); err != nil {
			return fmt.Errorf("failed inserting ban ip '%s' for iptables ipv6 rule", *decision.Value)
		}
		done = true
	}

	if !done {
		return fmt.Errorf("failed inserting ban: ip %s was not recognised", *decision.Value)
	}

	return nil
}

func (ipt *iptables) ShutDown() error {
	err := ipt.v4.shutDown()
	if err != nil {
		return fmt.Errorf("iptables for ipv4 shutdown failed: %s", err.Error())
	}
	if ipt.v6 != nil {
		err = ipt.v6.shutDown()
		if err != nil {
			return fmt.Errorf("iptables for ipv6 shutdown failed: %s", err.Error())
		}
	}
	return nil
}

func (ipt *iptables) Delete(decision *models.Decision) error {
	done := false
	if strings.Contains(*decision.Value, ":") {
		if ipt.v6 != nil {
			if err := ipt.v6.delete(decision); err != nil {
				return fmt.Errorf("failed deleting ban")
			}
			done = true
		} else {
			log.Debugf("not deleting '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	}
	if strings.Contains(*decision.Value, ".") {
		if err := ipt.v4.delete(decision); err != nil {
			return fmt.Errorf("failed deleting ban")
		}
		done = true
	}
	if !done {
		return fmt.Errorf("failed deleting ban: ip %s was not recognised", *decision.Value)
	}
	return nil
}
