//go:build linux

package iptables

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/ipsetcmd"
)

const (
	chainName           = "CROWDSEC_CHAIN"
	loggingChainName    = "CROWDSEC_LOG"
	dockerUserChainName = "DOCKER-USER"
	maxBanSeconds       = 2147483
	defaultTimeout      = "300"
)

type ipTablesContext struct {
	version              string
	iptablesBin          string
	iptablesSaveBin      string
	SetName              string // crowdsec-netfilter
	SetType              string
	SetSize              int
	ipsetContentOnly     bool
	ipsetDisableTimeouts bool
	Chains               []string

	target string

	ipsets     map[string]*ipsetcmd.IPSet
	defaultSet *ipsetcmd.IPSet // This one is only used to restore the content, as the file will contain the name of the set for each decision

	toAdd []*models.Decision
	toDel []*models.Decision

	// To avoid issues with set name length (ipsest name length is limited to 31 characters)
	// Store the origin of the decisions, and use the index in the slice as the name
	// This is not stable (ie, between two runs, the index of a set can change), but it's (probably) not an issue
	originSetMapping []string

	loggingEnabled bool
	loggingPrefix  string

	addRuleComments bool
}

func (ctx *ipTablesContext) chainExist(chainName string) bool {
	cmd := []string{"-L", chainName, "-t", "filter"}
	c := exec.Command(ctx.iptablesBin, cmd...)

	if _, err := c.CombinedOutput(); err != nil {
		return false
	}

	return true
}

func (ctx *ipTablesContext) setupChain() {
	cmd := []string{"-N", chainName, "-t", "filter"}

	c := exec.Command(ctx.iptablesBin, cmd...)

	log.Infof("Creating chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

	if out, err := c.CombinedOutput(); err != nil {
		log.Errorf("error while creating chain : %v --> %s", err, string(out))
		return
	}

	for _, chain := range ctx.Chains {
		cmd = []string{"-I", chain, "-j", chainName}

		c = exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Adding rule : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while adding rule : %v --> %s", err, string(out))
			continue
		}
	}

	if ctx.loggingEnabled {
		// Create the logging chain
		cmd = []string{"-N", loggingChainName, "-t", "filter"}

		c = exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Creating logging chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while creating logging chain : %v --> %s", err, string(out))
			return
		}

		// Insert the logging rule
		cmd = []string{"-I", loggingChainName, "-j", "LOG", "--log-prefix", ctx.loggingPrefix}

		c = exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Adding logging rule : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while adding logging rule : %v --> %s", err, string(out))
		}

		// Add the desired target to the logging chain

		cmd = []string{"-A", loggingChainName, "-j", ctx.target}

		c = exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Adding target rule to logging chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while setting logging chain policy : %v --> %s", err, string(out))
		}
	}

	if ctx.chainExist(dockerUserChainName) && !slices.Contains(ctx.Chains, dockerUserChainName) {
		// if the DOCKER-USER chain exists, but is not configured by the user, warn them as their containers will not be protected
		log.Warnf("The %s chain exists, but is not configured for use by the bouncer. The bouncer will not block traffic destined for your containers", dockerUserChainName)
	}
}

func (ctx *ipTablesContext) deleteChain() {
	for _, chain := range ctx.Chains {
		cmd := []string{"-D", chain, "-j", chainName}

		c := exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Deleting rule : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while removing rule : %v --> %s", err, string(out))
		}
	}

	cmd := []string{"-F", chainName}

	c := exec.Command(ctx.iptablesBin, cmd...)

	log.Infof("Flushing chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

	if out, err := c.CombinedOutput(); err != nil {
		log.Errorf("error while flushing chain : %v --> %s", err, string(out))
	}

	cmd = []string{"-X", chainName}

	c = exec.Command(ctx.iptablesBin, cmd...)

	log.Infof("Deleting chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

	if out, err := c.CombinedOutput(); err != nil {
		log.Errorf("error while deleting chain : %v --> %s", err, string(out))
	}

	if ctx.loggingEnabled {
		cmd = []string{"-F", loggingChainName}

		c = exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Flushing logging chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while flushing logging chain : %v --> %s", err, string(out))
		}

		cmd = []string{"-X", loggingChainName}

		c = exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Deleting logging chain : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while deleting logging chain : %v --> %s", err, string(out))
		}
	}
}

func (ctx *ipTablesContext) createRule(setName string, origin string) {
	target := ctx.target

	if ctx.loggingEnabled {
		target = loggingChainName
	}

	cmd := []string{"-I", chainName, "-m", "set", "--match-set", setName, "src", "-j", target}

	if ctx.addRuleComments {
		cmd = append(cmd, "-m", "comment", "--comment", "CrowdSec: "+origin)
	}

	c := exec.Command(ctx.iptablesBin, cmd...)

	log.Infof("Creating rule : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

	if out, err := c.CombinedOutput(); err != nil {
		log.Errorf("error while inserting set entry in iptables : %v --> %s", err, string(out))
	}
}

func (ctx *ipTablesContext) commit() error {
	tmpFile, err := os.CreateTemp("", "cs-firewall-bouncer-ipset-")
	if err != nil {
		return err
	}

	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())

		ctx.toAdd = nil
		ctx.toDel = nil
	}()

	for _, decision := range ctx.toDel {
		var (
			set *ipsetcmd.IPSet
			ok  bool
		)

		// Decisions coming from lists will have "lists" as origin, and the scenario will be the list name
		// We use those to build a custom origin because we want to track metrics per list
		// In case of other origin (crowdsec, cscli, ...), we do not really care about the scenario, it would be too noisy
		origin := *decision.Origin
		if origin == "lists" {
			origin = origin + ":" + *decision.Scenario
		}

		if ctx.ipsetContentOnly {
			set = ctx.ipsets["ipset"]
		} else {
			set, ok = ctx.ipsets[origin]
			if !ok {
				// No set for this origin, skip, as there's nothing to delete
				continue
			}
		}

		delCmd := fmt.Sprintf("del %s %s -exist\n", set.Name(), *decision.Value)

		log.Debugf("%s", delCmd)

		_, err = tmpFile.WriteString(delCmd)
		if err != nil {
			log.Errorf("error while writing to temp file : %s", err)
			continue
		}
	}

	for _, decision := range ctx.toAdd {
		banDuration, err := time.ParseDuration(*decision.Duration)
		if err != nil {
			log.Errorf("error while parsing ban duration : %s", err)
			continue
		}

		var (
			set *ipsetcmd.IPSet
			ok  bool
		)

		if banDuration.Seconds() > maxBanSeconds {
			log.Warnf("Ban duration too long (%d seconds), maximum for ipset is %d, setting duration to %d", int(banDuration.Seconds()), maxBanSeconds, maxBanSeconds-1)
			banDuration = time.Duration(maxBanSeconds-1) * time.Second
		}

		origin := *decision.Origin

		if origin == "lists" {
			origin = origin + ":" + *decision.Scenario
		}

		if ctx.ipsetContentOnly {
			set = ctx.ipsets["ipset"]
		} else {
			set, ok = ctx.ipsets[origin]

			if !ok {
				idx := slices.Index(ctx.originSetMapping, origin)

				if idx == -1 {
					ctx.originSetMapping = append(ctx.originSetMapping, origin)
					idx = len(ctx.originSetMapping) - 1
				}

				setName := fmt.Sprintf("%s-%d", ctx.SetName, idx)

				log.Infof("Using %s as set for origin %s", setName, origin)

				set, err = ipsetcmd.NewIPSet(setName)
				if err != nil {
					log.Errorf("error while creating ipset : %s", err)
					continue
				}

				family := "inet"

				if ctx.version == "v6" {
					family = "inet6"
				}

				err = set.Create(ipsetcmd.CreateOptions{
					Family:          family,
					Timeout:         defaultTimeout,
					MaxElem:         strconv.Itoa(ctx.SetSize),
					Type:            ctx.SetType,
					DisableTimeouts: ctx.ipsetDisableTimeouts,
				})
				// Ignore errors if the set already exists
				if err != nil {
					log.Errorf("error while creating ipset : %s", err)
					continue
				}

				ctx.ipsets[origin] = set

				if !ctx.ipsetContentOnly {
					// Create the rule to use the set
					ctx.createRule(set.Name(), origin)
				}
			}
		}

		var addCmd string
		if ctx.ipsetDisableTimeouts {
			addCmd = fmt.Sprintf("add %s %s -exist\n", set.Name(), *decision.Value)
		} else {
			addCmd = fmt.Sprintf("add %s %s timeout %d -exist\n", set.Name(), *decision.Value, int(banDuration.Seconds()))
		}

		log.Debugf("%s", addCmd)

		_, err = tmpFile.WriteString(addCmd)
		if err != nil {
			log.Errorf("error while writing to temp file : %s", err)
			continue
		}
	}

	if len(ctx.toAdd) == 0 && len(ctx.toDel) == 0 {
		return nil
	}

	return ctx.defaultSet.Restore(tmpFile.Name())
}

func (ctx *ipTablesContext) add(decision *models.Decision) {
	ctx.toAdd = append(ctx.toAdd, decision)
}

func (ctx *ipTablesContext) shutDown() error {
	// Remove rules
	if !ctx.ipsetContentOnly {
		ctx.deleteChain()
	}

	time.Sleep(1 * time.Second)

	// Clean sets
	for _, set := range ctx.ipsets {
		if ctx.ipsetContentOnly {
			err := set.Flush()
			if err != nil {
				log.Errorf("error while flushing ipset : %s", err)
			}
		} else {
			err := set.Destroy()
			if err != nil {
				log.Errorf("error while destroying set %s : %s", set.Name(), err)
			}
		}
	}

	if !ctx.ipsetContentOnly {
		// In case we are starting, just reset the map
		ctx.ipsets = make(map[string]*ipsetcmd.IPSet)
	}

	return nil
}

func (ctx *ipTablesContext) delete(decision *models.Decision) error {
	ctx.toDel = append(ctx.toDel, decision)
	return nil
}
