//go:build linux
// +build linux

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

type ipTablesContext struct {
	version          string
	iptablesBin      string
	SetName          string // crowdsec-netfilter
	SetType          string
	SetSize          int
	ipsetContentOnly bool
	Chains           []string

	target string

	ipsets     map[string]*ipsetcmd.IPSet
	defaultSet *ipsetcmd.IPSet //This one is only used to restore the content, as the file will contain the name of the set for each decision

	toAdd []*models.Decision
	toDel []*models.Decision

	//To avoid issues with set name length (ipsest name length is limited to 31 characters)
	//Store the origin of the decisions, and use the index in the slice as the name
	//This is not stable (ie, between two runs, the index of a set can change), but it's (probably) not an issue
	originSetMapping []string
}

func (ctx *ipTablesContext) createRule(setName string) {
	for _, chain := range ctx.Chains {
		cmd := []string{"-I", chain, "-m", "set", "--match-set", setName, "src", "-j", ctx.target}

		c := exec.Command(ctx.iptablesBin, cmd...)

		log.Infof("Creating rule : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while inserting set entry in iptables : %v --> %s", err, string(out))
			continue
		}
	}
}

func (ctx *ipTablesContext) deleteRule(setName string) {
	for _, chain := range ctx.Chains {
		cmd := []string{"-D", chain, "-m", "set", "--match-set", setName, "src", "-j", ctx.target}

		log.Infof("Deleting rule : %s %s", ctx.iptablesBin, strings.Join(cmd, " "))

		c := exec.Command(ctx.iptablesBin, cmd...)

		if out, err := c.CombinedOutput(); err != nil {
			log.Errorf("error while removing set entry in iptables : %v --> %s", err, string(out))
			continue
		}
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
		origin := *decision.Origin
		if origin == "lists" {
			origin = origin + ":" + *decision.Scenario
		}

		set, ok := ctx.ipsets[origin]

		if !ok {
			//No set for this origin, skip, as there's nothing to delete
			continue
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

		if banDuration.Seconds() > 2147483 {
			log.Warnf("Ban duration too long (%d seconds), maximum for ipset is 2147483, setting duration to 2147482", int(banDuration.Seconds()))
			banDuration = time.Duration(2147482) * time.Second
		}

		origin := *decision.Origin

		if origin == "lists" {
			origin = origin + ":" + *decision.Scenario
		}

		set, ok := ctx.ipsets[origin]

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
				Family:  family,
				Timeout: "300",
				MaxElem: strconv.Itoa(ctx.SetSize),
				Type:    ctx.SetType,
			})

			if err != nil {
				log.Errorf("error while creating ipset : %s", err)
				continue
			}

			ctx.ipsets[origin] = set

			//Create the rule to use the set
			ctx.createRule(set.Name())
		}

		addCmd := fmt.Sprintf("add %s %s timeout %d -exist\n", set.Name(), *decision.Value, int(banDuration.Seconds()))

		log.Debugf("%s", addCmd)

		_, err = tmpFile.WriteString(addCmd)

		if err != nil {
			log.Errorf("error while writing to temp file : %s", err)
			continue
		}
	}

	return ctx.defaultSet.Restore(tmpFile.Name())
}

func (ctx *ipTablesContext) add(decision *models.Decision) error {
	ctx.toAdd = append(ctx.toAdd, decision)
	return nil
}

func (ctx *ipTablesContext) shutDown() error {

	//Remove rules
	if !ctx.ipsetContentOnly {
		for _, set := range ctx.ipsets {
			ctx.deleteRule(set.Name())
		}
	}

	time.Sleep(1 * time.Second)

	//Clean sets
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

	return nil
}

func (ctx *ipTablesContext) delete(decision *models.Decision) error {
	ctx.toDel = append(ctx.toDel, decision)
	return nil
}
