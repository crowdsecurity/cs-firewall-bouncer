//go:build linux
// +build linux

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type ipTablesContext struct {
	Name             string
	version          string
	ipsetBin         string
	iptablesBin      string
	SetName          string // crowdsec-netfilter
	SetType          string
	StartupCmds      [][]string // -I INPUT -m set --match-set myset src -j DROP
	ShutdownCmds     [][]string // -D INPUT -m set --match-set myset src -j DROP
	CheckIptableCmds [][]string
	ipsetContentOnly bool
	Chains           []string
}

func (ctx *ipTablesContext) CheckAndCreate() error {
	var err error

	log.Infof("Checking existing set")
	/* check if the set already exist */
	cmd := exec.Command(ctx.ipsetBin, "-L", ctx.SetName)
	if _, err = cmd.CombinedOutput(); err != nil { // it doesn't exist
		if ctx.ipsetContentOnly {
			/*if we manage ipset content only, error*/
			log.Errorf("set %s doesn't exist, can't manage content", ctx.SetName)
			return fmt.Errorf("set %s doesn't exist: %w", ctx.SetName, err)
		}
		if ctx.version == "v6" {
			cmd = exec.Command(ctx.ipsetBin, "-exist", "create", ctx.SetName, ctx.SetType, "timeout", "300", "family", "inet6")
		} else {
			cmd = exec.Command(ctx.ipsetBin, "-exist", "create", ctx.SetName, ctx.SetType, "timeout", "300")
		}
		log.Infof("ipset set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error while creating set : %w --> %s", err, string(out))
		}
	}

	// waiting for propagation
	time.Sleep(1 * time.Second)

	// checking if iptables rules exist
	checkOk := true
	for _, checkCmd := range ctx.CheckIptableCmds {
		cmd = exec.Command(ctx.iptablesBin, checkCmd...)
		if stdout, err := cmd.CombinedOutput(); err != nil {
			checkOk = false
			/*rule doesn't exist, avoid alarming error messages*/
			if strings.Contains(string(stdout), "iptables: Bad rule") {
				log.Infof("Rule doesn't exist (%s)", cmd.String())
			} else {
				log.Warningf("iptables check command (%s) failed : %s", cmd.String(), err)
				log.Debugf("output: %s", string(stdout))
			}
		}
	}
	/*if any of the check command error'ed, exec the setup command*/
	if !checkOk {
		// if doesn't exist, create it
		for _, startCmd := range ctx.StartupCmds {
			cmd = exec.Command(ctx.iptablesBin, startCmd...)
			log.Infof("iptables set-up : %s", cmd.String())
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Warningf("Error inserting set in iptables (%s): %v : %s", cmd.String(), err, string(out))
				return fmt.Errorf("while inserting set in iptables: %w", err)
			}
		}
	}
	return nil
}

func (ctx *ipTablesContext) add(decision *models.Decision) error {
	/*Create our set*/

	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Debugf("ipset add ban [%s] (for %d seconds)", *decision.Value, int(banDuration.Seconds()))
	if banDuration.Seconds() > 2147483 {
		log.Warnf("Ban duration too long (%d seconds), maximum for ipset is 2147483, setting duration to 2147482", int(banDuration.Seconds()))
		banDuration = time.Duration(2147482) * time.Second
	}
	cmd := exec.Command(ctx.ipsetBin, "-exist", "add", ctx.SetName, *decision.Value, "timeout", fmt.Sprintf("%d", int(banDuration.Seconds())))
	log.Debugf("ipset add : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while inserting in set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	// ipset -exist add test 192.168.0.1 timeout 600
	return nil
}

func (ctx *ipTablesContext) shutDown() error {
	/*clean iptables rules*/
	var cmd *exec.Cmd
	// if doesn't exist, create it
	for _, startCmd := range ctx.ShutdownCmds {
		cmd = exec.Command(ctx.iptablesBin, startCmd...)
		log.Infof("iptables clean-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "Set "+ctx.SetName+" doesn't exist.") {
				log.Infof("ipset '%s' doesn't exist, skip", ctx.SetName)
			} else {
				log.Errorf("error while removing set entry in iptables : %v --> %s", err, string(out))
			}
		}
	}

	/*clean ipset set*/
	var ipsetCmd string
	if ctx.ipsetContentOnly {
		ipsetCmd = "flush"
	} else {
		ipsetCmd = "destroy"
	}
	cmd = exec.Command(ctx.ipsetBin, "-exist", ipsetCmd, ctx.SetName)
	log.Infof("ipset clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "The set with the given name does not exist") {
			log.Infof("ipset '%s' doesn't exist, skip", ctx.SetName)
		} else {
			log.Errorf("set %s error : %v - %s", ipsetCmd, err, string(out))
		}
	}
	return nil
}

func (ctx *ipTablesContext) delete(decision *models.Decision) error {
	/*
		ipset -exist delete test 192.168.0.1 timeout 600
		ipset -exist add test 192.168.0.1 timeout 600
	*/
	log.Debugf("ipset del ban for [%s]", *decision.Value)
	cmd := exec.Command(ctx.ipsetBin, "-exist", "del", ctx.SetName, *decision.Value)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	// ipset -exist add test 192.168.0.1 timeout 600
	return nil
}
