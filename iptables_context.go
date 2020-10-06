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
	SetName          string   //crowdsec-netfilter
	StartupCmds      []string //-I INPUT -m set --match-set myset src -j DROP
	ShutdownCmds     []string //-D INPUT -m set --match-set myset src -j DROP
	CheckIptableCmds []string
}

func (ctx *ipTablesContext) CheckAndCreate() error {
	var err error

	/* check if the set already exist */
	cmd := exec.Command(ctx.ipsetBin, "-L", ctx.SetName)
	if _, err = cmd.CombinedOutput(); err != nil { // if doesn't exist, create it
		if ctx.version == "v6" {
			cmd = exec.Command(ctx.ipsetBin, "-exist", "create", ctx.SetName, "nethash", "timeout", "300", "family", "inet6")
		} else {
			cmd = exec.Command(ctx.ipsetBin, "-exist", "create", ctx.SetName, "nethash", "timeout", "300")
		}
		log.Infof("ipset set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("Error while creating set : %v --> %s", err, string(out))
		}
	}

	//waiting for propagation
	time.Sleep(1 * time.Second)

	// checking if iptables rules exist
	cmd = exec.Command(ctx.iptablesBin, ctx.CheckIptableCmds...)
	if _, err := cmd.CombinedOutput(); err != nil { // if doesn't exist, create it
		cmd = exec.Command(ctx.iptablesBin, ctx.StartupCmds...)
		log.Infof("iptables set-up : %s", cmd.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("Error while insert set in iptables (%s): %v --> %s", cmd.String(), err, string(out))
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
	log.Infof("ipset add ban [%s] (for %d seconds)", *decision.Value, int(banDuration.Seconds()))
	cmd := exec.Command(ctx.ipsetBin, "-exist", "add", ctx.SetName, *decision.Value, "timeout", fmt.Sprintf("%d", int(banDuration.Seconds())))
	log.Debugf("ipset add : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while inserting in set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	//ipset -exist add test 192.168.0.1 timeout 600
	return nil
}

func (ctx *ipTablesContext) shutDown() error {
	/*clean iptables rules*/
	cmd := exec.Command(ctx.iptablesBin, ctx.ShutdownCmds...)
	log.Infof("iptables clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		/*if the set doesn't exist, don't frigthen user with error messages*/
		if strings.Contains(string(out), "Set crowdsec-blacklists doesn't exist.") {
			log.Infof("ipset 'crowdsec-blacklists' doesn't exist, skip")
		} else {
			log.Errorf("error while removing set entry in iptables : %v --> %s", err, string(out))
		}
	}
	/*clean ipset set*/
	cmd = exec.Command(ctx.ipsetBin, "-exist", "destroy", ctx.SetName)
	log.Infof("ipset clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "The set with the given name does not exist") {
			log.Infof("ipset 'crowdsec-blacklists' doesn't exist, skip")
		} else {
			log.Errorf("Error while destroying set : %v --> %s", err, string(out))
		}
	}

	return nil
}

func (ctx *ipTablesContext) delete(decision *models.Decision) error {
	/*
		ipset -exist delete test 192.168.0.1 timeout 600
		ipset -exist add test 192.168.0.1 timeout 600
	*/
	log.Infof("ipset del ban for [%s]", *decision.Value)
	cmd := exec.Command(ctx.ipsetBin, "-exist", "del", ctx.SetName, *decision.Value)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from set (%s): %v --> %s", cmd.String(), err, string(out))
	}
	//ipset -exist add test 192.168.0.1 timeout 600
	return nil
}
