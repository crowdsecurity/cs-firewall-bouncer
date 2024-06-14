//go:build linux
// +build linux

package iptables

import (
	"fmt"
	"os"
	"os/exec"
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
	StartupCmds      [][]string // -I INPUT -m set --match-set myset src -j DROP
	ShutdownCmds     [][]string // -D INPUT -m set --match-set myset src -j DROP
	CheckIptableCmds [][]string
	ipsetContentOnly bool
	Chains           []string

	ipset *ipsetcmd.IPSet

	toAdd []*models.Decision
	toDel []*models.Decision
}

func (ctx *ipTablesContext) CheckAndCreate() error {
	log.Infof("Checking existing set")
	/* check if the set already exist */
	if !ctx.ipset.Exists() {
		if ctx.ipsetContentOnly {
			/*if we manage ipset content only, error*/
			log.Errorf("set %s doesn't exist, can't manage content", ctx.SetName)
			return fmt.Errorf("set %s doesn't exist", ctx.SetName)
		}

		switch ctx.version {
		case "v4":
			err := ctx.ipset.Create(ipsetcmd.CreateOptions{
				Family:  "inet",
				Timeout: "300",
				MaxElem: strconv.Itoa(ctx.SetSize),
				Type:    ctx.SetType,
			})
			if err != nil {
				return err
			}
		case "v6":
			err := ctx.ipset.Create(ipsetcmd.CreateOptions{
				Family:  "inet6",
				Timeout: "300",
				MaxElem: strconv.Itoa(ctx.SetSize),
				Type:    ctx.SetType,
			})
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown version %s", ctx.version)
		}
	}

	// waiting for propagation
	time.Sleep(1 * time.Second)

	checkOk := true

	// checking if iptables rules exist
	for _, checkCmd := range ctx.CheckIptableCmds {
		cmd := exec.Command(ctx.iptablesBin, checkCmd...)
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
			cmd := exec.Command(ctx.iptablesBin, startCmd...)
			log.Infof("iptables set-up : %s", cmd.String())

			if out, err := cmd.CombinedOutput(); err != nil {
				log.Warningf("Error inserting set in iptables (%s): %v : %s", cmd.String(), err, string(out))
				return fmt.Errorf("while inserting set in iptables: %w", err)
			}
		}
	}

	return nil
}

func (ctx *ipTablesContext) commit() error {

	tmpFile, err := os.CreateTemp("", "cs-firewall-bouncer-ipset-")

	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())

		ctx.toAdd = nil
		ctx.toDel = nil
	}()

	if err != nil {
		return err
	}

	for _, decision := range ctx.toAdd {
		banDuration, err := time.ParseDuration(*decision.Duration)
		if err != nil {
			return err
		}

		if banDuration.Seconds() > 2147483 {
			log.Warnf("Ban duration too long (%d seconds), maximum for ipset is 2147483, setting duration to 2147482", int(banDuration.Seconds()))
			banDuration = time.Duration(2147482) * time.Second
		}

		addCmd := fmt.Sprintf("add %s %s timeout %d -exist\n", ctx.ipset.Name(), *decision.Value, int(banDuration.Seconds()))

		log.Debugf("%s", addCmd)

		_, err = tmpFile.WriteString(addCmd)

		if err != nil {
			log.Errorf("error while writing to temp file : %s", err)
			continue
		}
	}

	for _, decision := range ctx.toDel {
		delCmd := fmt.Sprintf("del %s %s -exist\n", ctx.ipset.Name(), *decision.Value)

		log.Debugf("%s", delCmd)

		_, err = tmpFile.WriteString(delCmd)

		if err != nil {
			log.Errorf("error while writing to temp file : %s", err)
			continue
		}
	}

	return ctx.ipset.Restore(tmpFile.Name())
}

func (ctx *ipTablesContext) add(decision *models.Decision) error {
	ctx.toAdd = append(ctx.toAdd, decision)
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
	if ctx.ipsetContentOnly {
		ctx.ipset.Flush()
	} else {
		ctx.ipset.Destroy()
	}

	return nil
}

func (ctx *ipTablesContext) delete(decision *models.Decision) error {
	ctx.toDel = append(ctx.toDel, decision)
	return nil
}
