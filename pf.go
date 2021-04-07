// +build openbsd freebsd

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/crowdsecurity/crowdsec/pkg/models"

	log "github.com/sirupsen/logrus"
)

type pfContext struct {
        proto  string
        table  string
}

type pf struct {
	inet  *pfContext
	inet6 *pfContext
}

const (
	pfctlCmd = "/sbin/pfctl"
	pfDevice = "/dev/pf"
)

var pfCtx = &pf{}

func newPF(config *bouncerConfig) (interface{}, error) {
	ret := &pf{}

	inetCtx := &pfContext{
		table: "crowdsec-blacklists",
		proto: "inet",
	}

	inet6Ctx := &pfContext{
		table: "crowdsec6-blacklists",
		proto: "inet6",
	}

	ret.inet = inetCtx

	if config.DisableIPV6 {
		return ret, nil
	}

	ret.inet6 = inet6Ctx

	return ret, nil
}

func (ctx *pfContext) checkTable() error {
	log.Infof("Checking pf table: %s", ctx.table)

	cmd := exec.Command(pfctlCmd, "-s", "Tables")
	out, err := cmd.CombinedOutput()

	if err != nil {
		return errors.Wrapf(err, "pfctl error : %v - %s", err, string(out))
	} else if !strings.Contains(string(out), ctx.table) {
		return errors.Errorf("table %s doesn't exist", ctx.table)
	}

	return nil
}

func (ctx *pfContext) shutDown() error {
	cmd := exec.Command(pfctlCmd, "-t", ctx.table, "-T", "flush")
	log.Infof("pf table clean-up : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Error while flushing table (%s): %v - %s", err, string(out))
	}
	return nil
}

func (ctx *pfContext) Add(decision *models.Decision) error {
	log.Debugf("pfctl add ban [%s]", *decision.Value)
	cmd := exec.Command(pfctlCmd, "-t", ctx.table, "-T", "add", *decision.Value)
	log.Debugf("pfctl add : %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while adding to table (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func (ctx *pfContext) Delete(decision *models.Decision) error {
	log.Debugf("pfctl del ban for [%s]", *decision.Value)
	cmd := exec.Command(pfctlCmd, "-t", ctx.table, "-T", "delete", *decision.Value)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from table (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func (pf *pf) Init() error {
	var err error

	if _, err := os.Stat(pfDevice); err != nil {
		return fmt.Errorf("%s device not found: %s", pfDevice, err.Error())
	}

	if _, err := exec.LookPath(pfctlCmd); err != nil {
		return fmt.Errorf("%s command not found: %s", pfctlCmd, err.Error())
	}

	if err := pf.inet.shutDown(); err != nil {
		return fmt.Errorf("pf table flush failed: %s", err.Error())
	}
	if err := pf.inet.checkTable(); err != nil {
		return fmt.Errorf("pf init failed: %s", err.Error())
	}
	log.Printf("pf for ipv4 initiated")

	if pf.inet6 != nil {
		if err = pf.inet.shutDown(); err != nil {
			return fmt.Errorf("pf shutdown failed: %s", err.Error())
		}
		if err := pf.inet.checkTable(); err != nil {
			return fmt.Errorf("pf init failed: %s", err.Error())
		}
		log.Printf("pf for ipv6 initiated")
	}

	return nil
}

func (pf *pf) Add(decision *models.Decision) error {
	if strings.Contains(*decision.Value, ":") && pf.inet6 != nil { // inet6
		if pf.inet6 != nil {
			if err := pf.inet6.Add(decision); err != nil {
				return fmt.Errorf("failed to add ban ip '%s' to inet6 table", *decision.Value)
			}
		} else {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // inet
		if err := pf.inet.Add(decision); err != nil {
				return fmt.Errorf("failed adding ban ip '%s' to inet table", *decision.Value)
		}
	}

	return nil
}

func (pf *pf) Delete(decision *models.Decision) error {
	if strings.Contains(*decision.Value, ":") { // ipv6
		if pf.inet6 != nil {
			if err := pf.inet6.Delete(decision); err != nil {
				return fmt.Errorf("failed to remove ban ip '%s' from inet6 table", *decision.Value)
			}
		} else {
			log.Debugf("not removing '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
	} else { // ipv4
		if err := pf.inet.Delete(decision); err != nil {
			return fmt.Errorf("failed to remove ban ip '%s' from inet6 table", *decision.Value)
		}
	}

	return nil
}

func (pf *pf) ShutDown() error {
	log.Infof("flushing 'crowdsec' table(s)")

	if err := pf.inet.shutDown(); err != nil {
		return fmt.Errorf("unable to flush inet table (%s): ", pf.inet.table)
	}

	if pf.inet6 != nil {
		if err := pf.inet6.shutDown(); err != nil {
			return fmt.Errorf("unable to flush inet table (%s): ", pf.inet.table)
		}
	}

	return nil
}
