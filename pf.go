package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type pfContext struct {
	proto   string
	anchor  string
	table   string
	version string
}

type pf struct {
	inet  *pfContext
	inet6 *pfContext
}

const (
	backendName = "pf"

	pfctlCmd = "/sbin/pfctl"
	pfDevice = "/dev/pf"

	addBanFormat = "%s: add ban on %s for %s sec (%s)"
	delBanFormat = "%s: del ban on %s for %s sec (%s)"
)

func newPF(config *bouncerConfig) (backend, error) {
	ret := &pf{}

	inetCtx := &pfContext{
		table:   config.BlacklistsIpv4,
		proto:   "inet",
		anchor:  config.PF.AnchorName,
		version: "ipv4",
	}

	inet6Ctx := &pfContext{
		table:   config.BlacklistsIpv6,
		proto:   "inet6",
		anchor:  config.PF.AnchorName,
		version: "ipv6",
	}

	ret.inet = inetCtx

	if config.DisableIPV6 {
		return ret, nil
	}

	ret.inet6 = inet6Ctx

	return ret, nil
}

func execPfctl(anchor string, arg ...string) *exec.Cmd {
	if anchor != "" {
		arg = append([]string{"-a", anchor}, arg...)
	}
	return exec.Command(pfctlCmd, arg...)
}

func (ctx *pfContext) checkTable() error {
	log.Infof("Checking pf table: %s", ctx.table)

	cmd := execPfctl(ctx.anchor, "-s", "Tables")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "pfctl error: %v - %s", err, string(out))
	}

	if !strings.Contains(string(out), ctx.table) {
		if ctx.anchor != "" {
			return errors.Errorf("table %s in anchor %s doesn't exist", ctx.table, ctx.anchor)
		}
		return errors.Errorf("table %s doesn't exist", ctx.table)
	}

	return nil
}

func (ctx *pfContext) shutDown() error {
	cmd := execPfctl(ctx.anchor, "-t", ctx.table, "-T", "flush")
	log.Infof("pf table clean-up: %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Error while flushing table (%s): %v --> %s", cmd.String(), err, string(out))
	}

	return nil
}

func (ctx *pfContext) Add(decision *models.Decision) error {
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Debugf(addBanFormat, backendName, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)

	cmd := execPfctl(ctx.anchor, "-t", ctx.table, "-T", "add", *decision.Value)
	log.Debugf("pfctl add: %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while adding to table (%s): %v --> %s", cmd.String(), err, string(out))
	}

	cmd = execPfctl("", "-k", *decision.Value)
	log.Debugf("pfctl flush state: %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while flushing state (%s): %v --> %s", cmd.String(), err, string(out))
	}

	return nil
}

func (ctx *pfContext) Delete(decision *models.Decision) error {
	banDuration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return err
	}
	log.Debugf(delBanFormat, backendName, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
	cmd := execPfctl(ctx.anchor, "-t", ctx.table, "-T", "delete", *decision.Value)
	log.Debugf("pfctl del: %s", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from table (%s): %v --> %s", cmd.String(), err, string(out))
	}
	return nil
}

func initPF(ctx *pfContext) error {
	if err := ctx.shutDown(); err != nil {
		return errors.Wrap(err, "pf table flush failed")
	}
	if err := ctx.checkTable(); err != nil {
		return errors.Wrap(err, "pf init failed")
	}
	log.Infof("%s initiated for %s", backendName, ctx.version)

	return nil
}

func (pf *pf) Init() error {
	if _, err := os.Stat(pfDevice); err != nil {
		return errors.Wrapf(err, "%s device not found", pfDevice)
	}

	if _, err := exec.LookPath(pfctlCmd); err != nil {
		return errors.Wrapf(err, "%s command not found", pfctlCmd)
	}

	if err := initPF(pf.inet); err != nil {
		return err
	}

	if pf.inet6 != nil {
		if err := initPF(pf.inet6); err != nil {
			return err
		}
	}

	return nil
}

func (pf *pf) Commit() error {
	return nil
}

func (pf *pf) Add(decision *models.Decision) error {
	if strings.Contains(*decision.Value, ":") && pf.inet6 != nil { // inet6
		if pf.inet6 == nil {
			log.Debugf("not adding '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
		if err := pf.inet6.Add(decision); err != nil {
			return fmt.Errorf("failed to add ban ip '%s' to inet6 table", *decision.Value)
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
		if pf.inet6 == nil {
			log.Debugf("not removing '%s' because ipv6 is disabled", *decision.Value)
			return nil
		}
		if err := pf.inet6.Delete(decision); err != nil {
			return fmt.Errorf("failed to remove ban ip '%s' from inet6 table", *decision.Value)
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
		return fmt.Errorf("unable to flush %s table (%s): ", pf.inet.version, pf.inet.table)
	}

	if pf.inet6 != nil {
		if err := pf.inet6.shutDown(); err != nil {
			return fmt.Errorf("unable to flush %s table (%s): ", pf.inet6.version, pf.inet6.table)
		}
	}

	return nil
}
