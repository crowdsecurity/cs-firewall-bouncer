package pf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

type pf struct {
	inet              *pfContext
	inet6             *pfContext
	decisionsToAdd    []*models.Decision
	decisionsToDelete []*models.Decision
}

const (
	pfctlCmd = "/sbin/pfctl"
	pfDevice = "/dev/pf"
)

func NewPF(config *cfg.BouncerConfig) (types.Backend, error) {
	ret := &pf{}

	batchSize := config.PF.BatchSize
	if batchSize == 0 {
		batchSize = 2000
	}

	inetCtx := &pfContext{
		table:     config.BlacklistsIpv4,
		proto:     "inet",
		anchor:    config.PF.AnchorName,
		version:   "ipv4",
		batchSize: batchSize,
	}

	inet6Ctx := &pfContext{
		table:     config.BlacklistsIpv6,
		proto:     "inet6",
		anchor:    config.PF.AnchorName,
		version:   "ipv6",
		batchSize: batchSize,
	}

	ret.inet = inetCtx

	if !config.DisableIPV6 {
		ret.inet6 = inet6Ctx
	}

	return ret, nil
}

// execPfctl runs a pfctl command by prepending the anchor name if needed.
// Some commands return an error if an anchor is specified.
func execPfctl(anchor string, arg ...string) *exec.Cmd {
	if anchor != "" {
		arg = append([]string{"-a", anchor}, arg...)
	}

	log.Tracef("Running: %s %s", pfctlCmd, arg)

	return exec.Command(pfctlCmd, arg...)
}

func (pf *pf) Init() error {
	if _, err := os.Stat(pfDevice); err != nil {
		return fmt.Errorf("%s device not found: %w", pfDevice, err)
	}

	if _, err := exec.LookPath(pfctlCmd); err != nil {
		return fmt.Errorf("%s command not found: %w", pfctlCmd, err)
	}

	if err := pf.inet.init(); err != nil {
		return err
	}

	if pf.inet6 != nil {
		if err := pf.inet6.init(); err != nil {
			return err
		}
	}

	return nil
}

func (pf *pf) Commit() error {
	defer pf.reset()

	if err := pf.commitDeletedDecisions(); err != nil {
		return err
	}

	if err := pf.commitAddedDecisions(); err != nil {
		return err
	}

	return nil
}

func (pf *pf) Add(decision *models.Decision) error {
	pf.decisionsToAdd = append(pf.decisionsToAdd, decision)
	return nil
}

func (pf *pf) reset() {
	pf.decisionsToAdd = make([]*models.Decision, 0)
	pf.decisionsToDelete = make([]*models.Decision, 0)
}

func (pf *pf) commitDeletedDecisions() error {
	ipv4decisions := make([]*models.Decision, 0)
	ipv6decisions := make([]*models.Decision, 0)

	for _, d := range pf.decisionsToDelete {
		if strings.Contains(*d.Value, ":") && pf.inet6 != nil {
			ipv6decisions = append(ipv6decisions, d)
		} else {
			ipv4decisions = append(ipv4decisions, d)
		}
	}

	if len(ipv6decisions) > 0 {
		if pf.inet6 == nil {
			log.Debugf("not removing '%d' decisions because ipv6 is disabled", len(ipv6decisions))
		} else {
			if err := pf.inet6.delete(ipv6decisions); err != nil {
				return err
			}
		}
	}

	if len(ipv4decisions) > 0 {
		if err := pf.inet.delete(ipv4decisions); err != nil {
			return err
		}
	}

	return nil
}

func (pf *pf) commitAddedDecisions() error {
	ipv4decisions := make([]*models.Decision, 0)
	ipv6decisions := make([]*models.Decision, 0)

	for _, d := range pf.decisionsToAdd {
		if strings.Contains(*d.Value, ":") && pf.inet6 != nil {
			ipv6decisions = append(ipv6decisions, d)
		} else {
			ipv4decisions = append(ipv4decisions, d)
		}
	}

	if len(ipv6decisions) > 0 {
		if pf.inet6 == nil {
			log.Debugf("not adding '%d' decisions because ipv6 is disabled", len(ipv6decisions))
		} else {
			if err := pf.inet6.add(ipv6decisions); err != nil {
				return err
			}
		}
	}

	if len(ipv4decisions) > 0 {
		if err := pf.inet.add(ipv4decisions); err != nil {
			return err
		}
	}

	return nil
}

func (pf *pf) Delete(decision *models.Decision) error {
	pf.decisionsToDelete = append(pf.decisionsToDelete, decision)
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
