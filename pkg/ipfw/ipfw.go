package ipfw

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
)

type ipfw struct {
	inet              *ipfwContext
	inet6             *ipfwContext
	decisionsToAdd    []*models.Decision
	decisionsToDelete []*models.Decision
}

const ipfwCmd = "/sbin/ipfw"

func NewIPFW(config *cfg.BouncerConfig) (types.Backend, error) {
	ret := &ipfw{}

	inetCtx := &ipfwContext{
		table:   config.BlacklistsIpv4,
		version: "ipv4",
	}

	inet6Ctx := &ipfwContext{
		table:   config.BlacklistsIpv6,
		version: "ipv6",
	}

	if !config.DisableIPV4 {
		ret.inet = inetCtx
	}

	if !config.DisableIPV6 {
		ret.inet6 = inet6Ctx
	}

	return ret, nil
}

func execIpfw(arg ...string) *exec.Cmd {
	log.Debugf("Running: %s %s", ipfwCmd, arg)

	return exec.Command(ipfwCmd, arg...)
}

func (fw *ipfw) Init() error {
	if _, err := exec.LookPath(ipfwCmd); err != nil {
		return fmt.Errorf("%s command not found: %w", ipfwCmd, err)
	}

	if fw.inet != nil {
		if err := fw.inet.init(); err != nil {
			return err
		}
	}

	if fw.inet6 != nil {
		if err := fw.inet6.init(); err != nil {
			return err
		}
	}

	return nil
}

func (fw *ipfw) Commit() error {
	defer fw.reset()

	if err := fw.commitDeletedDecisions(); err != nil {
		return err
	}

	return fw.commitAddedDecisions()
}

func (fw *ipfw) Add(decision *models.Decision) error {
	fw.decisionsToAdd = append(fw.decisionsToAdd, decision)
	return nil
}

func (fw *ipfw) reset() {
	fw.decisionsToAdd = make([]*models.Decision, 0)
	fw.decisionsToDelete = make([]*models.Decision, 0)
}

func (fw *ipfw) commitDeletedDecisions() error {
	ipv4decisions := make([]*models.Decision, 0)
	ipv6decisions := make([]*models.Decision, 0)

	for _, d := range fw.decisionsToDelete {
		if strings.Contains(*d.Value, ":") && fw.inet6 != nil {
			ipv6decisions = append(ipv6decisions, d)
		} else if fw.inet != nil {
			ipv4decisions = append(ipv4decisions, d)
		}
	}

	if len(ipv6decisions) > 0 {
		if fw.inet6 == nil {
			log.Debugf("not removing '%d' decisions because ipv6 is disabled", len(ipv6decisions))
		} else if err := fw.inet6.delete(ipv6decisions); err != nil {
			return err
		}
	}

	if len(ipv4decisions) > 0 {
		if fw.inet == nil {
			log.Debugf("not removing '%d' decisions because ipv4 is disabled", len(ipv4decisions))
		} else if err := fw.inet.delete(ipv4decisions); err != nil {
			return err
		}
	}

	return nil
}

func (fw *ipfw) commitAddedDecisions() error {
	ipv4decisions := make([]*models.Decision, 0)
	ipv6decisions := make([]*models.Decision, 0)

	for _, d := range fw.decisionsToAdd {
		if strings.Contains(*d.Value, ":") && fw.inet6 != nil {
			ipv6decisions = append(ipv6decisions, d)
		} else if fw.inet != nil {
			ipv4decisions = append(ipv4decisions, d)
		}
	}

	if len(ipv6decisions) > 0 {
		if fw.inet6 == nil {
			log.Debugf("not adding '%d' decisions because ipv6 is disabled", len(ipv6decisions))
		} else if err := fw.inet6.add(ipv6decisions); err != nil {
			return err
		}
	}

	if len(ipv4decisions) > 0 {
		if fw.inet == nil {
			log.Debugf("not adding '%d' decisions because ipv4 is disabled", len(ipv4decisions))
		} else if err := fw.inet.add(ipv4decisions); err != nil {
			return err
		}
	}

	return nil
}

func (fw *ipfw) Delete(decision *models.Decision) error {
	fw.decisionsToDelete = append(fw.decisionsToDelete, decision)
	return nil
}

func (fw *ipfw) ShutDown() error {
	log.Infof("flushing 'crowdsec' table(s)")

	if fw.inet != nil {
		if err := fw.inet.shutDown(); err != nil {
			return fmt.Errorf("unable to flush %s table (%s): ", fw.inet.version, fw.inet.table)
		}
	}

	if fw.inet6 != nil {
		if err := fw.inet6.shutDown(); err != nil {
			return fmt.Errorf("unable to flush %s table (%s): ", fw.inet6.version, fw.inet6.table)
		}
	}

	return nil
}
