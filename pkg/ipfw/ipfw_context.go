package ipfw

import (
	"bufio"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type ipfwContext struct {
	table   string
	version string
}

const backendName = "ipfw"

func decisionsToIPs(decisions []*models.Decision) []string {
	ips := make([]string, 0, len(decisions))

	for _, d := range decisions {
		if d == nil || d.Value == nil {
			continue
		}

		ips = append(ips, *d.Value)
	}

	return ips
}

// writeScript writes a sequence of "table <name> <action> <ip>" commands to a
// temp file, to be run in a single batch with "ipfw -q <file>".
func writeScript(table, action string, ips []string) (string, error) {
	f, err := os.CreateTemp("", "crowdsec-ipfw-*.txt")
	if err != nil {
		return "", err
	}

	name := f.Name()
	done := false

	defer func() {
		if !done {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()

	w := bufio.NewWriter(f)
	for _, ip := range ips {
		if _, err = fmt.Fprintf(w, "table %s %s %s\n", table, action, ip); err != nil {
			return "", err
		}
	}

	if err = w.Flush(); err != nil {
		return "", err
	}

	if err = f.Close(); err != nil {
		return "", err
	}

	done = true

	return name, nil
}

// checkTable makes sure the table already exists, it must be created
// beforehand along with the rule(s) referencing it (e.g. "deny ip from
// table(<name>) to any"), the bouncer only manages table membership.
func (ctx *ipfwContext) checkTable() error {
	log.Infof("Checking ipfw table: %s", ctx.table)

	cmd := execIpfw("table", ctx.table, "info")

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("table %s doesn't exist: %s - %w", ctx.table, out, err)
	}

	return nil
}

func (ctx *ipfwContext) shutDown() error {
	cmd := execIpfw("table", ctx.table, "flush")
	log.Infof("ipfw table clean-up: %s", cmd)

	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Error while flushing table (%s): %v --> %s", cmd, err, out)
	}

	return nil
}

func (ctx *ipfwContext) add(decisions []*models.Decision) error {
	log.Debugf("Adding %d decisions", len(decisions))

	ips := decisionsToIPs(decisions)

	file, err := writeScript(ctx.table, "add", ips)
	if err != nil {
		return fmt.Errorf("writing decisions to temp file: %w", err)
	}
	defer os.Remove(file)

	cmd := execIpfw("-q", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error while adding to table (%s): %w --> %s", cmd, err, out)
	}

	return nil
}

func (ctx *ipfwContext) delete(decisions []*models.Decision) error {
	log.Debugf("Removing %d decisions", len(decisions))

	ips := decisionsToIPs(decisions)

	file, err := writeScript(ctx.table, "delete", ips)
	if err != nil {
		return fmt.Errorf("writing decisions to temp file: %w", err)
	}
	defer os.Remove(file)

	cmd := execIpfw("-q", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from table (%s): %v --> %s", cmd, err, out)
	}

	return nil
}

func (ctx *ipfwContext) init() error {
	if err := ctx.shutDown(); err != nil {
		return fmt.Errorf("ipfw table flush failed: %w", err)
	}

	if err := ctx.checkTable(); err != nil {
		return fmt.Errorf("ipfw init failed: %w", err)
	}

	log.Infof("%s initiated for %s", backendName, ctx.version)

	return nil
}
