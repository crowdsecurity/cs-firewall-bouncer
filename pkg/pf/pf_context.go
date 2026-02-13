package pf

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type pfContext struct {
	proto   string
	anchor  string
	table   string
	version string
}

const backendName = "pf"

func decisionsToIPs(decisions []*models.Decision) []string {
	ips := make([]string, 0, len(decisions))

	for i, d := range decisions {
		if d == nil || d.Value == nil {
			continue
		}

		ips[i] = *d.Value
	}

	return ips
}

func writeIPsToFile(ips []string) (string, error) {
	f, err := os.CreateTemp("", "crowdsec-ips-*.txt")
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
		if _, err = w.WriteString(ip + "\n"); err != nil {
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

func (ctx *pfContext) checkTable() error {
	log.Infof("Checking pf table: %s", ctx.table)

	cmd := execPfctl(ctx.anchor, "-s", "Tables")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl error: %s - %w", out, err)
	}

	if !strings.Contains(string(out), ctx.table) {
		if ctx.anchor != "" {
			return fmt.Errorf("table %s in anchor %s doesn't exist", ctx.table, ctx.anchor)
		}

		return fmt.Errorf("table %s doesn't exist", ctx.table)
	}

	return nil
}

func (ctx *pfContext) shutDown() error {
	cmd := execPfctl(ctx.anchor, "-t", ctx.table, "-T", "flush")
	log.Infof("pf table clean-up: %s", cmd)

	if out, err := cmd.CombinedOutput(); err != nil {
		log.Errorf("Error while flushing table (%s): %v --> %s", cmd, err, out)
	}

	return nil
}

// getStateIPs returns a list of IPs that are currently in the state table.
func getStateIPs() (map[string]bool, error) {
	ret := make(map[string]bool)

	cmd := exec.Command(pfctlCmd, "-s", "states")

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		// don't bother to parse the direction, we'll block both anyway

		// right side
		ip := fields[4]
		if strings.Contains(ip, ":") {
			ip = strings.Split(ip, ":")[0]
		}

		ret[ip] = true

		// left side
		ip = fields[2]
		if strings.Contains(ip, ":") {
			ip = strings.Split(ip, ":")[0]
		}

		ret[ip] = true
	}

	log.Debugf("Found IPs in state table: %v", len(ret))

	return ret, nil
}

func (ctx *pfContext) add(decisions []*models.Decision) error {
	log.Debugf("Adding %d decisions", len(decisions))

	ips := decisionsToIPs(decisions)

	file, err := writeIPsToFile(ips)
	if err != nil {
		return fmt.Errorf("writing decisions to temp file: %w", err)
	}
	defer os.Remove(file)

	cmd := execPfctl(ctx.anchor, "-t", ctx.table, "-T", "add", "-f", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error while adding to table (%s): %w --> %s", cmd, err, out)
	}

	bannedIPs := make(map[string]bool, len(ips))
	for _, ip := range ips {
		bannedIPs[ip] = true
	}

	if len(bannedIPs) == 0 {
		log.Debugf("No new banned IPs")
		return nil
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		keys := slices.Collect(maps.Keys(bannedIPs))
		slices.Sort(keys)
		log.Debugf("New banned IPs: %v", keys)
	}

	stateIPs, err := getStateIPs()
	if err != nil {
		return fmt.Errorf("error while getting state IPs: %w", err)
	}

	// Reset the states of connections coming from or going to an IP if it's both in stateIPs and bannedIPs

	for ip := range bannedIPs {
		if stateIPs[ip] {
			// incoming
			cmd := execPfctl("", "-k", ip)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Errorf("Error while flushing state (%s): %v --> %s", cmd, err, out)
			}

			// outgoing
			cmd = execPfctl("", "-k", "0.0.0.0/0", "-k", ip)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Errorf("Error while flushing state (%s): %v --> %s", cmd, err, out)
			}
		}
	}

	return nil
}

func (ctx *pfContext) delete(decisions []*models.Decision) error {
	log.Debugf("Removing %d decisions", len(decisions))

	ips := decisionsToIPs(decisions)

	file, err := writeIPsToFile(ips)
	if err != nil {
		return fmt.Errorf("writing decisions to temp file: %w", err)
	}
	defer os.Remove(file)

	cmd := execPfctl(ctx.anchor, "-t", ctx.table, "-T", "delete", "-f", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Error while deleting from table (%s): %v --> %s", cmd, err, out)
	}

	return nil
}

func (ctx *pfContext) init() error {
	if err := ctx.shutDown(); err != nil {
		return fmt.Errorf("pf table flush failed: %w", err)
	}

	if err := ctx.checkTable(); err != nil {
		return fmt.Errorf("pf init failed: %w", err)
	}

	log.Infof("%s initiated for %s", backendName, ctx.version)

	return nil
}
