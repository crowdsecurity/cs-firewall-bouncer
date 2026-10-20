package pf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/netip"
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

	for _, d := range decisions {
		if d == nil || d.Value == nil {
			continue
		}

		ips = append(ips, *d.Value)
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

// stateHostIP extracts the address from a host printed by "pfctl -s states":
// "192.0.2.1:80" for IPv4, "2001:db8::1[80]" for IPv6, with or without port.
// NAT/rdr hosts are wrapped in parentheses.
func stateHostIP(host string) (netip.Addr, bool) {
	host = strings.Trim(host, "()")

	if i := strings.IndexByte(host, '['); i >= 0 {
		host = host[:i]
	} else if strings.Count(host, ":") == 1 {
		host, _, _ = strings.Cut(host, ":")
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr, true
}

// parseStateIPs returns the set of addresses found in the output of "pfctl -s states".
func parseStateIPs(reader io.Reader) map[string]bool {
	ret := make(map[string]bool)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		// skip the interface and protocol; the remaining fields are hosts
		// (possibly with a translated address in parentheses), the direction
		// and the connection state. Don't bother to parse the direction,
		// we'll block both anyway.
		for _, field := range fields[2:] {
			if addr, ok := stateHostIP(field); ok {
				ret[addr.String()] = true
			}
		}
	}

	return ret
}

// getStateIPs returns a list of IPs that are currently in the state table.
func getStateIPs() (map[string]bool, error) {
	cmd := exec.Command(pfctlCmd, "-s", "states")

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	ret := parseStateIPs(bytes.NewReader(out))

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

	anyAddr := "0.0.0.0/0"
	if ctx.proto == "inet6" {
		anyAddr = "::/0"
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
			cmd = execPfctl("", "-k", anyAddr, "-k", ip)
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
