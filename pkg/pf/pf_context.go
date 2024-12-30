package pf

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type pfContext struct {
	proto     string
	anchor    string
	table     string
	version   string
	batchSize int
}

const backendName = "pf"

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

// getStatesToKill returns the states of the connections that must be terminated.
func getStatesToKill(banned map[string]struct{}) (map[string]map[string]struct{}, error) {
	ret := make(map[string]map[string]struct{})

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

		left := fields[2]
		if strings.Contains(left, ":") {
			left = strings.Split(left, ":")[0]
		}

		right := fields[4]
		if strings.Contains(right, ":") {
			right = strings.Split(right, ":")[0]
		}

		// Don't know the direction, is left or right the origin of the connection?
		// We either look at the arrow direction, or don't need to care and will treat both cases.
		//
		// The banned ip will be associated to an empty map (will call pfctl -k <banned_ip>)
		// The other ip will be associated to a map where the keys are the banned ips with an existing connection.
		// (i.e. pfctl -k <other_ip> -k <banned_ip>) so we don't have to terminate ALL connections from other_ip.

		var bannedIP, otherIP string

		if _, ok := banned[left]; ok {
			bannedIP = left
			otherIP = right
		}

		if _, ok := banned[right]; ok {
			bannedIP = right
			otherIP = left
		}

		if bannedIP == "" {
			continue
		}

		// will call "pfctl -k <banned_ip>"
		ret[bannedIP] = make(map[string]struct{})

		// will call "pfctl -k <other_ip> -k <banned_ip>"
		if _, ok := ret[otherIP]; !ok {
			ret[otherIP] = make(map[string]struct{})
		}

		ret[otherIP][bannedIP] = struct{}{}
	}

	return ret, nil
}

func (ctx *pfContext) add(decisions []*models.Decision) error {
	chunks := slicetools.Chunks(decisions, ctx.batchSize)
	for _, chunk := range chunks {
		if err := ctx.addChunk(chunk); err != nil {
			log.Errorf("error while adding decision chunk: %s", err)
		}
	}

	bannedIPs := make(map[string]struct{})
	for _, d := range decisions {
		bannedIPs[*d.Value] = struct{}{}
	}

	if len(bannedIPs) == 0 {
		log.Tracef("No new banned IPs")
		return nil
	}

	log.Tracef("New banned IPs: %v", bannedIPs)

	// Get the states of connections
	//  - from a banned IP
	//  - from any IP to a banned IP

	states, err := getStatesToKill(bannedIPs)
	if err != nil {
		return fmt.Errorf("error while getting state IPs: %w", err)
	}

	for source := range states {
		targets := states[source]
		if len(targets) == 0 {
			cmd := execPfctl("", "-k", source)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Errorf("Error while flushing state (%s): %v --> %s", cmd, err, out)
			}
			continue
		}

		for target := range targets {
			cmd := execPfctl("", "-k", source, "-k", target)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Errorf("Error while flushing state (%s): %v --> %s", cmd, err, out)
			}
		}
	}

	return nil
}

func (ctx *pfContext) addChunk(decisions []*models.Decision) error {
	log.Debugf("Adding chunk with %d decisions", len(decisions))

	addArgs := []string{"-t", ctx.table, "-T", "add"}

	for _, d := range decisions {
		addArgs = append(addArgs, *d.Value)
	}

	cmd := execPfctl(ctx.anchor, addArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error while adding to table (%s): %w --> %s", cmd, err, out)
	}

	return nil
}

func (ctx *pfContext) delete(decisions []*models.Decision) error {
	chunks := slicetools.Chunks(decisions, ctx.batchSize)
	for _, chunk := range chunks {
		if err := ctx.deleteChunk(chunk); err != nil {
			log.Errorf("error while deleting decision chunk: %s", err)
		}
	}

	return nil
}

func (ctx *pfContext) deleteChunk(decisions []*models.Decision) error {
	delArgs := []string{"-t", ctx.table, "-T", "delete"}

	for _, d := range decisions {
		delArgs = append(delArgs, *d.Value)
	}

	cmd := execPfctl(ctx.anchor, delArgs...)
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
