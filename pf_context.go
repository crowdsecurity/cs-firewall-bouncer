package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

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

	log.Tracef("Found IPs in state table: %v", len(ret))
	return ret, nil
}

func (ctx *pfContext) add(decisions []*models.Decision) error {
	chunks := chunkItems(decisions, ctx.batchSize)
	for _, chunk := range chunks {
		if err := ctx.addChunk(chunk); err != nil {
			log.Errorf("error while adding decision chunk: %s", err)
		}
	}

	bannedIPs := make(map[string]bool)
	for _, d := range decisions {
		bannedIPs[*d.Value] = true
	}

	if len(bannedIPs) == 0 {
		log.Tracef("No new banned IPs")
		return nil
	}

	log.Tracef("New banned IPs: %v", bannedIPs)

	stateIPs, err := getStateIPs()
	if err != nil {
		return fmt.Errorf("error while getting state IPs: %w", err)
	}

	// Reset the states of connections coming from an IP if it's both in stateIPs and bannedIPs

	for ip := range bannedIPs {
		if stateIPs[ip] {
			cmd := execPfctl("", "-k", ip)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Errorf("Error while flushing state (%s): %v --> %s", cmd, err, out)
			}
		}
	}

	return nil
}

func (ctx *pfContext) addChunk(decisions []*models.Decision) error {
	addArgs := []string{"-t", ctx.table, "-T", "add"}

	log.Debugf("Adding chunk with %d decisions", len(decisions))
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
	chunks := chunkItems(decisions, ctx.batchSize)
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
