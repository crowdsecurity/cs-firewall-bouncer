package cfg

import (
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/types"
	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
)

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

const (
	IpsetMode    = "ipset"
	IptablesMode = "iptables"
	NftablesMode = "nftables"
	PfMode       = "pf"
	DryRunMode   = "dry-run"
)

type BouncerConfig struct {
	Mode            string        `yaml:"mode"`    // ipset,iptables,tc
	PidDir          string        `yaml:"pid_dir"` // unused
	UpdateFrequency string        `yaml:"update_frequency"`
	Daemon          *bool         `yaml:"daemonize"` // unused
	Logging         LoggingConfig `yaml:",inline"`
	DisableIPV6     bool          `yaml:"disable_ipv6"`
	DenyAction      string        `yaml:"deny_action"`
	DenyLog         bool          `yaml:"deny_log"`
	DenyLogPrefix   string        `yaml:"deny_log_prefix"`
	BlacklistsIpv4  string        `yaml:"blacklists_ipv4"` // unused for nftables
	BlacklistsIpv6  string        `yaml:"blacklists_ipv6"` // unused for nftables
	SetType         string        `yaml:"ipset_type"`
	SetSize         int           `yaml:"ipset_size"`

	// specific to iptables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/19
	IptablesChains          []string `yaml:"iptables_chains"`
	SupportedDecisionsTypes []string `yaml:"supported_decisions_types"`
	// specific to nftables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/74,
	// https://github.com/crowdsecurity/cs-firewall-bouncer/issues/153
	Nftables struct {
		Enabled *bool                        `yaml:"enabled"`
		Targets []types.NftablesTargetConfig `yaml:"targets"`
	} `yaml:"nftables"`
	PF struct {
		AnchorName string `yaml:"anchor_name"`
		BatchSize  int    `yaml:"batch_size"`
	} `yaml:"pf"`
	PrometheusConfig PrometheusConfig `yaml:"prometheus"`
}

// MergedConfig() returns the byte content of the patched configuration file (with .yaml.local).
func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")

	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}

	return data, nil
}

func NewConfig(reader io.Reader) (*BouncerConfig, error) {
	config := &BouncerConfig{}

	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	configBuff := csstring.StrictExpand(string(fcontent), os.LookupEnv)

	err = yaml.Unmarshal([]byte(configBuff), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err = config.Logging.setup("crowdsec-firewall-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	if config.Mode == "" {
		return nil, fmt.Errorf("config does not contain 'mode'")
	}

	if len(config.SupportedDecisionsTypes) == 0 {
		config.SupportedDecisionsTypes = []string{"ban"}
	}

	if config.PidDir != "" {
		log.Debug("Ignoring deprecated 'pid_dir' option")
	}

	if config.DenyLog && config.DenyLogPrefix == "" {
		config.DenyLogPrefix = "crowdsec drop: "
	}

	// for config file backward compatibility
	if config.BlacklistsIpv4 == "" {
		config.BlacklistsIpv4 = "crowdsec-blacklists"
	}

	if config.BlacklistsIpv6 == "" {
		config.BlacklistsIpv6 = "crowdsec6-blacklists"
	}

	if config.SetType == "" {
		config.SetType = "nethash"
	}

	if config.SetSize == 0 {
		config.SetSize = 131072
	}

	switch config.Mode {
	case NftablesMode:
		err := nftablesConfig(config)
		if err != nil {
			return nil, err
		}
	case IpsetMode, IptablesMode:
		// nothing specific to do
	case PfMode:
		err := pfConfig(config)
		if err != nil {
			return nil, err
		}
	case DryRunMode:
		// nothing specific to do
	default:
		log.Warningf("unexpected %s mode", config.Mode)
	}

	return config, nil
}

func pfConfig(config *BouncerConfig) error {
	return nil
}

func nftablesConfig(config *BouncerConfig) error {
	if config.Nftables.Enabled == nil {
		config.Nftables.Enabled = ptr.Of(false)
	}

	return nil
}
