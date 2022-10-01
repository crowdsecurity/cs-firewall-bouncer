package main

import (
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type nftablesFamilyConfig struct {
	Enabled *bool  `yaml:"enabled"`
	SetOnly bool   `yaml:"set-only"`
	Table   string `yaml:"table"`
	Chain   string `yaml:"chain"`
	// Blacklist string `yaml:"blacklist"`
}

const (
	IpsetMode    = "ipset"
	IptablesMode = "iptables"
	NftablesMode = "nftables"
	PfMode       = "pf"
)

type bouncerConfig struct {
	Mode            string    `yaml:"mode"` // ipset,iptables,tc
	PidDir          string    `yaml:"pid_dir"`
	UpdateFrequency string    `yaml:"update_frequency"`
	Daemon          bool      `yaml:"daemonize"`
	LogMode         string    `yaml:"log_mode"`
	LogDir          string    `yaml:"log_dir"`
	LogLevel        log.Level `yaml:"log_level"`
	CompressLogs    *bool     `yaml:"compress_logs,omitempty"`
	LogMaxSize      int       `yaml:"log_max_size,omitempty"`
	LogMaxFiles     int       `yaml:"log_max_files,omitempty"`
	LogMaxAge       int       `yaml:"log_max_age,omitempty"`
	DisableIPV6     bool      `yaml:"disable_ipv6"`
	DenyAction      string    `yaml:"deny_action"`
	DenyLog         bool      `yaml:"deny_log"`
	DenyLogPrefix   string    `yaml:"deny_log_prefix"`
	BlacklistsIpv4  string    `yaml:"blacklists_ipv4"`
	BlacklistsIpv6  string    `yaml:"blacklists_ipv6"`
	SetType         string    `yaml:"ipset_type"`

	// specific to iptables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/19
	IptablesChains          []string `yaml:"iptables_chains"`
	SupportedDecisionsTypes []string `yaml:"supported_decisions_types"`
	// specific to nftables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/74
	Nftables struct {
		Ipv4 nftablesFamilyConfig `yaml:"ipv4"`
		Ipv6 nftablesFamilyConfig `yaml:"ipv6"`
	} `yaml:"nftables"`
	PF struct {
		AnchorName string `yaml:"anchor_name"`
	} `yaml:"pf"`
	PrometheusConfig PrometheusConfig `yaml:"prometheus"`
}

func newConfig(configPath string) (*bouncerConfig, error) {
	config := &bouncerConfig{}

	configBuff, err := os.ReadFile(configPath)
	if err != nil {
		return &bouncerConfig{}, errors.Wrapf(err, "failed to read %s", configPath)
	}

	err = yaml.Unmarshal(configBuff, &config)
	if err != nil {
		return &bouncerConfig{}, errors.Wrapf(err, "failed to unmarshal %s", configPath)
	}

	err = validateConfig(*config)
	if err != nil {
		return &bouncerConfig{}, err
	}

	if len(config.SupportedDecisionsTypes) == 0 {
		config.SupportedDecisionsTypes = []string{"ban"}
	}

	if config.PidDir == "" {
		log.Warningf("missing 'pid_dir' directive in '%s', using default: '/var/run/'", configPath)

		config.PidDir = "/var/run/"
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
	default:
		log.Warningf("unexpected %s mode", config.Mode)
	}

	return config, nil
}

func pfConfig(config *bouncerConfig) error {
	return nil
}

func nftablesConfig(config *bouncerConfig) error {
	// deal with defaults in a backward compatible way
	if config.Nftables.Ipv4.Enabled == nil {
		config.Nftables.Ipv4.Enabled = types.BoolPtr(true)
	}

	if config.Nftables.Ipv6.Enabled == nil {
		if config.DisableIPV6 {
			config.Nftables.Ipv4.Enabled = types.BoolPtr(false)
		} else {
			config.Nftables.Ipv6.Enabled = types.BoolPtr(true)
		}
	}

	if *config.Nftables.Ipv4.Enabled {
		if config.Nftables.Ipv4.Table == "" {
			config.Nftables.Ipv4.Table = "crowdsec"
		}

		if config.Nftables.Ipv4.Chain == "" {
			config.Nftables.Ipv4.Chain = "crowdsec-chain"
		}
	}

	if *config.Nftables.Ipv6.Enabled {
		if config.Nftables.Ipv6.Table == "" {
			config.Nftables.Ipv6.Table = "crowdsec6"
		}

		if config.Nftables.Ipv6.Chain == "" {
			config.Nftables.Ipv6.Chain = "crowdsec6-chain"
		}
	}

	if !*config.Nftables.Ipv4.Enabled && !*config.Nftables.Ipv6.Enabled {
		return fmt.Errorf("both IPv4 and IPv6 disabled, doing nothing")
	}

	return nil
}

func configureLogging(config *bouncerConfig) {
	var LogOutput *lumberjack.Logger // io.Writer

	/* Configure logging */
	if err := types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel, config.LogMaxSize,
		config.LogMaxFiles, config.LogMaxAge, config.CompressLogs, false); err != nil {
		log.Fatal(err.Error())
	}

	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}

		_maxsize := 500

		if config.LogMaxSize != 0 {
			_maxsize = config.LogMaxSize
		}

		_maxfiles := 3

		if config.LogMaxFiles != 0 {
			_maxfiles = config.LogMaxFiles
		}

		_maxage := 30

		if config.LogMaxAge != 0 {
			_maxage = config.LogMaxAge
		}

		_compress := true

		if config.CompressLogs != nil {
			_compress = *config.CompressLogs
		}

		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-firewall-bouncer.log",
			MaxSize:    _maxsize, // megabytes
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,   // days
			Compress:   _compress, // disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}
}

func validateConfig(config bouncerConfig) error {
	if config.Mode == "" || config.LogMode == "" {
		return fmt.Errorf("config does not contain mode and log mode")
	}

	if config.LogMode != "stdout" && config.LogMode != "file" {
		return fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	return nil
}
