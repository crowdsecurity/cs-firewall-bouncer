package main

import (
	"fmt"
	"io/ioutil"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type nftablesFamilyConfig struct {
	Enabled   bool   `yaml:"enabled"`
	SetOnly   bool   `yaml:"set-only"`
	Table     string `yaml:"table"`
	Chain     string `yaml:"chain"`
	Blacklist string `yaml:"blacklist"`
}

var IpsetMode = "ipset"
var NftablesMode = "nftables"

type bouncerConfig struct {
	Mode            string    `yaml:"mode"` //ipset,iptables,tc
	PidDir          string    `yaml:"pid_dir"`
	UpdateFrequency string    `yaml:"update_frequency"`
	Daemon          bool      `yaml:"daemonize"`
	LogMode         string    `yaml:"log_mode"`
	LogDir          string    `yaml:"log_dir"`
	LogLevel        log.Level `yaml:"log_level"`
	LogCompress     *bool     `yaml:"log_compression,omitempty"`
	LogMaxSize      *int      `yaml:"log_max_size,omitempty"`
	LogMaxBackups   *int      `yaml:"log_max_backups,omitempty"`
	LogMaxAge       *int      `yaml:"log_max_age,omitempty"`
	APIUrl          string    `yaml:"api_url"`
	APIKey          string    `yaml:"api_key"`
	DisableIPV6     bool      `yaml:"disable_ipv6"`
	DenyAction      string    `yaml:"deny_action"`
	DenyLog         bool      `yaml:"deny_log"`
	DenyLogPrefix   string    `yaml:"deny_log_prefix"`
	BlacklistsIpv4  string    `yaml:"blacklists_ipv4"`
	BlacklistsIpv6  string    `yaml:"blacklists_ipv6"`

	//specific to iptables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/19
	IptablesChains          []string `yaml:"iptables_chains"`
	supportedDecisionsTypes []string `yaml:"supported_decisions_type"`
	// specific to nftables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/74
	/*	NftablesTable4         string `yaml:"nftables_table4"`
		NftablesChain4         string `yaml:"nftables_chain4"`
		NftablesTable6         string `yaml:"nftables_table6"`
		NftablesChain6         string `yaml:"nftables_chain6"`
	*/
	Nftables struct {
		Ipv4 nftablesFamilyConfig `yaml:"ipv4"`
		Ipv6 nftablesFamilyConfig `yaml:"ipv6"`
	} `yaml:"nftables"`
}

func newConfig(configPath string) (*bouncerConfig, error) {
	config := &bouncerConfig{}

	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	err = yaml.Unmarshal(configBuff, &config)
	if err != nil {
		return &bouncerConfig{}, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}

	err = validateConfig(*config)
	if err != nil {
		return &bouncerConfig{}, err
	}

	if len(config.supportedDecisionsTypes) == 0 {
		config.supportedDecisionsTypes = []string{"ban"}
	}

	if config.PidDir == "" {
		log.Warningf("missing 'pid_dir' directive in '%s', using default: '/var/run/'", configPath)
		config.PidDir = "/var/run/"
	}
	if config.DenyLog && config.DenyLogPrefix == "" {
		config.DenyLogPrefix = "crowdsec drop: "
	}
	// for config file backward compatibility
	if config.BlacklistsIpv4 != "" {
		config.Nftables.Ipv4.Blacklist = config.BlacklistsIpv4
	}

	if config.BlacklistsIpv6 != "" {
		config.Nftables.Ipv6.Blacklist = config.BlacklistsIpv6
	}

	// nftables IPv4 specific
	if config.Nftables.Ipv4.Enabled {
		if config.Nftables.Ipv4.Table == "" {
			config.Nftables.Ipv4.Table = "crowdsec"
		}

		if config.Nftables.Ipv4.Chain == "" {
			config.Nftables.Ipv4.Chain = "crowdsec-chain"
		}

		if config.Nftables.Ipv4.Blacklist == "" {
			config.Nftables.Ipv4.Blacklist = "crowdsec-blacklist"
		}
	}
	// nftables IPv6 specific
	// What if config.DisableIPV6 (bool) has not been defined?
	if config.DisableIPV6 {
		config.Nftables.Ipv6.Enabled = false
	}
	// for config file compability
	config.DisableIPV6 = !config.Nftables.Ipv6.Enabled

	if config.Nftables.Ipv6.Enabled {
		if config.Nftables.Ipv6.Table == "" {
			config.Nftables.Ipv6.Table = "crowdsec6"
		}

		if config.Nftables.Ipv6.Chain == "" {
			config.Nftables.Ipv6.Chain = "crowdsec6-chain"
		}

		if config.Nftables.Ipv6.Blacklist == "" {
			config.Nftables.Ipv6.Blacklist = "crowdsec6-blacklist"
		}
	}
	return config, nil
}

func configureLogging(config *bouncerConfig) {
	var LogOutput *lumberjack.Logger //io.Writer

	/*Configure logging*/
	if err := types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		_maxsize := 500
		if config.LogMaxSize != nil {
			_maxsize = *config.LogMaxSize
		}
		_maxbackups := 3
		if config.LogMaxBackups != nil {
			_maxbackups = *config.LogMaxBackups
		}
		_maxage := 30
		if config.LogMaxAge != nil {
			_maxage = *config.LogMaxAge
		}
		_compress := true
		if config.LogCompress != nil {
			_compress = *config.LogCompress
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-firewall-bouncer.log",
			MaxSize:    _maxsize, //megabytes
			MaxBackups: _maxbackups,
			MaxAge:     _maxage,   //days
			Compress:   _compress, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}
}

func validateConfig(config bouncerConfig) error {
	if config.APIUrl == "" {
		return fmt.Errorf("config does not contain LAPI url")
	}
	if config.APIKey == "" {
		return fmt.Errorf("config does not contain LAPI key")
	}

	if config.Mode == "" || config.LogMode == "" {
		return fmt.Errorf("config does not contain mode and log mode")
	}

	if config.LogMode != "stdout" && config.LogMode != "file" {
		return fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}
	if config.Mode == NftablesMode {
		if !config.Nftables.Ipv4.Enabled && !config.Nftables.Ipv6.Enabled {
			return fmt.Errorf("Both IPv4 and IPv6 disabled, doing nothing")
		}
	}
	return nil
}
