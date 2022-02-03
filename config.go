package main

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-playground/validator"
	log "github.com/sirupsen/logrus"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	Mode            string    `yaml:"mode" validate:"required"` //ipset,iptables,tc
	PidDir          string    `yaml:"pid_dir"`
	UpdateFrequency string    `yaml:"update_frequency"`
	Daemon          bool      `yaml:"daemonize"`
	LogMode         string    `yaml:"log_mode" validate:"required,oneof=stdout file"`
	LogDir          string    `yaml:"log_dir"`
	LogLevel        log.Level `yaml:"log_level"`
	APIUrl          string    `yaml:"api_url" validate:"required"`
	APIKey          string    `yaml:"api_key" validate:"required"`
	DisableIPV6     bool      `yaml:"disable_ipv6"`
	DenyAction      string    `yaml:"deny_action"`
	DenyLog         bool      `yaml:"deny_log"`
	DenyLogPrefix   string    `yaml:"deny_log_prefix"`
	BlacklistsIpv4  string    `yaml:"blacklists_ipv4"`
	BlacklistsIpv6  string    `yaml:"blacklists_ipv6"`
	//specific to iptables, following https://github.com/crowdsecurity/cs-firewall-bouncer/issues/19
	IptablesChains          []string `yaml:"iptables_chains"`
	supportedDecisionsTypes []string `yaml:"supported_decisions_type"`
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

	if config.BlacklistsIpv4 == "" {
		config.BlacklistsIpv4 = "crowdsec-blacklists"
	}

	if config.BlacklistsIpv6 == "" {
		config.BlacklistsIpv6 = "crowdsec6-blacklists"
	}
	return config, nil
}

func configureLogging(config *bouncerConfig) {
	var LogOutput *lumberjack.Logger //io.Writer

	if err := types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-firewall-bouncer.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}
}

func configStructLevelValidation(sl validator.StructLevel) {
	//	config := sl.Current().Interface().(bouncerConfig)
}

func validateConfig(config bouncerConfig) error {
	validate := validator.New()

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("yaml"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	validate.RegisterStructValidation(configStructLevelValidation, bouncerConfig{})
	err := validate.Struct(config)
	if err != nil {
		// log.Errorf("%s", err)
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				log.Errorf("'%s' is required.", err.Field())
			case "oneof":
				log.Errorf("'%s' must be one of: %s", err.Field(), err.Param())
			default:
				log.Errorf("'%s' is plain wrong", err.Field())
			}

			// log.Info("namespace: ", err.Namespace()) // can differ when a custom TagNameFunc is registered or
			// log.Info("field: ", err.Field())         // by passing alt name to ReportError like below
			// log.Info("structnamespace: ", err.StructNamespace())
			// log.Info("structfield: ", err.StructField())
			// log.Info("tag: ", err.Tag())
			// log.Info("actualtag: ", err.ActualTag())
			// log.Info("kind: ", err.Kind())
			// log.Info("type: ", err.Type())
			// log.Info("value: ", err.Value())
			// log.Info("param: ", err.Param())
		}
	}

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
	return nil
}
