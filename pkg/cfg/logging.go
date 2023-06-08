package cfg

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
)

type LoggingConfig struct {
	LogLevel     *log.Level `yaml:"log_level"`
	LogMode      string     `yaml:"log_mode"`
	LogDir       string     `yaml:"log_dir"`
	LogMaxSize   int        `yaml:"log_max_size,omitempty"`
	LogMaxFiles  int        `yaml:"log_max_files,omitempty"`
	LogMaxAge    int        `yaml:"log_max_age,omitempty"`
	CompressLogs *bool      `yaml:"compress_logs,omitempty"`
}

func (c *LoggingConfig) LoggerForFile(fileName string) (io.Writer, error) {
	if c.LogMode == "stdout" {
		return os.Stderr, nil
	}

	// default permissions will be 0600 from lumberjack
	// and are preserved if the file already exists

	l := &lumberjack.Logger{
		Filename:   filepath.Join(c.LogDir, fileName),
		MaxSize:    c.LogMaxSize,
		MaxBackups: c.LogMaxFiles,
		MaxAge:     c.LogMaxAge,
		Compress:   *c.CompressLogs,
	}

	return l, nil
}

func (c *LoggingConfig) setDefaults() {
	if c.LogMode == "" {
		c.LogMode = "stdout"
	}

	if c.LogDir == "" {
		c.LogDir = "/var/log/"
	}

	if c.LogLevel == nil {
		c.LogLevel = ptr.Of(log.InfoLevel)
	}

	if c.LogMaxSize == 0 {
		c.LogMaxSize = 500
	}

	if c.LogMaxFiles == 0 {
		c.LogMaxFiles = 3
	}

	if c.LogMaxAge == 0 {
		c.LogMaxAge = 30
	}

	if c.CompressLogs == nil {
		c.CompressLogs = ptr.Of(true)
	}
}

func (c *LoggingConfig) validate() error {
	if c.LogMode != "stdout" && c.LogMode != "file" {
		return fmt.Errorf("log_mode should be either 'stdout' or 'file'")
	}
	return nil
}

func (c *LoggingConfig) setup(fileName string) error {
	c.setDefaults()
	if err := c.validate(); err != nil {
		return err
	}
	log.SetLevel(*c.LogLevel)

	if c.LogMode == "stdout" {
		return nil
	}

	log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})

	logger, err := c.LoggerForFile(fileName)
	if err != nil {
		return err
	}

	log.SetOutput(logger)

	// keep stderr for panic/fatal, otherwise process failures
	// won't be visible enough
	log.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	return nil
}
