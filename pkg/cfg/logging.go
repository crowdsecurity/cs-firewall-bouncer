package cfg

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"gopkg.in/natefinch/lumberjack.v2"
)

type LoggingConfig struct {
	LogMode      string     `yaml:"log_mode"`
	LogDir       string     `yaml:"log_dir"`
	LogLevel     *log.Level `yaml:"log_level"`
	CompressLogs *bool      `yaml:"compress_logs,omitempty"`
	LogMaxSize   int        `yaml:"log_max_size,omitempty"`
	LogMaxFiles  int        `yaml:"log_max_files,omitempty"`
	LogMaxAge    int        `yaml:"log_max_age,omitempty"`
}

func (c *LoggingConfig) setup(fileName string) error {
	logLevel := log.InfoLevel
	if c.LogLevel != nil {
		logLevel = *c.LogLevel
	}

	log.SetLevel(logLevel)

	switch c.LogMode {
	case "":
		c.LogMode = "stdout"
	case "stdout", "file":
	default:
		return fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", c.LogMode)
	}

	if c.LogMode == "stdout" {
		return nil
	}

	log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})

	if c.LogDir == "" {
		c.LogDir = "/var/log/"
	}

	_maxsize := 500
	if c.LogMaxSize != 0 {
		_maxsize = c.LogMaxSize
	}

	_maxfiles := 3
	if c.LogMaxFiles != 0 {
		_maxfiles = c.LogMaxFiles
	}

	_maxage := 30
	if c.LogMaxAge != 0 {
		_maxage = c.LogMaxAge
	}

	_compress := true
	if c.CompressLogs != nil {
		_compress = *c.CompressLogs
	}

	logPath, err := setLogFilePermissions(c.LogDir, fileName)
	if err != nil {
		return err
	}

	log.SetOutput(&lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    _maxsize, // megabytes
		MaxBackups: _maxfiles,
		MaxAge:     _maxage,   // days
		Compress:   _compress, // disabled by default
	})

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
