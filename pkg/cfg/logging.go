package cfg

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"

	"gopkg.in/natefinch/lumberjack.v2"
)

func ConfigureLogging(config *BouncerConfig) error {
	var LogOutput *lumberjack.Logger // io.Writer

	if config.LogMode == "" {
		config.LogMode = "stdout"
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

		logPath, err := setLogFilePermissions(config.LogDir, "crowdsec-firewall-bouncer.log")
		if err != nil {
			return err
		}

		LogOutput = &lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    _maxsize, // megabytes
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,   // days
			Compress:   _compress, // disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})

		// keep stderr for panic/fatal, otherwise process failures
		// won't be visible enough
		log.AddHook(&writer.Hook{
			Writer: os.Stderr,
			LogLevels: []log.Level{
				log.PanicLevel,
				log.FatalLevel,
			},
		})
	}

	logLevel := log.InfoLevel
	if config.LogLevel != nil {
		logLevel = *config.LogLevel
	}

	log.SetLevel(logLevel)

	return nil
}
