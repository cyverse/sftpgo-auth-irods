package types

import (
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logFilename   = "sftpgo_auth_irods.log"
	logMaxSize    = 50 // 50MB
	logMaxAge     = 30 // 30 days
	logMaxBackups = 5
)

func SetLog(logDir string) {
	log.SetLevel(log.DebugLevel)
	logWriter := &lumberjack.Logger{
		Filename:   filepath.Join(logDir, logFilename),
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   false,
	}
	log.SetOutput(logWriter)
}
