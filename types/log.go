package types

import (
	"log"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logPath       = "/tmp/sftpgo_auth_irods/irods.log"
	logMaxSize    = 10 // 10MB
	logMaxAge     = 30 // 30 days
	logMaxBackups = 1
)

func SetLog() {
	logWriter := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   false,
	}
	log.SetOutput(logWriter)
}
