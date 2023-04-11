package commons

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

const (
	defaultIRODSPort int    = 1247
	defaultLogDir    string = "/tmp"
	defaultHomeDir   string = "/srv/sftpgo/data"
)

// Config is a configuration struct
type Config struct {
	// for public key auth
	IRODSProxyUsername string `envconfig:"IRODS_PROXY_USER"`
	IRODSProxyPassword string `envconfig:"IRODS_PROXY_PASSWORD"`

	// for iRODS Auth
	IRODSHost string `envconfig:"IRODS_HOST"`
	IRODSPort int    `envconfig:"IRODS_PORT"`
	IRODSZone string `envconfig:"IRODS_ZONE"`

	// for fs mount
	IRODSShared   string `envconfig:"IRODS_SHARED"`
	SFTPGoHomeDir string `envconfig:"SFTPGO_HOME_PATH"`

	// SFTP args
	SFTPGoAuthdUsername  string `envconfig:"SFTPGO_AUTHD_USERNAME"`
	SFTPGoAuthdPassword  string `envconfig:"SFTPGO_AUTHD_PASSWORD"`
	SFTPGoAuthdPublickey string `envconfig:"SFTPGO_AUTHD_PUBLIC_KEY"`
	SFTPGoAuthdIP        string `envconfig:"SFTPGO_AUTHD_IP"`

	// for Logging
	SFTPGoLogDir string `envconfig:"SFTPGO_LOG_DIR"`
}

func GetDefaultLogPath() string {
	return defaultLogDir
}

func ReadFromEnv() (*Config, error) {
	var config Config
	err := envconfig.Process("", &config)
	if err != nil {
		return nil, err
	}

	if config.IRODSPort == 0 {
		config.IRODSPort = defaultIRODSPort
	}

	if len(config.SFTPGoLogDir) == 0 {
		config.SFTPGoLogDir = defaultLogDir
	}

	if len(config.SFTPGoHomeDir) == 0 {
		config.SFTPGoHomeDir = defaultHomeDir
	}

	return &config, nil
}

// Validate validates field values and returns error if occurs
func (config *Config) Validate() error {
	if len(config.IRODSHost) == 0 {
		return errors.New("iRODS host is not given")
	}
	if config.IRODSPort <= 0 {
		return errors.New("iRODS port must not be negative")
	}
	if len(config.IRODSZone) == 0 {
		return errors.New("iRODS zone is not given")
	}

	if len(config.SFTPGoAuthdUsername) == 0 {
		return errors.New("user name is not given")
	}
	if len(config.SFTPGoAuthdPublickey) == 0 && len(config.SFTPGoAuthdPassword) == 0 {
		return errors.New("at least any of password or public key must be given")
	}
	if len(config.SFTPGoAuthdIP) == 0 {
		return errors.New("ip address is not given")
	}
	if len(config.SFTPGoLogDir) == 0 {
		return errors.New("log dir is not given")
	}
	if len(config.SFTPGoHomeDir) == 0 {
		return errors.New("home dir is not given")
	}
	return nil
}

// ValidateForPublicKeyAuth validates field values and returns error if occurs
func (config *Config) ValidateForPublicKeyAuth() error {
	if len(config.IRODSProxyUsername) == 0 {
		return errors.New("iRODS proxy username is not given")
	}
	if len(config.IRODSProxyPassword) == 0 {
		return errors.New("iRODS proxy password is not given")
	}

	return nil
}

// IsPublicKeyAuth checks if the auth mode is public key auth
func (config *Config) IsPublicKeyAuth() bool {
	if config.IsAnonymousUser() {
		return false
	}

	return len(config.SFTPGoAuthdPublickey) > 0
}

// IsAnonymousUser checks if the user is anonymous
func (config *Config) IsAnonymousUser() bool {
	return strings.ToLower(config.SFTPGoAuthdUsername) == "anonymous"
}

// HasSharedDir checks if shared dir is provided
func (config *Config) HasSharedDir() bool {
	return len(config.IRODSShared) > 0
}

// GetSharedDirName returns shared dir's name
func (config *Config) GetHomeDirPath() string {
	if config.IsAnonymousUser() {
		return ""
	}

	return fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
}

// GetSharedDirName returns shared dir's name
func (config *Config) GetSharedDirName() string {
	return filepath.Base(config.IRODSShared)
}
