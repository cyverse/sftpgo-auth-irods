package types

import (
	"errors"

	"github.com/kelseyhightower/envconfig"
)

const (
	defaultIRODSPort int = 1247
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

	// SFTP args
	SFTPGoAuthdUsername  string `envconfig:"SFTPGO_AUTHD_USERNAME"`
	SFTPGoAuthdPassword  string `envconfig:"SFTPGO_AUTHD_PASSWORD"`
	SFTPGoAuthdPublickey string `envconfig:"SFTPGO_AUTHD_PUBLIC_KEY"`
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
	return nil
}

func (config *Config) IsPublicKeyAuth() bool {
	if len(config.SFTPGoAuthdPublickey) > 0 {
		return true
	}
	return false
}
