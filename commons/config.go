package commons

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/kelseyhightower/envconfig"
)

const (
	defaultIRODSPort       int    = 1247
	defaultIRODSAuthScheme string = "native"
	defaultLogDir          string = "/tmp"
	defaultHomeDir         string = "/srv/sftpgo/data"
	defaultAuthCacheTime   int64  = 300

	// client-server negotiation policies accepted by go-irodsclient
	csNegotiationPolicyRefuse   string = "CS_NEG_REFUSE"
	csNegotiationPolicyRequire  string = "CS_NEG_REQUIRE"
	csNegotiationPolicyDontCare string = "CS_NEG_DONT_CARE"

	// server certificate verification modes accepted by go-irodsclient.
	// Note that go-irodsclient only verifies the server for 'hostname';
	// 'cert' behaves like 'none'.
	SSLVerifyServerNone     string = "none"
	SSLVerifyServerCert     string = "cert"
	SSLVerifyServerHostname string = "hostname"
)

// Config is a configuration struct
type Config struct {
	// for public key auth
	IRODSProxyUsername string `envconfig:"IRODS_PROXY_USER"`
	IRODSProxyPassword string `envconfig:"IRODS_PROXY_PASSWORD"`

	// for iRODS auth
	IRODSHost string `envconfig:"IRODS_HOST"`
	IRODSPort int    `envconfig:"IRODS_PORT"`
	IRODSZone string `envconfig:"IRODS_ZONE"`
	// IRODSAuthScheme should be one of ['native','pam','pam_for_users']
	IRODSAuthScheme           string `envconfig:"IRODS_AUTH_SCHEME"`
	IRODSRequireCSNegotiation bool   `envconfig:"IRODS_REQUIRE_CS_NEGOTIATION"`
	// IRODSCSNegotiationPolicy should be one of ['CS_NEG_REFUSE','CS_NEG_REQUIRE','CS_NEG_DONT_CARE']
	IRODSCSNegotiationPolicy string `envconfig:"IRODS_CS_NEGOTIATION_POLICY"`

	// for irodsfs-pool
	// IRODSPoolEndpoint is an optional irodsfs-pool service endpoint, e.g. "tcp://host:port", "unix:///path/to/socket" or "host:port"
	IRODSPoolEndpoint string `envconfig:"IRODS_POOL_ENDPOINT"`

	// for SSL/PAM auth
	IRODSSSLCACertificatePath string `envconfig:"IRODS_SSL_CA_CERT_PATH"`
	IRODSSSLAlgorithm         string `envconfig:"IRODS_SSL_ALGORITHM"`
	IRODSSSLKeySize           int    `envconfig:"IRODS_SSL_KEY_SIZE"`
	IRODSSSLSaltSize          int    `envconfig:"IRODS_SSL_SALT_SIZE"`
	IRODSSSLHashRounds        int    `envconfig:"IRODS_SSL_HASH_ROUNDS"`
	// IRODSSSLVerifyServer should be one of ['none','cert','hostname'].
	// Defaults to 'none', which does not verify the iRODS server certificate.
	IRODSSSLVerifyServer string `envconfig:"IRODS_SSL_VERIFY_SERVER"`

	// for fs mount
	IRODSShared   string `envconfig:"IRODS_SHARED"`
	SFTPGoHomeDir string `envconfig:"SFTPGO_HOME_PATH"`

	// SFTP args
	SFTPGoAuthdUsername  string `envconfig:"SFTPGO_AUTHD_USERNAME"`
	SFTPGoAuthdPassword  string `envconfig:"SFTPGO_AUTHD_PASSWORD"`
	SFTPGoAuthdPublickey string `envconfig:"SFTPGO_AUTHD_PUBLIC_KEY"`
	SFTPGoAuthdIP        string `envconfig:"SFTPGO_AUTHD_IP"`

	// SFTPGoAuthCacheTime is how long, in seconds, SFTPGo may reuse the result
	// of a successful authentication before calling this hook again. 0 falls
	// back to defaultAuthCacheTime. A revoked password or public key keeps
	// working for up to this long, so the default is deliberately short.
	SFTPGoAuthCacheTime int64 `envconfig:"SFTPGO_AUTH_CACHE_TIME"`

	// for Logging
	SFTPGoLogDir string `envconfig:"SFTPGO_LOG_DIR"`

	// for SFTPGo REST API (folder management)
	SFTPGoAPIBaseURL string `envconfig:"SFTPGO_API_BASE_URL"`
	SFTPGoAPIKey     string `envconfig:"SFTPGO_API_KEY"`
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

	if len(config.IRODSAuthScheme) == 0 {
		config.IRODSAuthScheme = defaultIRODSAuthScheme
	}

	if config.SFTPGoAuthCacheTime == 0 {
		config.SFTPGoAuthCacheTime = defaultAuthCacheTime
	}

	// normalize so that every comparison against the policy agrees
	config.IRODSCSNegotiationPolicy = strings.ToUpper(strings.TrimSpace(config.IRODSCSNegotiationPolicy))
	if len(config.IRODSCSNegotiationPolicy) == 0 {
		config.IRODSCSNegotiationPolicy = csNegotiationPolicyDontCare
	}

	config.IRODSSSLVerifyServer = strings.ToLower(strings.TrimSpace(config.IRODSSSLVerifyServer))
	if len(config.IRODSSSLVerifyServer) == 0 {
		config.IRODSSSLVerifyServer = SSLVerifyServerNone
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
	if len(config.IRODSAuthScheme) == 0 {
		return errors.New("iRODS auth scheme is not given")
	}
	if len(config.IRODSSSLVerifyServer) > 0 {
		switch strings.ToLower(config.IRODSSSLVerifyServer) {
		case SSLVerifyServerNone, SSLVerifyServerCert, SSLVerifyServerHostname:
		default:
			return errors.Errorf("iRODS SSL verify server %q must be one of %s, %s or %s",
				config.IRODSSSLVerifyServer, SSLVerifyServerNone, SSLVerifyServerCert, SSLVerifyServerHostname)
		}
	}
	if config.IRODSRequireCSNegotiation {
		if len(config.IRODSCSNegotiationPolicy) == 0 {
			return errors.New("iRODS client-server negotiation policy is not given")
		}

		// an unrecognized policy silently falls back to a plain TCP connection,
		// so reject it instead of letting it downgrade the connection
		switch strings.ToUpper(config.IRODSCSNegotiationPolicy) {
		case csNegotiationPolicyRefuse, csNegotiationPolicyRequire, csNegotiationPolicyDontCare:
		default:
			return errors.Errorf("iRODS client-server negotiation policy %q must be one of %s, %s or %s",
				config.IRODSCSNegotiationPolicy, csNegotiationPolicyRefuse, csNegotiationPolicyRequire, csNegotiationPolicyDontCare)
		}

		if strings.ToUpper(config.IRODSCSNegotiationPolicy) == csNegotiationPolicyRequire {
			// SSL
			if len(config.IRODSSSLCACertificatePath) == 0 {
				return errors.New("iRODS SSL CA certificate path is not given")
			}
			if len(config.IRODSSSLAlgorithm) == 0 {
				return errors.New("iRODS SSL encryption algorithm is not given")
			}
			if config.IRODSSSLKeySize <= 0 {
				return errors.New("iRODS SSL encryption key size is not given")
			}
			if config.IRODSSSLSaltSize <= 0 {
				return errors.New("iRODS SSL encryption salt size is not given")
			}
			if config.IRODSSSLHashRounds <= 0 {
				return errors.New("iRODS SSL encryption hash rounds is not given")
			}
		}
	}
	if strings.ToLower(config.IRODSAuthScheme) == "pam" || strings.ToLower(config.IRODSAuthScheme) == "pam_for_users" {
		if !config.IRODSRequireCSNegotiation {
			return errors.New("iRODS client-server negotiation is not given for PAM authentication")
		}
		if len(config.IRODSCSNegotiationPolicy) == 0 {
			return errors.New("iRODS client-server negotiation policy is not given for PAM authentication")
		}

		if len(config.IRODSSSLCACertificatePath) == 0 {
			return errors.New("iRODS SSL CA certificate path is not given")
		}
		if len(config.IRODSSSLAlgorithm) == 0 {
			return errors.New("iRODS SSL encryption algorithm is not given")
		}
		if config.IRODSSSLKeySize <= 0 {
			return errors.New("iRODS SSL encryption key size is not given")
		}
		if config.IRODSSSLSaltSize <= 0 {
			return errors.New("iRODS SSL encryption salt size is not given")
		}
		if config.IRODSSSLHashRounds <= 0 {
			return errors.New("iRODS SSL encryption hash rounds is not given")
		}
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
	if config.SFTPGoAuthCacheTime < 0 {
		return errors.New("auth cache time must not be negative")
	}
	if len(config.SFTPGoLogDir) == 0 {
		return errors.New("log dir is not given")
	}
	if len(config.SFTPGoHomeDir) == 0 {
		return errors.New("home dir is not given")
	}
	if (len(config.SFTPGoAPIBaseURL) == 0) != (len(config.SFTPGoAPIKey) == 0) {
		return errors.New("both SFTPGO_API_BASE_URL and SFTPGO_API_KEY must be set together")
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

// IsProxyAuth checks if it uses proxy auth
func (config *Config) IsProxyAuth() bool {
	return len(config.IRODSProxyUsername) > 0
}

// HasSharedDir checks if shared dir is provided
func (config *Config) HasSharedDir() bool {
	return len(config.IRODSShared) > 0
}

// HasSFTPGoAPI checks if SFTPGo REST API is configured
func (config *Config) HasSFTPGoAPI() bool {
	return len(config.SFTPGoAPIBaseURL) > 0 && len(config.SFTPGoAPIKey) > 0
}

// GetHomeDirPath returns the user's iRODS home collection path, or an empty
// string for the anonymous user, who has no home collection. This is the only
// place the home path is spelled out, because the public key flow compares the
// path it derives from a home= option against this one.
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
