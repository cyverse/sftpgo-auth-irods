package types

import (
	"encoding/json"

	"github.com/sftpgo/sdk"
)

const (
	plainSecretStatus = "Plain"
)

// SFTPGoUser is a user filter data type for SFTPGo
type SFTPGoUserFilter struct {
	AllowedIP             []string `json:"allowed_ip,omitempty"`
	DeniedLoginMethods    []string `json:"denied_login_methods,omitempty"`
	ExternalAuthCacheTime int64    `json:"external_auth_cache_time,omitempty"`
}

// SFTPGoSecret is a secret data type for SFTPGo
type SFTPGoSecret struct {
	Status         string `json:"status,omitempty"`
	Payload        string `json:"payload,omitempty"`
	Key            string `json:"key,omitempty"`
	AdditionalData string `json:"additional_data,omitempty"`
	// 1 means encrypted using a master key
	Mode int `json:"mode,omitempty"`
}

// SFTPGoIRODSFsConfig is a filesystem data type for SFTPGo
type SFTPGoIRODSFsConfig struct {
	Endpoint                       string        `json:"endpoint"`
	Username                       string        `json:"username"`
	ProxyUsername                  string        `json:"proxy_username,omitempty"`
	Password                       *SFTPGoSecret `json:"password"`
	CollectionPath                 string        `json:"collection_path"`
	Resource                       string        `json:"resource,omitempty"`
	AuthScheme                     string        `json:"auth_scheme,omitempty"`
	RequireClientServerNegotiation bool          `json:"require_cs_negotiation,omitempty"`
	ClientServerNegotiationPolicy  string        `json:"cs_negotiation_policy,omitempty"`
	SSLCACertificatePath           string        `json:"ssl_ca_cert_path,omitempty"`
	SSLKeySize                     int           `json:"ssl_key_size,omitempty"`
	SSLAlgorithm                   string        `json:"ssl_algorithm,omitempty"`
	SSLSaltSize                    int           `json:"ssl_salt_size,omitempty"`
	SSLHashRounds                  int           `json:"ssl_hash_rounds,omitempty"`
	PoolEndpoint                   string        `json:"pool_endpoint,omitempty"`
}

// GetRedacted returns a redacted SFTPGoIRODSFsConfig, or nil for a nil config
func (config *SFTPGoIRODSFsConfig) GetRedacted() *SFTPGoIRODSFsConfig {
	if config == nil {
		return nil
	}

	newConfig := *config
	if newConfig.Password != nil && len(newConfig.Password.Payload) > 0 {
		newConfig.Password = &SFTPGoSecret{
			Status:         plainSecretStatus,
			Payload:        "<redacted>",
			Key:            "",
			AdditionalData: "",
			Mode:           0,
		}
	}
	return &newConfig
}

// SFTPGoFileSystem is a filesystem data type for SFTPGo
type SFTPGoFileSystem struct {
	Provider    sdk.FilesystemProvider `json:"provider"`
	IRODSConfig *SFTPGoIRODSFsConfig   `json:"irodsconfig"`
}

// GetRedacted returns a redacted SFTPGoFileSystem, or nil for a nil filesystem
func (fs *SFTPGoFileSystem) GetRedacted() *SFTPGoFileSystem {
	if fs == nil {
		return nil
	}

	newFs := *fs
	newFs.IRODSConfig = newFs.IRODSConfig.GetRedacted()
	return &newFs
}

// SFTPGoVirtualFolder is a virtual folder data type for SFTPGo
type SFTPGoVirtualFolder struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	MappedPath  string            `json:"mapped_path"`
	VirtualPath string            `json:"virtual_path"`
	FileSystem  *SFTPGoFileSystem `json:"filesystem"`
}

// SFTPGoFolder is a folder data type for SFTPGo
type SFTPGoFolder struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	FileSystem  *SFTPGoFileSystem `json:"filesystem,omitempty"`
}

// SFTPGoUser is a user data type for SFTPGo
type SFTPGoUser struct {
	Status         int                   `json:"status,omitempty"`
	Username       string                `json:"username"`
	HomeDir        string                `json:"home_dir,omitempty"`
	VirtualFolders []SFTPGoVirtualFolder `json:"virtual_folders,omitempty"`
	Permissions    map[string][]string   `json:"permissions"`
	Filters        *SFTPGoUserFilter     `json:"filters"`
	FileSystem     *SFTPGoFileSystem     `json:"filesystem"`
}

// GetRedacted returns a redacted SFTPGoUser, or nil for a nil user. The
// original is left untouched, because the caller logs the redacted copy and
// still sends the original to SFTPGo.
func (user *SFTPGoUser) GetRedacted() *SFTPGoUser {
	if user == nil {
		return nil
	}

	newUser := *user

	if len(newUser.VirtualFolders) > 0 {
		newVFolders := []SFTPGoVirtualFolder{}
		for _, vfolder := range newUser.VirtualFolders {
			vfolder.FileSystem = vfolder.FileSystem.GetRedacted()
			newVFolders = append(newVFolders, vfolder)
		}
		newUser.VirtualFolders = newVFolders
	}

	newUser.FileSystem = newUser.FileSystem.GetRedacted()
	return &newUser
}

// GetRedactedJSONString returns a JSON string after redacting sensitive info.
func (user *SFTPGoUser) GetRedactedJSONString() string {
	redactedUser := user.GetRedacted()
	resp, _ := json.MarshalIndent(redactedUser, "", "  ")
	return string(resp)
}

// NewSFTPGoUserForError returns a new SFTPGoUser for auth failure
func NewSFTPGoUserForError() *SFTPGoUser {
	return &SFTPGoUser{
		Username: "",
	}
}

// NewSFTPGoSecretForUserPassword returns a new SFTPGoSecret for storing user password
func NewSFTPGoSecretForUserPassword(password string) *SFTPGoSecret {
	return &SFTPGoSecret{
		Status:         plainSecretStatus,
		Payload:        password,
		Key:            "",
		AdditionalData: "",
		Mode:           0,
	}
}
