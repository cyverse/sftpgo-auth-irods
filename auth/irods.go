package auth

import (
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/cyverse/sftpgo-auth-irods/types"

	irodsclient_conn "github.com/cyverse/go-irodsclient/irods/connection"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
)

const (
	homeDirPrefix                    = "/srv/sftpgo/data"
	applicationName                  = "sftpgo-auth-irods"
	authRequestTimeout time.Duration = 30 * time.Second
	iRODSFsProvider                  = 6
)

func makeHomedir(config *types.Config) string {
	return path.Join(homeDirPrefix, config.SFTPGoAuthdUsername)
}

func makeCollectionPath(config *types.Config) string {
	return fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
}

func makePermissions(config *types.Config) map[string][]string {
	permissions := make(map[string][]string)
	permissions["/"] = []string{"*"}
	return permissions
}

func makeFilters(config *types.Config) *types.SFTPGoUserFilter {
	return &types.SFTPGoUserFilter{
		AllowedIP:          []string{},
		DeniedLoginMethods: []string{},
	}
}

func makeIRODSFsConfigForPasswordAuth(config *types.Config) *types.SFTPGoIRODSFsConfig {
	return &types.SFTPGoIRODSFsConfig{
		Endpoint:       fmt.Sprintf("%s:%d", config.IRODSHost, config.IRODSPort),
		Username:       config.SFTPGoAuthdUsername,
		ProxyUsername:  "",
		Password:       types.NewSFTPGoSecretForUserPassword(config.SFTPGoAuthdPassword),
		CollectionPath: makeCollectionPath(config),
		Resource:       "",
	}
}

func makeIRODSFsConfigForPublicKeyAuth(config *types.Config) *types.SFTPGoIRODSFsConfig {
	return &types.SFTPGoIRODSFsConfig{
		Endpoint:       fmt.Sprintf("%s:%d", config.IRODSHost, config.IRODSPort),
		Username:       config.SFTPGoAuthdUsername,
		ProxyUsername:  config.IRODSProxyUsername,
		Password:       types.NewSFTPGoSecretForUserPassword(config.IRODSProxyPassword),
		CollectionPath: makeCollectionPath(config),
		Resource:       "",
	}
}

func makeFileSystemForPasswordAuth(config *types.Config) *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider:    iRODSFsProvider,
		IRODSConfig: makeIRODSFsConfigForPasswordAuth(config),
	}
}

func makeFileSystemForPublicKeyAuth(config *types.Config) *types.SFTPGoFileSystem {
	return &types.SFTPGoFileSystem{
		Provider:    iRODSFsProvider,
		IRODSConfig: makeIRODSFsConfigForPublicKeyAuth(config),
	}
}

// AuthViaPassword authenticate a user via password
func AuthViaPassword(config *types.Config) (*types.SFTPGoUser, error) {
	irodsAccount, err := irodsclient_types.CreateIRODSAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.SFTPGoAuthdPassword, "")
	if err != nil {
		return nil, err
	}

	irodsConn := irodsclient_conn.NewIRODSConnection(irodsAccount, authRequestTimeout, applicationName)
	err = irodsConn.Connect()
	if err != nil {
		// auth fail
		return nil, err
	}

	defer irodsConn.Disconnect()

	return &types.SFTPGoUser{
		Status:      1,
		Username:    irodsAccount.ClientUser,
		HomeDir:     makeHomedir(config),
		Permissions: makePermissions(config),
		Filters:     makeFilters(config),
		FileSystem:  makeFileSystemForPasswordAuth(config),
	}, nil
}

// AuthViaPublicKey authenticate a user via public key
func AuthViaPublicKey(envConfig *types.Config) (*types.SFTPGoUser, error) {
	/*
		// check public key
		u := SFTPGoUser{
			Username: username,
			HomeDir:  homeDir,
			UID:      0,
			GID:      0,
			Status:   1,
		}
		u.Permissions = make(map[string][]string)
		u.Permissions["/"] = []string{"*"}
		// uncomment the next line to require publickey+password authentication
		//u.Filters.DeniedLoginMethods = []string{"publickey", "password", "keyboard-interactive", "publickey+keyboard-interactive"}

		userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publickey))
		if err != nil {
			log.Printf("ParseAuthorizedKey(%s): %s\n", publickey, err.Error())
			exitError()
		}
		authOk := false
		for _, k := range sr.Entries[0].GetAttributeValues("nsSshPublicKey") {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
			// we skip an invalid public key stored inside the LDAP server
			if err != nil {
				continue
			}
			if bytes.Equal(key.Marshal(), userKey.Marshal()) {
				authOk = true
				break
			}
		}
		if !authOk {
			log.Printf("publickey %s !authOk\n", publickey)
			exitError()
		}
	*/
	return nil, errors.New("Not Implemented")
}
