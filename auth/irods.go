package auth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/cyverse/sftpgo-auth-irods/types"
	"github.com/gliderlabs/ssh"

	irodsclient_conn "github.com/cyverse/go-irodsclient/irods/connection"
	irodsclient_fs "github.com/cyverse/go-irodsclient/irods/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	log "github.com/sirupsen/logrus"
)

const (
	homeDirPrefix         string        = "/srv/sftpgo/data"
	authorizedKeyFilename string        = "authorized_keys"
	applicationName       string        = "sftpgo-auth-irods"
	authRequestTimeout    time.Duration = 30 * time.Second
	iRODSFsProvider       int           = 6
)

func makeHomePath(config *types.Config) string {
	return path.Join(homeDirPrefix, config.SFTPGoAuthdUsername)
}

func makeCollectionPath(config *types.Config) string {
	return fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
}

func makeSSHPath(config *types.Config) string {
	homePath := makeCollectionPath(config)
	return path.Join(homePath, ".ssh")
}

func makeSSHAuthorizedKeysPath(config *types.Config) string {
	sshPath := makeSSHPath(config)
	return path.Join(sshPath, authorizedKeyFilename)
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
		HomeDir:     makeHomePath(config),
		Permissions: makePermissions(config),
		Filters:     makeFilters(config),
		FileSystem:  makeFileSystemForPasswordAuth(config),
	}, nil
}

// AuthViaPublicKey authenticate a user via public key
func AuthViaPublicKey(config *types.Config) (*types.SFTPGoUser, error) {
	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.SFTPGoAuthdPublickey))
	if err != nil {
		return nil, err
	}

	irodsAccount, err := irodsclient_types.CreateIRODSProxyAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, config.IRODSProxyUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.IRODSProxyPassword, "")
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

	sshPath := makeSSHPath(config)

	log.Debugf("Checking .ssh dir '%s'\n", sshPath)
	sshCollection, err := irodsclient_fs.GetCollection(irodsConn, sshPath)
	if err != nil {
		return nil, err
	}

	if sshCollection.ID <= 0 {
		// collection not exist
		return nil, err
	}

	sshAuthorizedKeysPath := makeSSHAuthorizedKeysPath(config)
	log.Debugf("Checking .ssh/authorized_keys file '%s'\n", sshAuthorizedKeysPath)
	sshAuthorizedKeysDataObject, err := irodsclient_fs.GetDataObjectMasterReplica(irodsConn, sshCollection, authorizedKeyFilename)
	if err != nil {
		return nil, err
	}

	if sshAuthorizedKeysDataObject.ID <= 0 {
		// authorized keys not exist
		return nil, err
	}

	fileHandle, _, err := irodsclient_fs.OpenDataObject(irodsConn, sshAuthorizedKeysPath, "", "r")
	if err != nil {
		return nil, err
	}

	defer irodsclient_fs.CloseDataObject(irodsConn, fileHandle)

	var authorizedKeysBuffer bytes.Buffer
	for {
		data, err := irodsclient_fs.ReadDataObject(irodsConn, fileHandle, 1024*64)
		if err != nil {
			return nil, err
		}

		if len(data) == 0 {
			// EOF
			break
		}

		authorizedKeysBuffer.Write(data)
	}

	authorizedKeysReader := bytes.NewReader(authorizedKeysBuffer.Bytes())
	authorizedKeysScanner := bufio.NewScanner(authorizedKeysReader)

	for authorizedKeysScanner.Scan() {
		authorizedKeyLine := strings.TrimSpace(authorizedKeysScanner.Text())
		if authorizedKeyLine == "" || authorizedKeyLine[0] == '#' {
			// skip
			continue
		}

		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
		if err != nil {
			// skip invalid public key
			continue
		}

		if bytes.Equal(authorizedKey.Marshal(), userKey.Marshal()) {
			// auth ok
			return &types.SFTPGoUser{
				Status:      1,
				Username:    irodsAccount.ClientUser,
				HomeDir:     makeHomePath(config),
				Permissions: makePermissions(config),
				Filters:     makeFilters(config),
				FileSystem:  makeFileSystemForPublicKeyAuth(config),
			}, nil
		}
	}

	return nil, errors.New("unable to find matching authorized public key")
}
