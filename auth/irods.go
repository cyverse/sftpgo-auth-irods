package auth

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
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
	log.Debugf("authenticating a user '%s'\n", config.SFTPGoAuthdUsername)

	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.SFTPGoAuthdPublickey))
	if err != nil {
		log.Debugf("failed to parse public-key for a user '%s'\n", config.SFTPGoAuthdUsername)
		return nil, err
	}

	irodsAccount, err := irodsclient_types.CreateIRODSProxyAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, config.IRODSProxyUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.IRODSProxyPassword, "")
	if err != nil {
		log.Debugf("failed to create iRODS account for proxy auth\n")
		return nil, err
	}

	irodsConn := irodsclient_conn.NewIRODSConnection(irodsAccount, authRequestTimeout, applicationName)
	err = irodsConn.Connect()
	if err != nil {
		// auth fail
		log.Debugf("failed to login via iRODS proxy user account\n")
		return nil, err
	}

	defer irodsConn.Disconnect()

	sshPath := makeSSHPath(config)

	log.Debugf("checking .ssh dir '%s'\n", sshPath)
	sshCollection, err := irodsclient_fs.GetCollection(irodsConn, sshPath)
	if err != nil {
		log.Debugf(".ssh dir not exist'%s'\n", sshPath)
		return nil, err
	}

	if sshCollection.ID <= 0 {
		// collection not exist
		log.Debugf(".ssh dir not exist'%s'\n", sshPath)
		return nil, err
	}

	sshAuthorizedKeysPath := makeSSHAuthorizedKeysPath(config)
	log.Debugf("checking .ssh/authorized_keys file '%s'\n", sshAuthorizedKeysPath)
	sshAuthorizedKeysDataObject, err := irodsclient_fs.GetDataObjectMasterReplica(irodsConn, sshCollection, authorizedKeyFilename)
	if err != nil {
		log.Debugf(".ssh/authorized_keys file not exist '%s'\n", sshAuthorizedKeysPath)
		return nil, err
	}

	if sshAuthorizedKeysDataObject.ID <= 0 {
		// authorized keys not exist
		log.Debugf(".ssh/authorized_keys file not exist '%s'\n", sshAuthorizedKeysPath)
		return nil, err
	}

	fileHandle, _, err := irodsclient_fs.OpenDataObject(irodsConn, sshAuthorizedKeysPath, "", "r")
	if err != nil {
		log.Debugf("failed to open .ssh/authorized_keys file '%s'\n", sshAuthorizedKeysPath)
		return nil, err
	}

	defer irodsclient_fs.CloseDataObject(irodsConn, fileHandle)

	var authorizedKeysBuffer bytes.Buffer
	readBuffer := make([]byte, 64*1024)
	for {
		readLen, err := irodsclient_fs.ReadDataObject(irodsConn, fileHandle, readBuffer)
		if err != nil && err != io.EOF {
			log.Debugf("failed to read .ssh/authorized_keys file '%s'\n", sshAuthorizedKeysPath)
			return nil, err
		}

		authorizedKeysBuffer.Write(readBuffer[:readLen])
		if err == io.EOF {
			break
		}
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
			log.Debugf("authenticated a user '%s'\n", config.SFTPGoAuthdUsername)
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

	log.Debugf("unable to find matching authorized public key for a user '%s'\n")

	return nil, errors.New("unable to find matching authorized public key")
}
