package auth

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/cyverse/sftpgo-auth-irods/types"
	"github.com/gliderlabs/ssh"

	irodsclient_conn "github.com/cyverse/go-irodsclient/irods/connection"
	irodsclient_fs "github.com/cyverse/go-irodsclient/irods/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	log "github.com/sirupsen/logrus"
)

const (
	authorizedKeyFilename string        = "authorized_keys"
	applicationName       string        = "sftpgo-auth-irods"
	authRequestTimeout    time.Duration = 30 * time.Second
)

func makeIRODSHomePath(config *types.Config) string {
	return fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
}

func makeSSHPath(config *types.Config) string {
	homePath := makeIRODSHomePath(config)
	return path.Join(homePath, ".ssh")
}

func makeSSHAuthorizedKeysPath(config *types.Config) string {
	sshPath := makeSSHPath(config)
	return path.Join(sshPath, authorizedKeyFilename)
}

// AuthViaPassword authenticate a user via password
func AuthViaPassword(config *types.Config) (bool, error) {
	irodsAccount, err := irodsclient_types.CreateIRODSAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.SFTPGoAuthdPassword, "")
	if err != nil {
		return false, err
	}

	irodsConn := irodsclient_conn.NewIRODSConnection(irodsAccount, authRequestTimeout, applicationName)
	err = irodsConn.Connect()
	if err != nil {
		// auth fail
		return false, err
	}

	defer irodsConn.Disconnect()
	return true, nil
}

// AuthViaPublicKey authenticate a user via public key
func AuthViaPublicKey(config *types.Config) (bool, []string, error) {
	log.Debugf("authenticating a user '%s'", config.SFTPGoAuthdUsername)

	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.SFTPGoAuthdPublickey))
	if err != nil {
		log.Debugf("failed to parse public-key for a user '%s'", config.SFTPGoAuthdUsername)
		return false, nil, err
	}

	// login using proxy (admin) account
	irodsAccount, err := irodsclient_types.CreateIRODSProxyAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, config.IRODSProxyUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.IRODSProxyPassword, "")
	if err != nil {
		log.Debugf("failed to create iRODS account for proxy auth")
		return false, nil, err
	}

	irodsConn := irodsclient_conn.NewIRODSConnection(irodsAccount, authRequestTimeout, applicationName)
	err = irodsConn.Connect()
	if err != nil {
		// auth fail
		log.Debugf("failed to login via iRODS proxy user account")
		return false, nil, err
	}

	defer irodsConn.Disconnect()

	authorizedKeys, err := readAuthorizedKeys(config, irodsConn)
	if err != nil {
		// auth fail
		return false, nil, err
	}

	loggedIn, options := checkAuthorizedKey(authorizedKeys, userKey)
	if loggedIn {
		log.Debugf("checking options - %v", options)
		// expiry
		if IsKeyExpired(options) {
			return false, options, fmt.Errorf("public key access for the user '%s' is expired", config.SFTPGoAuthdUsername)
		}

		// reject by client whilte-list
		if IsClientRejected(config.SFTPGoAuthdIP, options) {
			return false, options, fmt.Errorf("public key access for the user '%s' is rejected", config.SFTPGoAuthdUsername)
		}

		// auth success
		log.Debugf("authenticated a user '%s'", config.SFTPGoAuthdUsername)
		return true, options, nil
	}

	// auth fail
	log.Debugf("unable to authenticate the user '%s' using a public key", config.SFTPGoAuthdUsername)
	return false, nil, fmt.Errorf("unable to find matching authorized public key for the user '%s'", config.SFTPGoAuthdUsername)
}

// readAuthorizedKeys returns content of authorized_keys
func readAuthorizedKeys(config *types.Config, irodsConn *irodsclient_conn.IRODSConnection) ([]byte, error) {
	// check .ssh dir
	sshPath := makeSSHPath(config)

	log.Debugf("checking .ssh dir '%s'", sshPath)
	sshCollection, err := irodsclient_fs.GetCollection(irodsConn, sshPath)
	if err != nil {
		log.Debugf(".ssh dir not exist'%s'", sshPath)
		return nil, err
	}

	if sshCollection.ID <= 0 {
		// collection not exist
		log.Debugf(".ssh dir not exist'%s'", sshPath)
		return nil, err
	}

	// get .ssh/authorized_keys file
	sshAuthorizedKeysPath := makeSSHAuthorizedKeysPath(config)
	log.Debugf("checking .ssh/authorized_keys file '%s'", sshAuthorizedKeysPath)
	sshAuthorizedKeysDataObject, err := irodsclient_fs.GetDataObjectMasterReplica(irodsConn, sshCollection, authorizedKeyFilename)
	if err != nil {
		log.Debugf(".ssh/authorized_keys file not exist '%s'", sshAuthorizedKeysPath)
		return nil, err
	}

	if sshAuthorizedKeysDataObject.ID <= 0 {
		// authorized keys not exist
		log.Debugf(".ssh/authorized_keys file not exist '%s'", sshAuthorizedKeysPath)
		return nil, err
	}

	fileHandle, _, err := irodsclient_fs.OpenDataObject(irodsConn, sshAuthorizedKeysPath, "", "r")
	if err != nil {
		log.Debugf("failed to open .ssh/authorized_keys file '%s'", sshAuthorizedKeysPath)
		return nil, err
	}

	defer irodsclient_fs.CloseDataObject(irodsConn, fileHandle)

	var authorizedKeysBuffer bytes.Buffer
	readBuffer := make([]byte, 64*1024)
	for {
		readLen, err := irodsclient_fs.ReadDataObject(irodsConn, fileHandle, readBuffer)
		if err != nil && err != io.EOF {
			log.Debugf("failed to read .ssh/authorized_keys file '%s'", sshAuthorizedKeysPath)
			return nil, err
		}

		authorizedKeysBuffer.Write(readBuffer[:readLen])
		if err == io.EOF {
			break
		}
	}

	return authorizedKeysBuffer.Bytes(), nil
}
