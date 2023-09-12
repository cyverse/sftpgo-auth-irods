package auth

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/cyverse/sftpgo-auth-irods/commons"
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

func makeIRODSHomePath(config *commons.Config) string {
	return fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
}

func makeSSHPath(config *commons.Config) string {
	homePath := makeIRODSHomePath(config)
	return path.Join(homePath, ".ssh")
}

func makeSSHAuthorizedKeysPath(config *commons.Config) string {
	sshPath := makeSSHPath(config)
	return path.Join(sshPath, authorizedKeyFilename)
}

func makeIRODSAccount(config *commons.Config) (*irodsclient_types.IRODSAccount, error) {
	var irodsAccount *irodsclient_types.IRODSAccount
	var err error

	switch strings.ToLower(config.IRODSAuthScheme) {
	case "", "native":
		irodsAccount, err = irodsclient_types.CreateIRODSAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.SFTPGoAuthdPassword, "")
		if err != nil {
			log.Debugf("failed to create iRODS account for auth")
			return nil, err
		}
	case "pam", "pam_for_users":
		// pam_for_users auth mode uses PAM auth for testing user password

		irodsAccount, err = irodsclient_types.CreateIRODSAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, irodsclient_types.AuthSchemePAM, config.SFTPGoAuthdPassword, "")
		if err != nil {
			log.Debugf("failed to create iRODS account for auth")
			return nil, err
		}

		sslConf, err := irodsclient_types.CreateIRODSSSLConfig(config.IRODSSSLCACertificatePath, config.IRODSSSLKeySize, config.IRODSSSLAlgorithm, config.IRODSSSLSaltSize, config.IRODSSSLHashRounds)
		if err != nil {
			log.Debugf("failed to create iRODS SSL config for auth")
			return nil, err
		}

		irodsAccount.SetSSLConfiguration(sslConf)
	default:
		log.Debugf("unknown authentication scheme %s", config.IRODSAuthScheme)
		return nil, fmt.Errorf("unknown authentication scheme %s", config.IRODSAuthScheme)
	}

	return irodsAccount, nil
}

func makeIRODSAccountForProxy(config *commons.Config) (*irodsclient_types.IRODSAccount, error) {
	var irodsAccount *irodsclient_types.IRODSAccount
	var err error

	switch strings.ToLower(config.IRODSAuthScheme) {
	case "", "native", "pam_for_users":
		// pam_for_users auth mode uses native auth to use proxy

		irodsAccount, err = irodsclient_types.CreateIRODSProxyAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, config.IRODSProxyUsername, config.IRODSZone, irodsclient_types.AuthSchemeNative, config.IRODSProxyPassword, "")
		if err != nil {
			log.Debugf("failed to create iRODS account for proxy auth")
			return nil, err
		}
	case "pam":
		irodsAccount, err = irodsclient_types.CreateIRODSProxyAccount(config.IRODSHost, config.IRODSPort, config.SFTPGoAuthdUsername, config.IRODSZone, config.IRODSProxyUsername, config.IRODSZone, irodsclient_types.AuthSchemePAM, config.IRODSProxyPassword, "")
		if err != nil {
			log.Debugf("failed to create iRODS account for proxy auth")
			return nil, err
		}

		sslConf, err := irodsclient_types.CreateIRODSSSLConfig(config.IRODSSSLCACertificatePath, config.IRODSSSLKeySize, config.IRODSSSLAlgorithm, config.IRODSSSLSaltSize, config.IRODSSSLHashRounds)
		if err != nil {
			log.Debugf("failed to create iRODS SSL config for auth")
			return nil, err
		}

		irodsAccount.SetSSLConfiguration(sslConf)
	default:
		return nil, fmt.Errorf("unknown authentication scheme %s", config.IRODSAuthScheme)
	}

	return irodsAccount, nil
}

// AuthViaPassword authenticate a user via password
func AuthViaPassword(config *commons.Config) (bool, error) {
	irodsAccount, err := makeIRODSAccount(config)
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
func AuthViaPublicKey(config *commons.Config) (bool, []string, error) {
	log.Debugf("authenticating a user '%s'", config.SFTPGoAuthdUsername)

	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.SFTPGoAuthdPublickey))
	if err != nil {
		log.Debugf("failed to parse public-key for a user '%s'", config.SFTPGoAuthdUsername)
		return false, nil, err
	}

	// login using proxy (admin) account
	irodsAccount, err := makeIRODSAccountForProxy(config)
	if err != nil {
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
func readAuthorizedKeys(config *commons.Config, irodsConn *irodsclient_conn.IRODSConnection) ([]byte, error) {
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

func CreateSshDir(config *commons.Config) error {
	sshPath := makeSSHPath(config)

	log.Debugf("creating .ssh dir '%s'", sshPath)

	var irodsAccount *irodsclient_types.IRODSAccount
	var err error

	if config.IsProxyAuth() {
		// login using proxy (admin) account
		irodsAccount, err = makeIRODSAccountForProxy(config)
		if err != nil {
			return err
		}
	} else {
		// login
		irodsAccount, err = makeIRODSAccount(config)
		if err != nil {
			return err
		}
	}

	irodsConn := irodsclient_conn.NewIRODSConnection(irodsAccount, authRequestTimeout, applicationName)
	err = irodsConn.Connect()
	if err != nil {
		// auth fail
		log.Debugf("failed to login via iRODS proxy user account")
		return err
	}

	defer irodsConn.Disconnect()

	err = irodsclient_fs.CreateCollection(irodsConn, sshPath, true)
	if err != nil {
		log.Debugf("failed to create .ssh dir")
		return err
	}

	return nil
}
