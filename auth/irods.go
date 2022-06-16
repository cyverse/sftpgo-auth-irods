package auth

import (
	"bufio"
	"bytes"
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
	authorizedKeyFilename string        = "authorized_keys"
	applicationName       string        = "sftpgo-auth-irods"
	authRequestTimeout    time.Duration = 30 * time.Second
)

func makeIRODSHomePath(config *types.Config) string {
	return fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
}

func makeIRODSSharedPath(config *types.Config) string {
	return fmt.Sprintf("/%s/home/shared", config.IRODSZone)
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
		// auth success
		log.Debugf("authenticated a user '%s'", config.SFTPGoAuthdUsername)
		return true, options, nil
	}

	// auth fail
	log.Debugf("unable to authenticate a user '%s' using a public key", config.SFTPGoAuthdUsername)
	return false, nil, fmt.Errorf("unable to find matching authorized public key for user '%s'", config.SFTPGoAuthdUsername)
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

func checkAuthorizedKey(authorizedKeys []byte, userKey ssh.PublicKey) (bool, []string) {
	authorizedKeysReader := bytes.NewReader(authorizedKeys)
	authorizedKeysScanner := bufio.NewScanner(authorizedKeysReader)

	for authorizedKeysScanner.Scan() {
		authorizedKeyLine := strings.TrimSpace(authorizedKeysScanner.Text())
		if authorizedKeyLine == "" || authorizedKeyLine[0] == '#' {
			// skip
			continue
		}

		authorizedKey, _, options, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
		if err != nil {
			// skip invalid public key
			continue
		}

		if bytes.Equal(authorizedKey.Marshal(), userKey.Marshal()) {
			// found
			expired := isKeyExpired(options)
			log.Debugf("found matching key - expired:%t", expired)
			if !expired {
				// auth ok
				return true, options
			}
		}
	}

	return false, nil
}

func isKeyExpired(options []string) bool {
	log.Debugf("checking options - %v", options)

	for _, option := range options {
		optKV := strings.Split(option, "=")
		if len(optKV) == 2 {
			optK := strings.TrimSpace(optKV[0])
			if strings.ToLower(optK) == "expiry-time" {
				optV := strings.TrimSpace(optKV[1])

				var expiryDate time.Time
				if len(optV) == 8 {
					// "YYYYMMDD" format
					d, err := time.ParseInLocation("20060102", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						// ignore
						continue
					}
					expiryDate = d
				} else if len(optV) == 12 {
					// "YYYYMMDDHHMM" format
					d, err := time.ParseInLocation("200601021504", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						// ignore
						continue
					}
					expiryDate = d
				} else if len(optV) == 14 {
					// "YYYYMMDDHHMMSS" format
					d, err := time.ParseInLocation("20060102150405", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						// ignore
						continue
					}
					expiryDate = d
				} else {
					d, err := time.ParseInLocation("2006-01-02 15:04:05", optV, time.Local)
					if err != nil {
						log.Debugf("failed to parse expiry date '%s'", optV)
						// ignore
						continue
					}
					expiryDate = d
				}

				nowTime := time.Now()
				log.Debugf("nowTime: %v, expiryDate: %v", nowTime, expiryDate)
				return nowTime.After(expiryDate)
			}
		}
	}
	return false
}
