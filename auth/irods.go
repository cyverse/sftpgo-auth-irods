package auth

import (
	"bytes"
	"io"
	"path"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
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

	// maxAuthorizedKeysSize bounds how much of authorized_keys is read into
	// memory. A key line stays well under a kilobyte, so this holds far more
	// keys than a user would register while keeping an object of any size from
	// being buffered by the auth hook.
	maxAuthorizedKeysSize int64 = 1024 * 1024
)

// makeSSHPath returns the user's .ssh collection path. Only the public key flow
// and CreateSshDir reach this, and neither runs for the anonymous user, who has
// no home collection.
func makeSSHPath(config *commons.Config) string {
	return path.Join(config.GetHomeDirPath(), ".ssh")
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
	default:
		log.Debugf("unknown authentication scheme %q", config.IRODSAuthScheme)
		return nil, errors.Errorf("unknown authentication scheme %q", config.IRODSAuthScheme)
	}

	// SSL
	if config.IRODSRequireCSNegotiation {
		require := irodsclient_types.GetCSNegotiationPolicyRequest(config.IRODSCSNegotiationPolicy)
		irodsAccount.SetCSNegotiation(true, require)

		if require == irodsclient_types.CSNegotiationPolicyRequestSSL || len(config.IRODSSSLCACertificatePath) > 0 {
			// SSL
			irodsAccount.SetSSLConfiguration(makeIRODSSSLConfig(config))
		}
	}

	return irodsAccount, nil
}

func makeIRODSSSLConfig(config *commons.Config) *irodsclient_types.IRODSSSLConfig {
	verifyServer := irodsclient_types.SSLVerifyServer(config.IRODSSSLVerifyServer)
	if verifyServer == irodsclient_types.SSLVerifyServerCert {
		// go-irodsclient only verifies the server for 'hostname', so 'cert' silently
		// leaves the certificate unverified
		log.Warnf("iRODS SSL verify server %q does not verify the server certificate, use %q instead",
			irodsclient_types.SSLVerifyServerCert, irodsclient_types.SSLVerifyServerHostname)
	}

	return &irodsclient_types.IRODSSSLConfig{
		CACertificatePath:       config.IRODSSSLCACertificatePath,
		EncryptionKeySize:       config.IRODSSSLKeySize,
		EncryptionAlgorithm:     config.IRODSSSLAlgorithm,
		EncryptionSaltSize:      config.IRODSSSLSaltSize,
		EncryptionNumHashRounds: config.IRODSSSLHashRounds,
		VerifyServer:            verifyServer,
	}
}

func makeIRODSConnectionConfig() *irodsclient_conn.IRODSConnectionConfig {
	return &irodsclient_conn.IRODSConnectionConfig{
		OperationTimeout:     authRequestTimeout,
		LongOperationTimeout: authRequestTimeout,
		ApplicationName:      applicationName,
	}
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
	default:
		return nil, errors.Errorf("unknown authentication scheme %q", config.IRODSAuthScheme)
	}

	if config.IRODSRequireCSNegotiation {
		require := irodsclient_types.GetCSNegotiationPolicyRequest(config.IRODSCSNegotiationPolicy)
		irodsAccount.SetCSNegotiation(true, require)

		if require == irodsclient_types.CSNegotiationPolicyRequestSSL || len(config.IRODSSSLCACertificatePath) > 0 {
			// SSL
			irodsAccount.SetSSLConfiguration(makeIRODSSSLConfig(config))
		}
	}

	return irodsAccount, nil
}

// AuthViaPassword authenticate a user via password
func AuthViaPassword(config *commons.Config) (bool, error) {
	irodsAccount, err := makeIRODSAccount(config)
	if err != nil {
		return false, err
	}

	irodsConnectionConfig := makeIRODSConnectionConfig()

	irodsConn, err := irodsclient_conn.NewIRODSConnection(irodsAccount, irodsConnectionConfig)
	if err != nil {
		return false, err
	}

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
	log.Debugf("authenticating a user %q", config.SFTPGoAuthdUsername)

	userKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.SFTPGoAuthdPublickey))
	if err != nil {
		log.Debugf("failed to parse public-key for a user %q", config.SFTPGoAuthdUsername)
		return false, nil, err
	}

	// login using proxy (admin) account
	irodsAccount, err := makeIRODSAccountForProxy(config)
	if err != nil {
		return false, nil, err
	}

	irodsConnectionConfig := makeIRODSConnectionConfig()

	irodsConn, err := irodsclient_conn.NewIRODSConnection(irodsAccount, irodsConnectionConfig)
	if err != nil {
		return false, nil, err
	}
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

	loggedIn, options, err := checkAuthorizedKey(authorizedKeys, userKey)
	if err != nil {
		// auth fail
		return false, nil, err
	}

	if loggedIn {
		log.Debugf("checking options - %v", options)
		// expiry
		if IsKeyExpired(options) {
			return false, options, errors.Errorf("public key access for the user %q is expired", config.SFTPGoAuthdUsername)
		}

		// reject by client whilte-list
		if IsClientRejected(config.SFTPGoAuthdIP, options) {
			return false, options, errors.Errorf("public key access for the user %q is rejected", config.SFTPGoAuthdUsername)
		}

		// auth success
		log.Debugf("authenticated a user %q", config.SFTPGoAuthdUsername)
		return true, options, nil
	}

	// auth fail
	log.Debugf("unable to authenticate the user %q using a public key", config.SFTPGoAuthdUsername)
	return false, nil, errors.Errorf("unable to find matching authorized public key for the user %q", config.SFTPGoAuthdUsername)
}

// readAuthorizedKeys returns content of authorized_keys
func readAuthorizedKeys(config *commons.Config, irodsConn *irodsclient_conn.IRODSConnection) ([]byte, error) {
	// check .ssh dir
	sshPath := makeSSHPath(config)

	log.Debugf("checking .ssh dir %q", sshPath)
	sshCollection, err := irodsclient_fs.GetCollection(irodsConn, sshPath)
	if err != nil {
		log.Debugf(".ssh dir %q not exist", sshPath)
		return nil, err
	}

	if sshCollection.ID <= 0 {
		// collection not exist
		log.Debugf(".ssh dir %q not exist", sshPath)
		return nil, errors.Errorf(".ssh dir %q does not exist", sshPath)
	}

	// get .ssh/authorized_keys file
	sshAuthorizedKeysPath := makeSSHAuthorizedKeysPath(config)
	log.Debugf("checking .ssh/authorized_keys file %q", sshAuthorizedKeysPath)
	sshAuthorizedKeysDataObject, err := irodsclient_fs.GetDataObjectMasterReplica(irodsConn, sshAuthorizedKeysPath)
	if err != nil {
		log.Debugf(".ssh/authorized_keys file not exist %q", sshAuthorizedKeysPath)
		return nil, err
	}

	if sshAuthorizedKeysDataObject.ID <= 0 {
		// authorized keys not exist
		log.Debugf(".ssh/authorized_keys file not exist %q", sshAuthorizedKeysPath)
		return nil, errors.Errorf(".ssh/authorized_keys file %q does not exist", sshAuthorizedKeysPath)
	}

	fileHandle, _, err := irodsclient_fs.OpenDataObject(irodsConn, sshAuthorizedKeysPath, "", "r", nil)
	if err != nil {
		log.Debugf("failed to open .ssh/authorized_keys file %q", sshAuthorizedKeysPath)
		return nil, err
	}

	defer irodsclient_fs.CloseDataObject(irodsConn, fileHandle)

	authorizedKeys, truncated, err := readAllLimited(func(buffer []byte) (int, error) {
		return irodsclient_fs.ReadDataObject(irodsConn, fileHandle, buffer)
	}, maxAuthorizedKeysSize)
	if err != nil {
		log.Debugf("failed to read .ssh/authorized_keys file %q", sshAuthorizedKeysPath)
		return nil, errors.Wrapf(err, "failed to read .ssh/authorized_keys file %q", sshAuthorizedKeysPath)
	}

	if truncated {
		log.Warnf("read only the first %d bytes of .ssh/authorized_keys file %q, which holds %d bytes; keys past that point are ignored",
			maxAuthorizedKeysSize, sshAuthorizedKeysPath, sshAuthorizedKeysDataObject.Size)
	}

	return authorizedKeys, nil
}

// readAllLimited reads until EOF and returns what it read, failing once more
// readAllLimited reads at most limit bytes and reports whether the object held
// more than that. Reading only a bounded prefix keeps the auth hook from
// buffering an object of any size; the caller checks the keys it did get.
func readAllLimited(read func([]byte) (int, error), limit int64) ([]byte, bool, error) {
	var buffer bytes.Buffer
	readBuffer := make([]byte, 64*1024)

	// read one round past the limit, so that an object of exactly limit bytes
	// is not reported as truncated
	for int64(buffer.Len()) <= limit {
		readLen, err := read(readBuffer)
		if err != nil && err != io.EOF {
			return nil, false, err
		}

		buffer.Write(readBuffer[:readLen])

		if err == io.EOF {
			break
		}

		if readLen == 0 {
			// no data and no EOF, so reading again would not make progress.
			// Returning what was read so far would look like a shorter
			// authorized_keys rather than a failure
			return nil, false, errors.New("read returned no data before the end of the object")
		}
	}

	if int64(buffer.Len()) > limit {
		// a key line cut in half parses as an invalid line and is skipped
		return buffer.Bytes()[:limit], true, nil
	}

	return buffer.Bytes(), false, nil
}

func CreateSshDir(config *commons.Config) error {
	sshPath := makeSSHPath(config)

	log.Debugf("creating .ssh dir %q", sshPath)

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

	irodsConnectionConfig := makeIRODSConnectionConfig()

	irodsConn, err := irodsclient_conn.NewIRODSConnection(irodsAccount, irodsConnectionConfig)
	if err != nil {
		return err
	}
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
