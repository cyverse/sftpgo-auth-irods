package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/sftpgo-auth-irods/auth"
	"github.com/cyverse/sftpgo-auth-irods/commons"
	"github.com/cyverse/sftpgo-auth-irods/types"
	log "github.com/sirupsen/logrus"
)

func main() {
	// set logger
	defaultLogPath := commons.GetDefaultLogPath()
	commons.SetLog(defaultLogPath)

	// Parse parameters
	var version bool

	flag.BoolVar(&version, "version", false, "Print client version information")
	flag.BoolVar(&version, "v", false, "Print client version information (shorthand form)")

	flag.Parse()

	if version {
		info, err := commons.GetVersionJSON()
		if err != nil {
			exitError(err)
			return
		}

		fmt.Println(info)
		return
	}

	// read environmental vars
	config, err := commons.ReadFromEnv()
	if err != nil {
		exitError(err)
		return
	}

	_, err = os.Stat(config.SFTPGoLogDir)
	if err != nil {
		if os.IsNotExist(err) {
			err2 := os.MkdirAll(config.SFTPGoLogDir, 0755)
			if err2 != nil {
				// failed to create a log dir
				exitError(err2)
				return
			}
		} else {
			// failed to access a log dir
			exitError(err)
			return
		}
	}

	commons.SetLog(config.SFTPGoLogDir)

	err = config.Validate()
	if err != nil {
		exitError(err)
		return
	}

	if config.IsPublicKeyAuth() {
		sftpGoUser, err := authPublicKey(config)
		if err != nil {
			exitError(err)
			return
		}

		printSuccessResponse(sftpGoUser)
		return
	} else {
		sftpGoUser, err := authPassword(config)
		if err != nil {
			exitError(err)
			return
		}

		printSuccessResponse(sftpGoUser)
		return
	}
}

// The iRODS operations are referenced through variables so that tests can
// exercise the SFTPGoUser generation without reaching an iRODS server.
var (
	authViaPassword  = auth.AuthViaPassword
	authViaPublicKey = auth.AuthViaPublicKey
	createSshDir     = auth.CreateSshDir
)

func authPublicKey(config *commons.Config) (*types.SFTPGoUser, error) {
	err := config.ValidateForPublicKeyAuth()
	if err != nil {
		return nil, err
	}

	loggedIn, options, err := authViaPublicKey(config)
	if err != nil {
		return nil, err
	}

	if loggedIn {
		log.Infof("Authenticated user %q using public key, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

		// must have .ssh dir to reach here!
		// create .ssh dir
		//err := auth.CreateSshDir(config)
		//if err != nil {
		//	return nil, err
		//}

		// return the authenticated user
		mountPaths := []types.MountPath{}

		userHomePath := config.GetHomeDirPath()
		customUserHomePath := auth.GetHomeCollectionPath(config, options)
		sftpgoUsername := config.SFTPGoAuthdUsername

		if userHomePath != customUserHomePath {
			// set a new home path
			pubKeyName := makeSafePublickKeyName(config.SFTPGoAuthdPublickey)
			// assign a new user
			sftpgoUsername = fmt.Sprintf("%s_%s", config.SFTPGoAuthdUsername, pubKeyName)

			mountPaths = append(mountPaths, makeMountPathForCustomHome(config, customUserHomePath, pubKeyName))

			// We don't give access to .ssh dir to not allow editting the authorized_keys file
			//mountPaths = append(mountPaths, makeMountPathForSSHDir(config))

			if config.HasSharedDir() {
				mountPaths = append(mountPaths, makeMountPathForCustomSharedDir(config, pubKeyName))
			}
		} else {
			mountPaths = append(mountPaths, makeMountPathForHome(config))

			//mountPaths = append(mountPaths, makeMountPathForSSHDir(config))

			if config.HasSharedDir() {
				mountPaths = append(mountPaths, makeMountPathForSharedDir(config))
			}
		}

		sftpGoUser, err := auth.MakeSFTPGoUser(config, sftpgoUsername, mountPaths)
		if err != nil {
			return nil, err
		}

		return sftpGoUser, nil
	}

	return nil, errors.Errorf("unable to auth the user %q", config.SFTPGoAuthdUsername)
}

func authPassword(config *commons.Config) (*types.SFTPGoUser, error) {
	if config.IsAnonymousUser() {
		// overwrite existing account info to ensure correct spell/case and empty password
		config.SFTPGoAuthdUsername = "anonymous"
		config.SFTPGoAuthdPassword = "" // empty password
	}

	loggedIn, err := authViaPassword(config)
	if err != nil {
		log.WithError(err).Errorf("Authenticated failed for user %q using password", config.SFTPGoAuthdUsername)
		return nil, err
	}

	if loggedIn {
		log.Infof("Authenticated user %q using password, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

		// create .ssh dir
		if !config.IsAnonymousUser() {
			err := createSshDir(config)
			if err != nil {
				return nil, err
			}
		}

		mountPaths := []types.MountPath{}
		if !config.IsAnonymousUser() {
			// anonymous user doesn't have home dir
			// so do this only if user is not anonymous
			mountPaths = append(mountPaths, makeMountPathForHome(config))

			//mountPaths = append(mountPaths, makeMountPathForSSHDir(config))
		}

		if config.HasSharedDir() {
			mountPaths = append(mountPaths, makeMountPathForSharedDir(config))
		}

		sftpGoUser, err := auth.MakeSFTPGoUser(config, config.SFTPGoAuthdUsername, mountPaths)
		if err != nil {
			return nil, err
		}

		return sftpGoUser, nil
	}

	return nil, errors.Errorf("unable to auth the user %q", config.SFTPGoAuthdUsername)
}

func makeMountPathForHome(config *commons.Config) types.MountPath {
	userHomePath := config.GetHomeDirPath()
	return types.MountPath{
		Name:           fmt.Sprintf("%s_home", config.SFTPGoAuthdUsername),
		DirName:        config.SFTPGoAuthdUsername,
		Description:    "iRODS home",
		CollectionPath: userHomePath,
	}
}

func makeMountPathForCustomHome(config *commons.Config, customUserHomePath string, pubKeyName string) types.MountPath {
	return types.MountPath{
		Name:           fmt.Sprintf("%s_home_%s", config.SFTPGoAuthdUsername, pubKeyName),
		DirName:        config.SFTPGoAuthdUsername,
		Description:    fmt.Sprintf("iRODS home - %s", customUserHomePath),
		CollectionPath: customUserHomePath,
	}
}

func makeMountPathForSSHDir(config *commons.Config) types.MountPath {
	userHomePath := config.GetHomeDirPath()
	return types.MountPath{
		Name:           fmt.Sprintf("%s_ssh", config.SFTPGoAuthdUsername),
		DirName:        ".ssh",
		Description:    "iRODS .ssh dir",
		CollectionPath: fmt.Sprintf("%s/.ssh", userHomePath),
	}
}

func makeMountPathForSharedDir(config *commons.Config) types.MountPath {
	sharedDirName := config.GetSharedDirName()
	return types.MountPath{
		Name:           fmt.Sprintf("%s_%s", config.SFTPGoAuthdUsername, sharedDirName),
		DirName:        sharedDirName,
		Description:    fmt.Sprintf("iRODS %s", sharedDirName),
		CollectionPath: config.IRODSShared,
	}
}

func makeMountPathForCustomSharedDir(config *commons.Config, pubKeyName string) types.MountPath {
	sharedDirName := config.GetSharedDirName()
	return types.MountPath{
		Name:           fmt.Sprintf("%s_%s_%s", config.SFTPGoAuthdUsername, sharedDirName, pubKeyName),
		DirName:        sharedDirName,
		Description:    fmt.Sprintf("iRODS %s", sharedDirName),
		CollectionPath: config.IRODSShared,
	}
}

func exitError(err error) {
	log.Error(err)

	u := types.NewSFTPGoUserForError()
	resp, _ := json.Marshal(u)
	fmt.Printf("%v\n", string(resp))
	os.Exit(1)
}

func printSuccessResponse(sftpGoUser *types.SFTPGoUser) {
	redactedJSONString := sftpGoUser.GetRedactedJSONString()
	log.Infof("Authenticated user %q: %s", sftpGoUser.Username, redactedJSONString)

	resp, _ := json.Marshal(sftpGoUser)
	fmt.Printf("%v\n", string(resp))
	os.Exit(0)
}

// makeSafePublickKeyName returns a short name that uniquely identifies the given
// public key. The leading characters of a key blob only encode the key type, so
// the blob is hashed to tell keys of the same type apart.
func makeSafePublickKeyName(pubkey string) string {
	key := strings.TrimSpace(pubkey)
	fields := strings.Fields(pubkey)
	if len(fields) >= 2 {
		// drop the key type and the trailing comment
		key = fields[1]
	}

	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])[:16]
}
