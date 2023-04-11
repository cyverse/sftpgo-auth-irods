package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

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
	var fakeoutput bool

	flag.BoolVar(&version, "version", false, "Print client version information")
	flag.BoolVar(&version, "v", false, "Print client version information (shorthand form)")
	flag.BoolVar(&fakeoutput, "fake", false, "Generate fake output json")

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
			err2 := os.MkdirAll(config.SFTPGoLogDir, 0644)
			if err2 != nil {
				// failed to create a log dir
				exitError(err)
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
		if fakeoutput {
			sftpGoUser, err := authPublicKeyFake(config)
			if err != nil {
				exitError(err)
				return
			}

			printSuccessResponse(sftpGoUser)
			return
		}

		sftpGoUser, err := authPublicKey(config)
		if err != nil {
			exitError(err)
			return
		}

		printSuccessResponse(sftpGoUser)
		return
	} else {
		if fakeoutput {
			sftpGoUser, err := authPasswordFake(config)
			if err != nil {
				exitError(err)
				return
			}

			printSuccessResponse(sftpGoUser)
			return
		}

		sftpGoUser, err := authPassword(config)
		if err != nil {
			exitError(err)
			return
		}

		printSuccessResponse(sftpGoUser)
		return
	}
}

func authPublicKeyFake(config *commons.Config) (*types.SFTPGoUser, error) {
	err := config.ValidateForPublicKeyAuth()
	if err != nil {
		return nil, err
	}

	log.Infof("Authenticated user '%s' using public key, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

	// return the authenticated user
	mountPaths := []types.MountPath{}

	sftpgoUsername := config.SFTPGoAuthdUsername

	mountPaths = append(mountPaths, makeMountPathForHome(config))

	//mountPaths = append(mountPaths, makeMountPathForSSHDir(config))

	if config.HasSharedDir() {
		mountPaths = append(mountPaths, makeMountPathForSharedDir(config))
	}

	sftpGoUser := auth.MakeSFTPGoUser(config, sftpgoUsername, mountPaths)
	return sftpGoUser, nil
}

func authPasswordFake(config *commons.Config) (*types.SFTPGoUser, error) {
	if config.IsAnonymousUser() {
		// overwrite existing account info to ensure correct spell/case and empty password
		config.SFTPGoAuthdUsername = "anonymous"
		config.SFTPGoAuthdPassword = "" // empty password
	}

	log.Infof("Authenticated user '%s' using password, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

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

	sftpGoUser := auth.MakeSFTPGoUser(config, config.SFTPGoAuthdUsername, mountPaths)
	return sftpGoUser, nil
}

func authPublicKey(config *commons.Config) (*types.SFTPGoUser, error) {
	err := config.ValidateForPublicKeyAuth()
	if err != nil {
		return nil, err
	}

	loggedIn, options, err := auth.AuthViaPublicKey(config)
	if err != nil {
		return nil, err
	}

	if loggedIn {
		log.Infof("Authenticated user '%s' using public key, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

		// create .ssh dir
		err := auth.CreateSshDir(config)
		if err != nil {
			return nil, err
		}

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

		sftpGoUser := auth.MakeSFTPGoUser(config, sftpgoUsername, mountPaths)
		return sftpGoUser, nil
	}

	return nil, fmt.Errorf("unable to auth the user %s", config.SFTPGoAuthdUsername)
}

func authPassword(config *commons.Config) (*types.SFTPGoUser, error) {
	if config.IsAnonymousUser() {
		// overwrite existing account info to ensure correct spell/case and empty password
		config.SFTPGoAuthdUsername = "anonymous"
		config.SFTPGoAuthdPassword = "" // empty password
	}

	loggedIn, err := auth.AuthViaPassword(config)
	if err != nil {
		return nil, err
	}

	if loggedIn {
		log.Infof("Authenticated user '%s' using password, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

		// create .ssh dir
		if !config.IsAnonymousUser() {
			err := auth.CreateSshDir(config)
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

		sftpGoUser := auth.MakeSFTPGoUser(config, config.SFTPGoAuthdUsername, mountPaths)
		return sftpGoUser, nil
	}

	return nil, fmt.Errorf("unable to auth the user %s", config.SFTPGoAuthdUsername)
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
	log.Infof("Authenticated user '%s': %s", sftpGoUser.Username, redactedJSONString)

	resp, _ := json.Marshal(sftpGoUser)
	fmt.Printf("%v\n", string(resp))
	os.Exit(0)
}

func makeSafePublickKeyName(pubkey string) string {
	fields := strings.Fields(pubkey)
	key := pubkey
	if len(fields) >= 2 {
		key = fields[1]
	}

	return strings.ReplaceAll(key[:15], " ", "_")
}
