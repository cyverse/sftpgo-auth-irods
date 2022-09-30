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

	userHomePath := fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)

	if config.IsPublicKeyAuth() {
		err = config.ValidateForPublicKeyAuth()
		if err != nil {
			exitError(err)
			return
		}

		loggedIn, options, err := auth.AuthViaPublicKey(config)
		if err != nil {
			exitError(err)
			return
		}

		if loggedIn {
			log.Infof("Authenticated user '%s' using public key, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

			// return the authenticated user
			mountPaths := []types.MountPath{}

			customUserHomePath := auth.GetHomeCollectionPath(config, options)
			sftpgoUsername := config.SFTPGoAuthdUsername

			if userHomePath != customUserHomePath {
				// set a new home path
				pubKeyName := makeSafePublickKeyName(config.SFTPGoAuthdPublickey)
				// assign a new user
				sftpgoUsername = fmt.Sprintf("%s_%s", config.SFTPGoAuthdUsername, pubKeyName)

				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_home_%s", config.SFTPGoAuthdUsername, pubKeyName),
					DirName:        config.SFTPGoAuthdUsername,
					Description:    fmt.Sprintf("iRODS home - %s", customUserHomePath),
					CollectionPath: customUserHomePath,
				})

				if config.HasSharedDir() {
					sharedDirName := config.GetSharedDirName()
					mountPaths = append(mountPaths, types.MountPath{
						Name:           fmt.Sprintf("%s_%s_%s", config.SFTPGoAuthdUsername, sharedDirName, pubKeyName),
						DirName:        sharedDirName,
						Description:    fmt.Sprintf("iRODS %s", sharedDirName),
						CollectionPath: config.IRODSShared,
					})
				}
			} else {
				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_home", config.SFTPGoAuthdUsername),
					DirName:        config.SFTPGoAuthdUsername,
					Description:    "iRODS home",
					CollectionPath: userHomePath,
				})

				if config.HasSharedDir() {
					sharedDirName := config.GetSharedDirName()
					mountPaths = append(mountPaths, types.MountPath{
						Name:           fmt.Sprintf("%s_%s", config.SFTPGoAuthdUsername, sharedDirName),
						DirName:        sharedDirName,
						Description:    fmt.Sprintf("iRODS %s", sharedDirName),
						CollectionPath: config.IRODSShared,
					})
				}
			}

			sftpGoUser := auth.MakeSFTPGoUser(config, sftpgoUsername, mountPaths)
			printSuccessResponse(sftpGoUser)
			return
		}
	} else {
		if config.IsAnonymousUser() {
			// overwrite existing account info to ensure correct spell/case and empty password
			config.SFTPGoAuthdUsername = "anonymous"
			config.SFTPGoAuthdPassword = "" // empty password
		}

		loggedIn, err := auth.AuthViaPassword(config)
		if err != nil {
			exitError(err)
			return
		}

		if loggedIn {
			log.Infof("Authenticated user '%s' using password, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

			mountPaths := []types.MountPath{}
			if !config.IsAnonymousUser() {
				// anonymous user doesn't have home dir
				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_home", config.SFTPGoAuthdUsername),
					DirName:        config.SFTPGoAuthdUsername,
					Description:    "iRODS home",
					CollectionPath: userHomePath,
				})
			}

			if config.HasSharedDir() {
				sharedDirName := config.GetSharedDirName()
				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_%s", config.SFTPGoAuthdUsername, sharedDirName),
					DirName:        sharedDirName,
					Description:    fmt.Sprintf("iRODS %s", sharedDirName),
					CollectionPath: config.IRODSShared,
				})
			}

			sftpGoUser := auth.MakeSFTPGoUser(config, config.SFTPGoAuthdUsername, mountPaths)
			printSuccessResponse(sftpGoUser)
			return
		}
	}

	exitError(fmt.Errorf("unable to auth the user %s", config.SFTPGoAuthdUsername))
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
