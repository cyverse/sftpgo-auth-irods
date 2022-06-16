package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cyverse/sftpgo-auth-irods/auth"
	"github.com/cyverse/sftpgo-auth-irods/types"
	log "github.com/sirupsen/logrus"
)

func main() {
	// set logger
	defaultLogPath := types.GetDefaultLogPath()
	types.SetLog(defaultLogPath)

	// read environmental vars
	config, err := types.ReadFromEnv()
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

	types.SetLog(config.SFTPGoLogDir)

	err = config.Validate()
	if err != nil {
		exitError(err)
		return
	}

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

			userHomePath := fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername)
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

				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_shared_%s", config.SFTPGoAuthdUsername, pubKeyName),
					DirName:        "shared",
					Description:    "iRODS shared",
					CollectionPath: fmt.Sprintf("/%s/home/shared", config.IRODSZone),
				})
			} else {
				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_home", config.SFTPGoAuthdUsername),
					DirName:        config.SFTPGoAuthdUsername,
					Description:    "iRODS home",
					CollectionPath: userHomePath,
				})

				mountPaths = append(mountPaths, types.MountPath{
					Name:           fmt.Sprintf("%s_shared", config.SFTPGoAuthdUsername),
					DirName:        "shared",
					Description:    "iRODS shared",
					CollectionPath: fmt.Sprintf("/%s/home/shared", config.IRODSZone),
				})
			}

			sftpGoUser := auth.MakeSFTPGoUser(config, sftpgoUsername, mountPaths)
			printSuccessResponse(sftpGoUser)
			return
		}
	} else {
		loggedIn, err := auth.AuthViaPassword(config)
		if err != nil {
			exitError(err)
			return
		}

		if loggedIn {
			log.Infof("Authenticated user '%s' using password, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

			// return the authenticated user
			mountPaths := []types.MountPath{
				{
					Name:           config.SFTPGoAuthdUsername,
					Description:    "iRODS home",
					CollectionPath: fmt.Sprintf("/%s/home/%s", config.IRODSZone, config.SFTPGoAuthdUsername),
				},
				{
					Name:           "shared",
					Description:    "iRODS shared",
					CollectionPath: fmt.Sprintf("/%s/home/shared", config.IRODSZone),
				},
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
