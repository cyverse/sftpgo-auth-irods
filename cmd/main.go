package main

import (
	"encoding/json"
	"fmt"
	"os"

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

		loggedIn, _, err := auth.AuthViaPublicKey(config)
		if err != nil {
			exitError(err)
			return
		}

		if loggedIn {
			log.Infof("Authenticated user '%s' using public key, creating a SFTPGoUser", config.SFTPGoAuthdUsername)

			// return the authenticated user
			sftpGoUser := auth.MakeSFTPGoUser(config)
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
			sftpGoUser := auth.MakeSFTPGoUser(config)
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
