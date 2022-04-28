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
	types.SetLog()

	// read environmental vars
	config, err := types.ReadFromEnv()
	if err != nil {
		exitError(err)
		return
	}

	err = config.Validate()
	if err != nil {
		exitError(err)
		return
	}

	var sftpGoUser *types.SFTPGoUser
	if config.IsPublicKeyAuth() {
		sftpGoUser, err = auth.AuthViaPublicKey(config)
	} else {
		sftpGoUser, err = auth.AuthViaPassword(config)
	}

	if err != nil {
		exitError(err)
		return
	}

	// return the authenticated user
	printSuccessResponse(sftpGoUser)
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
	log.Printf("Authenticated user '%s': %s\n", sftpGoUser.Username, redactedJSONString)

	resp, _ := json.Marshal(sftpGoUser)
	fmt.Printf("%v\n", string(resp))
	os.Exit(0)
}
