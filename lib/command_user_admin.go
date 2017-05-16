package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/spikeekips/sault/ssh"
)

var userAdminOptionsTemplate = OptionsTemplate{
	Name:      "admin",
	Help:      "make user to be admin or not",
	Usage:     "[flags] <userName>[-]",
	ParseFunc: parseUserAdminOptions,
}

func parseUserAdminOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("<userName> is missing")
	}

	userName := args[0]

	var setAdmin bool
	if regexp.MustCompile(`\-$`).FindString(userName) == "" {
		setAdmin = true
	} else {
		userName = userName[0 : len(userName)-1]
		setAdmin = false
	}

	op.Extra["UserName"] = userName
	op.Extra["SetAdmin"] = setAdmin

	return nil
}

func requestUserAdmin(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	userName := ov["UserName"].(string)
	setAdmin := ov["SetAdmin"].(bool)

	var data userResponseData
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.admin",
		userAdminRequestData{
			User:     userName,
			SetAdmin: setAdmin,
		},
		&data,
	)

	fmt.Fprintf(os.Stdout, printUser(data))

	exitStatus = 0

	return
}

func responseUserAdmin(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userAdminRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to admin: %v", data)
	err = pc.proxy.Registry.SetAdmin(data.User, data.SetAdmin)
	if err != nil {
		log.Errorf("failed to admin: %v", err)
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)

	channel.Write(toResponse(newUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
