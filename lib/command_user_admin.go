package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var userAdminOptionsTemplate = OptionsTemplate{
	Name:      "admin",
	Help:      "make user to be admin or not",
	Usage:     "[flags] <userName>[-]",
	Options:   []OptionTemplate{atOptionTemplate, pOptionTemplate},
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

func requestUserAdmin(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)
	address := ov["SaultServerAddress"].(string)
	serverName := ov["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	userName := ov["UserName"].(string)
	setAdmin := ov["SetAdmin"].(bool)

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"user.admin",
			userAdminRequestData{
				User:     userName,
				SetAdmin: setAdmin,
			},
		)
		if err != nil {
			log.Errorf("failed to make message: %v", err)
			exitStatus = 1
			return
		}

		log.Debug("msg sent")
		output, exitStatus, err = runCommand(connection, msg)
		if err != nil {
			log.Error(err)
			return
		}
	}

	var rm responseMsg
	if err := saultSsh.Unmarshal(output, &rm); err != nil {
		log.Errorf("got invalid response: %v", err)
		exitStatus = 1
		return
	}

	if rm.Error != "" {
		log.Errorf("%s", rm.Error)
		exitStatus = 1

		return
	}

	var data userResponseData
	if err := json.Unmarshal(rm.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("received data %v", string(jsoned))

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

		channel.Write(toResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)

	channel.Write(toResponse(newUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
