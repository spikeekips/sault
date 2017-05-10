package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var UserAdminOptionsTemplate = OptionsTemplate{
	Name:      "admin",
	Help:      "make user to be admin or not",
	Usage:     "[flags] <userName>[-]",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseUserAdminOptions,
}

func ParseUserAdminOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
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

func RequestUserAdmin(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		msg, err := NewCommandMsg(
			"user.admin",
			UserAdminRequestData{
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

	var responseMsg ResponseMsg
	if err := saultSsh.Unmarshal(output, &responseMsg); err != nil {
		log.Errorf("got invalid response: %v", err)
		exitStatus = 1
		return
	}

	if responseMsg.Error != "" {
		log.Errorf("%s", responseMsg.Error)
		exitStatus = 1

		return
	}

	var data UserResponseData
	if err := json.Unmarshal(responseMsg.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	fmt.Fprintf(os.Stdout, PrintUser(data))

	exitStatus = 0

	return
}

func ResponseUserAdmin(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data UserAdminRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to admin: %v", data)
	err = pc.proxy.Registry.SetAdmin(data.User, data.SetAdmin)
	if err != nil {
		log.Errorf("failed to admin: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)

	channel.Write(ToResponse(NewUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
