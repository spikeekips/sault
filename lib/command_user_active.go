package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var UserActiveOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name: "active",
	Help: "set user active or not",
	Description: `
The deactivated user will be not allowed to be authenticated. The difference with "user remove" is, the "user remove" will remove user data, but the data of the deactivated user will be kept, so the *deactivating* user will be safer way to manage user.

To active "spikeekips",
$ sault user active spikeekips

To deactivate "spikeekips",
$ sault user active spikeekips-
	`,
	Usage:     "[flags] <userName>[-]",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseUserActiveOptions,
}

func ParseUserActiveOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("<userName> is missing")
	}

	userName := args[0]

	var active bool
	if regexp.MustCompile(`\-$`).FindString(userName) == "" {
		active = true
	} else {
		userName = userName[0 : len(userName)-1]
		active = false
	}

	op.Extra["UserName"] = userName
	op.Extra["Active"] = active

	return nil
}

func RequestUserActive(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
	active := ov["Active"].(bool)

	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"user.active",
			UserActiveRequestData{UserName: userName, Active: active},
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

func ResponseUserActive(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data UserActiveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to active: %v", data)
	err = pc.proxy.Registry.SetActive(data.UserName, data.Active)
	if err != nil {
		log.Errorf("failed to set active: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.UserName)

	channel.Write(ToResponse(NewUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
