package sault

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/spikeekips/sault/ssh"
)

var userActiveOptionsTemplate = OptionsTemplate{
	Name: "active",
	Help: "set user active or not",
	Description: `
The deactivated user will be not allowed to be authenticated. The difference with "user remove" is, the "user remove" will remove user data, but the data of the deactivated user will be kept, so the *deactivating* user will be safer way to manage users.

To active "spikeekips",
{{ "$ sault user active spikeekips" | magenta }}

To deactivate "spikeekips", just add "{{ "-" | yellow }}" in the end of user name,
{{ "$ sault user active spikeekips-" | magenta }}
	`,
	Usage:     "[flags] <userName>[-]",
	ParseFunc: parseUserActiveOptions,
}

func parseUserActiveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
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

func requestUserActive(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var response *responseMsg
	var data userResponseData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.active",
		userActiveRequestData{User: ov["UserName"].(string), Active: ov["Active"].(bool)},
		&data,
	)
	if err != nil {
		return
	}
	if response.Error != nil {
		err = response.Error
		return
	}

	CommandOut.Println(printUser(data))
	return
}

func responseUserActive(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userActiveRequestData
	json.Unmarshal(msg.Data, &data)

	err = pc.proxy.Registry.SetUserActive(data.User, data.Active)
	if err != nil {
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)

	var response []byte
	response, err = newResponseMsg(
		newUserResponseData(pc.proxy.Registry, userData),
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
