package sault

import (
	"encoding/json"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var userRemoveOptionsTemplate = OptionsTemplate{
	Name:      "remove",
	Help:      "remove user",
	Usage:     "[flags] <userName>",
	ParseFunc: parseUserRemoveOptions,
}

func parseUserRemoveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("<userName> is missing")
	}

	op.Extra["UserName"] = args[0]

	return nil
}

func requestUserRemove(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	userName := ov["UserName"].(string)

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	var response *responseMsg
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		clientPublicKey,
		"user.remove",
		userRemoveRequestData{
			User: userName,
		},
		nil,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	CommandOut.Printf("user, `%s` was removed", userName)
	return
}

func responseUserRemove(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	err = pc.proxy.Registry.RemoveUser(data.User)
	if err != nil {
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var response []byte
	response, err = newResponseMsg(
		nil,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
