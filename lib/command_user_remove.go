package sault

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var userRemoveOptionsTemplate = OptionsTemplate{
	Name:      "remove",
	Help:      "remove user",
	Usage:     "[flags] <userName> [<userName>...]",
	ParseFunc: parseUserRemoveOptions,
}

func parseUserRemoveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	userNames := op.FlagSet.Args()
	if len(userNames) < 1 {
		return fmt.Errorf("<userName> is missing")
	}

	{
		var names []string
		for _, userName := range userNames {
			if !CheckUserName(userName) {
				return fmt.Errorf("invalid userName, '%s'", userName)
			}
			names = append(names, userName)
		}

		op.Extra["Users"] = names
	}

	return nil
}

func requestUserRemove(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	var users []string
	var response *responseMsg
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		clientPublicKey,
		"user.remove",
		userRemoveRequestData{
			Users: ov["Users"].([]string),
		},
		&users,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	if len(users) < 1 {
		err = errors.New("no users removed")
		return
	}

	CommandOut.Printf("users, %s was removed", users)
	return
}

func responseUserRemove(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	var users []string
	for _, userName := range data.Users {
		err = pc.proxy.Registry.RemoveUser(userName)
		if err != nil {
			continue
		}
		users = append(users, userName)
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var response []byte
	response, err = newResponseMsg(
		users,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
