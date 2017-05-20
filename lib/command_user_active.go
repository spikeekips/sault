package sault

import (
	"encoding/json"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var userActiveOptionsTemplate = OptionsTemplate{
	Name:        "active",
	Help:        "set user active or not",
	Usage:       "[flags] <userName>[-] [<userName>[-]...]",
	ParseFunc:   parseUserActiveOptions,
	Description: descriptionUserActive,
}

func parseUserActiveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	userNames := op.FlagSet.Args()
	if len(userNames) < 1 {
		return fmt.Errorf("<userName> is missing")
	}

	names := map[string]bool{}
	for _, u := range userNames {
		name, active := parseNameActive(u)
		if !CheckUserName(name) {
			return fmt.Errorf("invalid userName, '%s'", name)
		}
		names[name] = active
	}

	op.Extra["Users"] = names

	return nil
}

func requestUserActive(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	var users []userResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		signer,
		"user.active",
		userActiveRequestData{Users: ov["Users"].(map[string]bool)},
		&users,
	)
	if err != nil {
		return
	}
	if response.Error != nil {
		err = response.Error
		return
	}

	CommandOut.Println(printUsers(users))
	return
}

func responseUserActive(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userActiveRequestData
	json.Unmarshal(msg.Data, &data)

	var users []userResponseData
	for userName, active := range data.Users {
		err = pc.proxy.Registry.SetUserActive(userName, active)
		if err != nil {
			log.Error(err)
			continue
		}
		userData, _ := pc.proxy.Registry.GetUserByUserName(userName)
		userResponseData := newUserResponseData(pc.proxy.Registry, userData)
		users = append(users, userResponseData)
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
