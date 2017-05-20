package sault

import (
	"encoding/json"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var userAdminOptionsTemplate = OptionsTemplate{
	Name:        "admin",
	Help:        "make user to be admin or not",
	Usage:       "[flags] <userName>[-] [<userName>[-]...]",
	ParseFunc:   parseUserAdminOptions,
	Description: descriptionUserAdmin,
}

func parseUserAdminOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	userNames := op.FlagSet.Args()
	if len(userNames) < 1 {
		return fmt.Errorf("<userName> is missing")
	}

	names := map[string]bool{}
	for _, userName := range userNames {
		name, active := parseNameActive(userName)
		if !CheckUserName(name) {
			return fmt.Errorf("invalid userName, '%s' found", name)
		}
		names[name] = active
	}

	op.Extra["Users"] = names

	return nil
}

func requestUserAdmin(options OptionsValues, globalOptions OptionsValues) (err error) {
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
		"user.admin",
		userAdminRequestData{
			Users: ov["Users"].(map[string]bool),
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

	CommandOut.Println(printUsers(users))
	return
}

func responseUserAdmin(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userAdminRequestData
	json.Unmarshal(msg.Data, &data)

	var users []userResponseData
	for userName, setAdmin := range data.Users {
		err = pc.proxy.Registry.SetAdmin(userName, setAdmin)
		if err != nil {
			continue
		}
		userData, _ := pc.proxy.Registry.GetUserByUserName(userName)
		users = append(users, newUserResponseData(pc.proxy.Registry, userData))
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
