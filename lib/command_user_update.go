package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var userUpdateOptionsTemplate = OptionsTemplate{
	Name:        "update",
	Help:        "update user",
	Usage:       "[flags] <userName> [userName <new userName>] [publicKey <publicKeyFile>]",
	ParseFunc:   parseUserUpdateOptions,
	Description: descriptionUserUpdate,
}

func parseUserUpdateOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()

	var userName, newUserName, newPublicKeyFile string
	var argsSet [][]string

	if len(commandArgs) == 3 {
		argsSet = append(argsSet, commandArgs[1:])
	} else if len(commandArgs) == 5 {
		argsSet = append(argsSet, commandArgs[1:3], commandArgs[3:])
	} else {
		return fmt.Errorf("wrong usage")
	}
	userName = commandArgs[0]
	op.Extra["UserName"] = userName

	for _, s := range argsSet {
		if s[0] == "userName" {
			newUserName = s[1]
		} else if s[0] == "publicKey" {
			newPublicKeyFile = s[1]
		} else {
			return fmt.Errorf("wrong usage")
		}
	}

	if strings.ToLower(userName) == "username" || !CheckUserName(userName) {
		return fmt.Errorf("invalid userName, '%s'", userName)
	}

	op.Extra["NewUserName"] = ""
	if newUserName != "" {
		if !CheckUserName(newUserName) {
			return fmt.Errorf("invalid new userName, '%s'", newUserName)
		}

		op.Extra["NewUserName"] = newUserName
	}

	op.Extra["NewPublicKey"] = ""
	if newPublicKeyFile != "" {
		publicKeyString, err := ioutil.ReadFile(newPublicKeyFile)
		if err != nil {
			return err
		}
		if _, err := ParsePublicKeyFromString(string(publicKeyString)); err != nil {
			return err
		}

		op.Extra["NewPublicKey"] = string(publicKeyString)
	}

	return nil
}

func requestUserUpdate(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	var data userResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		signer,
		"user.update",
		userUpdateRequestData{
			User:         ov["UserName"].(string),
			NewUserName:  ov["NewUserName"].(string),
			NewPublicKey: ov["NewPublicKey"].(string),
		},
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

func responseUserUpdate(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userUpdateRequestData
	json.Unmarshal(msg.Data, &data)

	if !pc.userData.IsAdmin && !pc.proxy.Config.Server.AllowUserCanUpdate {
		err = fmt.Errorf("updating publicKey; permission denied")
		return
	}

	var userData UserRegistryData
	if data.NewUserName != "" {
		if userData, err = pc.proxy.Registry.UpdateUserName(data.User, data.NewUserName); err != nil {
			return
		}
	}

	if data.NewPublicKey != "" {
		if _, err = ParsePublicKeyFromString(data.NewPublicKey); err != nil {
			return
		}

		if userData, err = pc.proxy.Registry.UpdateUserPublicKey(data.User, data.NewPublicKey); err != nil {
			return
		}
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

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
