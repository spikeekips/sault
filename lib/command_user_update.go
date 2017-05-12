package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var userUpdateOptionsTemplate = OptionsTemplate{
	Name:      "update",
	Help:      "update user",
	Usage:     "[flags] <userName> [userName <new userName>] [publicKey <publicKeyFile>]",
	Options:   []OptionTemplate{atOptionTemplate, pOptionTemplate},
	ParseFunc: parseUserUpdateOptions,
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
		return fmt.Errorf("invalid userName, `%s`", userName)
	}

	op.Extra["NewUserName"] = ""
	if newUserName != "" {
		if !CheckUserName(newUserName) {
			return fmt.Errorf("invalid new userName, `%s`", newUserName)
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

func requestUserUpdate(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
	newUserName := ov["NewUserName"].(string)
	newPublicKeyString := ov["NewPublicKey"].(string)

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"user.update",
			userUpdateRequestData{
				User:         userName,
				NewUserName:  newUserName,
				NewPublicKey: newPublicKeyString,
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

func responseUserUpdate(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userUpdateRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to update user: %v", data)
	if !pc.userData.IsAdmin && !pc.proxy.Config.Server.AllowUserCanUpdate {
		err = fmt.Errorf("not allowed to update publicKey")
		channel.Write(toResponse(nil, err))
		return
	}

	var userData UserRegistryData
	if data.NewUserName != "" {
		if userData, err = pc.proxy.Registry.UpdateUserName(data.User, data.NewUserName); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}

	if data.NewPublicKey != "" {
		if _, err = ParsePublicKeyFromString(data.NewPublicKey); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}

		if userData, err = pc.proxy.Registry.UpdateUserPublicKey(data.User, data.NewPublicKey); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(newUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
