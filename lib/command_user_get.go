package sault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spikeekips/sault/ssh"
)

var userGetOptionsTemplate = OptionsTemplate{
	Name:  "get",
	Help:  "get user",
	Usage: "[flags] [<userName>]",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:      "PublicKey",
			Help:      "find user by public key; you can find user without userName",
			ValueType: &struct{ Type flagPublicKey }{flagPublicKey("")},
		},
	},
	ParseFunc: parseUserGetOptions,
}

type flagPublicKey string

func (f *flagPublicKey) String() string {
	return string(*f)
}

func (f *flagPublicKey) Set(v string) error {
	if _, err := os.Stat(v); err != nil {
		return err
	}

	b, err := ioutil.ReadFile(v)
	if err != nil {
		return err
	}

	{
		_, err := ParsePublicKeyFromString(string(b))
		if err != nil {
			return err
		}
	}

	*f = flagPublicKey(v)

	return nil
}

func parseUserGetOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	values := op.Values(false)
	publicKeyFile := string(*values["Options"].(OptionsValues)["PublicKey"].(*flagPublicKey))

	commandArgs := op.FlagSet.Args()
	if publicKeyFile == "" && len(commandArgs) != 1 {
		return fmt.Errorf("wrong usage")
	}

	op.Extra["UserName"] = ""
	if len(commandArgs) == 1 {
		userName := commandArgs[0]
		if !CheckUserName(userName) {
			return fmt.Errorf("invalid userName, `%s`", userName)
		}
		op.Extra["UserName"] = userName
	}

	op.Extra["publicKeyString"] = ""
	if publicKeyFile != "" {
		b, _ := ioutil.ReadFile(publicKeyFile)
		op.Extra["publicKeyString"] = string(b)
	}

	return nil
}

func requestUserGet(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	userName := ov["UserName"].(string)
	publicKeyString := ov["publicKeyString"].(string)

	var response *responseMsg
	var data userResponseData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.get",
		userGetRequestData{
			User:      userName,
			PublicKey: publicKeyString,
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

func responseUserGet(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userGetRequestData
	json.Unmarshal(msg.Data, &data)

	if data.User == "" && data.PublicKey == "" {
		err = fmt.Errorf("empty request: %v", data)
		return
	}

	var userData UserRegistryData
	if data.User != "" {
		userData, err = pc.proxy.Registry.GetUserByUserName(data.User)
		if err != nil {
			return
		}
	}
	if data.PublicKey != "" {
		var publicKey saultSsh.PublicKey
		publicKey, err = ParsePublicKeyFromString(data.PublicKey)
		if err != nil {
			log.Errorf("invalid PublicKey received: %v", err)
			return
		}

		var userDataOfPublicKey UserRegistryData
		userDataOfPublicKey, err = pc.proxy.Registry.GetUserByPublicKey(publicKey)
		if userData.User != "" && userData.User != userDataOfPublicKey.User {
			err = errors.New("user not found")
			return
		}
		userData = userDataOfPublicKey
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
