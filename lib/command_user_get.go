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
	Usage: "[flags] <userName>",
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

func requestUserGet(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)
	serverName := gov["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	userName := ov["UserName"].(string)
	publicKeyString := ov["publicKeyString"].(string)

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"user.get",
			userGetRequestData{
				User:      userName,
				PublicKey: publicKeyString,
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

func responseUserGet(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userGetRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to get user data: %v", data)
	if data.User == "" && data.PublicKey == "" {
		err = fmt.Errorf("empty request: %v", data)
		log.Error(err)
		channel.Write(toResponse(nil, err))
		return
	}

	var userData UserRegistryData
	if data.User != "" {
		userData, err = pc.proxy.Registry.GetUserByUserName(data.User)
		if err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}
	if data.PublicKey != "" {
		var publicKey saultSsh.PublicKey
		publicKey, err = ParsePublicKeyFromString(data.PublicKey)
		if err != nil {
			log.Errorf("invalid PublicKey received: %v", err)
			channel.Write(toResponse(nil, err))
			return
		}

		var userDataOfPublicKey UserRegistryData
		userDataOfPublicKey, err = pc.proxy.Registry.GetUserByPublicKey(publicKey)
		if userData.User != "" && userData.User != userDataOfPublicKey.User {
			err = errors.New("user not found")
			channel.Write(toResponse(nil, err))
			return
		}
		userData = userDataOfPublicKey
	}

	if err != nil {
		log.Errorf("failed to get user: %v", err)
		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(newUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
