package sault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

type FlagPublicKey string

func (f *FlagPublicKey) String() string {
	return string(*f)
}

func (f *FlagPublicKey) Set(v string) error {
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

	*f = FlagPublicKey(v)

	return nil
}

var UserGetOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name:  "get",
	Help:  "get user",
	Usage: "[flags] <userName>",
	Options: []OptionTemplate{
		AtOptionTemplate,
		POptionTemplate,
		OptionTemplate{
			Name:      "PublicKey",
			Help:      "find user by public key; you can find user without userName",
			ValueType: &struct{ Type FlagPublicKey }{FlagPublicKey("")},
		},
	},
	ParseFunc: ParseUserGetOptions,
}

func ParseUserGetOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	values := op.Values(false)
	publicKeyFile := string(*values["Options"].(OptionsValues)["PublicKey"].(*FlagPublicKey))

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

func RequestUserGet(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
	publicKeyString := ov["publicKeyString"].(string)

	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"user.get",
			UserGetRequestData{
				UserName:  userName,
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

func ResponseUserGet(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data UserGetRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to get user data: %v", data)
	if data.UserName == "" && data.PublicKey == "" {
		err = fmt.Errorf("empty request: %v", data)
		log.Error(err)
		channel.Write(ToResponse(nil, err))
		return
	}

	var userData UserRegistryData
	if data.UserName != "" {
		userData, err = pc.proxy.Registry.GetUserByUserName(data.UserName)
		if err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}
	if data.PublicKey != "" {
		var publicKey saultSsh.PublicKey
		publicKey, err = ParsePublicKeyFromString(data.PublicKey)
		if err != nil {
			log.Errorf("invalid PublicKey received: %v", err)
			channel.Write(ToResponse(nil, err))
			return
		}

		var userDataOfPublicKey UserRegistryData
		userDataOfPublicKey, err = pc.proxy.Registry.GetUserByPublicKey(publicKey)
		if userData.User != "" && userData.User != userDataOfPublicKey.User {
			err = errors.New("user not found")
			channel.Write(ToResponse(nil, err))
			return
		}
		userData = userDataOfPublicKey
	}

	if err != nil {
		log.Errorf("failed to get user: %v", err)
		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(NewUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
