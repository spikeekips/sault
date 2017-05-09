package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var UserAddOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name:      "add",
	Help:      "add user",
	Usage:     "[flags] <userName> <publicKeyFile>",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseUserAddOptions,
}

func ParseUserAddOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 2 {
		return fmt.Errorf("wrong usage")
	}

	userName, publicKeyFile := commandArgs[0], commandArgs[1]

	if !CheckUserName(userName) {
		return fmt.Errorf("invalid userName, `%s`", userName)
	}

	op.Extra["UserName"] = userName

	publicKeyString, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}
	if _, err := ParsePublicKeyFromString(string(publicKeyString)); err != nil {
		return err
	}

	op.Extra["PublicKey"] = string(publicKeyString)

	return nil
}

func RequestUserAdd(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
	publicKeyString := ov["PublicKey"].(string)

	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"user.add",
			UserAddRequestData{
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

	result := FormatResponse(`
{{ .user | escape }}

new user added`,
		map[string]interface{}{
			"user": PrintUser(data),
		},
	)
	fmt.Fprintf(os.Stdout, result)

	exitStatus = 0

	return
}

func ResponseUserAdd(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data UserAddRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to add new user: %v", data)
	userData, err := pc.proxy.Registry.AddUser(data.User, data.PublicKey)
	if err != nil {
		log.Errorf("failed to add user: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(NewUserResponseData(pc.proxy.Registry, userData), nil))
	return
}
