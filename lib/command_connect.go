package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var ConnectOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name:      "connect",
	Help:      "(dis)connect user and host",
	Usage:     "[flags] <userName> [<account>+]<hostName>[-]",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseConnectOptions,
}

func ParseConnectOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 2 {
		return fmt.Errorf("wrong usage")
	}

	userName, accountAndHostName := commandArgs[0], commandArgs[1]

	var disconnect bool
	if regexp.MustCompile(`\-$`).FindString(accountAndHostName) == "" {
		disconnect = false
	} else {
		accountAndHostName = accountAndHostName[0 : len(accountAndHostName)-1]
		disconnect = true
	}
	op.Extra["Disconnect"] = disconnect

	{
		if !CheckUserName(userName) {
			return fmt.Errorf("invalid userName, `%s`", userName)
		}

		op.Extra["UserName"] = userName
	}
	{
		account, hostName, err := ParseAccountName(accountAndHostName)
		if err != nil {
			return fmt.Errorf("invalid [<account>@]<hostName>: %v", err)
		}
		op.Extra["TargetAccount"] = account
		op.Extra["HostName"] = hostName
	}

	return nil
}

func RequestConnect(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	serverName := options["SaultServerName"].(string)
	address := options["SaultServerAddress"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	disconnect := options["Disconnect"].(bool)
	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"connect",
			ConnectRequestData{
				Host:          options["HostName"].(string),
				User:          options["UserName"].(string),
				TargetAccount: options["TargetAccount"].(string),
				Disconnect:    disconnect,
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

func ResponseConnect(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data ConnectRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to connect user and host: %v", data)

	if data.TargetAccount == "" {
		if data.Disconnect {
			err = pc.proxy.Registry.DisconnectAll(data.Host, data.User)
		} else {
			err = pc.proxy.Registry.ConnectAll(data.Host, data.User)
		}
	} else {
		if data.Disconnect {
			err = pc.proxy.Registry.Disconnect(
				data.Host,
				data.User,
				[]string{data.TargetAccount},
			)
		} else {
			err = pc.proxy.Registry.Connect(
				data.Host,
				data.User,
				[]string{data.TargetAccount},
			)
		}
	}
	if err != nil {
		log.Errorf("failed to connect: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)
	channel.Write(ToResponse(NewUserResponseData(pc.proxy.Registry, userData), nil))

	return
}
