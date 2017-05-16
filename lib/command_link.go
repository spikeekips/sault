package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/spikeekips/sault/ssh"
)

var linkOptionsTemplate = OptionsTemplate{
	Name: "link",
	Help: "(un)link user and host",
	Description: `
	`,
	Usage:     "[flags] <userName> [<account>+]<hostName>[-]",
	ParseFunc: parseLinkOptions,
}

func parseLinkOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 2 {
		return fmt.Errorf("wrong usage")
	}

	userName, accountAndHostName := commandArgs[0], commandArgs[1]

	var unlink bool
	if regexp.MustCompile(`\-$`).FindString(accountAndHostName) == "" {
		unlink = false
	} else {
		accountAndHostName = accountAndHostName[0 : len(accountAndHostName)-1]
		unlink = true
	}
	op.Extra["Unlink"] = unlink

	{
		if !CheckUserName(userName) {
			return fmt.Errorf("invalid userName, `%s`", userName)
		}

		op.Extra["UserName"] = userName
	}
	{
		account, requestLink, err := ParseAccountName(accountAndHostName)
		if err != nil {
			return fmt.Errorf("invalid [<account>@]<hostName>: %v", err)
		}
		op.Extra["TargetAccount"] = account
		op.Extra["HostName"] = requestLink
	}

	return nil
}

func requestLink(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	serverName := gov["SaultServerName"].(string)
	address := gov["SaultServerAddress"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	unlink := ov["Unlink"].(bool)
	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"user.link",
			linkRequestData{
				Host:          ov["HostName"].(string),
				User:          ov["UserName"].(string),
				TargetAccount: ov["TargetAccount"].(string),
				Unlink:        unlink,
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
		log.Errorf("failed to unmarshal ResponseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	fmt.Fprintf(os.Stdout, printUser(data))

	exitStatus = 0

	return
}

func responseLink(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data linkRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to (un)link user and host: %v", data)

	if data.TargetAccount == "" {
		if data.Unlink {
			err = pc.proxy.Registry.UnlinkAll(data.Host, data.User)
		} else {
			err = pc.proxy.Registry.LinkAll(data.Host, data.User)
		}
	} else {
		if data.Unlink {
			err = pc.proxy.Registry.Unlink(
				data.Host,
				data.User,
				[]string{data.TargetAccount},
			)
		} else {
			err = pc.proxy.Registry.Link(
				data.Host,
				data.User,
				[]string{data.TargetAccount},
			)
		}
	}
	if err != nil {
		log.Errorf("failed to link: %v", err)

		channel.Write(toResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)
	channel.Write(toResponse(newUserResponseData(pc.proxy.Registry, userData), nil))

	return
}
