package sault

import (
	"encoding/json"
	"fmt"
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

func requestLink(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var response *responseMsg
	var data userResponseData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.link",
		linkRequestData{
			Host:          ov["HostName"].(string),
			User:          ov["UserName"].(string),
			TargetAccount: ov["TargetAccount"].(string),
			Unlink:        ov["Unlink"].(bool),
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

func responseLink(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data linkRequestData
	json.Unmarshal(msg.Data, &data)

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
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.GetUserByUserName(data.User)

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
