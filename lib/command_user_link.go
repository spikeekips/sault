package sault

import (
	"encoding/json"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var linkOptionsTemplate = OptionsTemplate{
	Name:        "link",
	Help:        "(un)link user and hosts",
	Usage:       "[flags] <userName> [<account>+]<hostName>[-] [[<account>+]<hostName>[-]...]",
	ParseFunc:   parseLinkOptions,
	Description: descriptionUserLink,
}

func parseLinkOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) < 2 {
		return fmt.Errorf("wrong usage")
	}

	userName := commandArgs[0]
	{
		if !CheckUserName(userName) {
			return fmt.Errorf("invalid userName, `%s` found", userName)
		}

		op.Extra["UserName"] = userName
	}

	hostNames := commandArgs[1:]
	names := map[string]bool{}
	for _, hostName := range hostNames {
		name, link := parseNameActive(hostName)

		account, hostName, err := ParseAccountName(name)
		if err != nil {
			return fmt.Errorf("invalid [<account>+]<hostName>, '%s'", name)
		}
		names[fmt.Sprintf("%s@%s", account, hostName)] = link
	}

	op.Extra["Links"] = names

	return nil
}

func requestLink(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	var users userResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		signer,
		"user.link",
		linkRequestData{
			User:  ov["UserName"].(string),
			Links: ov["Links"].(map[string]bool),
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

	CommandOut.Println(printUser(users))
	return
}

func responseLink(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data linkRequestData
	json.Unmarshal(msg.Data, &data)

	for k, link := range data.Links {
		account, hostName, _ := ParseHostAccount(k)
		if account == "" {
			if !link {
				err = pc.proxy.Registry.UnlinkAll(hostName, data.User)
			} else {
				err = pc.proxy.Registry.LinkAll(hostName, data.User)
			}
		} else {
			if !link {
				err = pc.proxy.Registry.Unlink(
					hostName,
					data.User,
					[]string{account},
				)
			} else {
				err = pc.proxy.Registry.Link(
					hostName,
					data.User,
					[]string{account},
				)
			}
		}
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
