package sault

import (
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var whoAmIOptionsTemplate = OptionsTemplate{
	Name:      "whoami",
	Help:      "show mine",
	Usage:     "[flags]",
	ParseFunc: parseWhoAmIOptions,
}

func parseWhoAmIOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestWhoAmI(options OptionsValues, globalOptions OptionsValues) (err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	var response *responseMsg
	var data userResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		clientPublicKey,
		"whoami",
		nil,
		&data,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	CommandOut.Println(printUser(data) + "\n")
	return
}

func responseWhoAmI(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	data := newUserResponseData(pc.proxy.Registry, pc.userData)
	if pc.clientType == saultClient {
		var response []byte
		response, err = newResponseMsg(
			data,
			commandErrorNone,
			nil,
		).ToJSON()
		if err != nil {
			return
		}

		channel.Write(response)
		return
	}

	fmt.Fprintln(channel, printUser(data))
	return
}
