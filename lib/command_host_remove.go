package sault

import (
	"encoding/json"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var hostRemoveOptionsTemplate = OptionsTemplate{
	Name:      "remove",
	Help:      "remove host",
	Usage:     "[flags] <hostName>",
	ParseFunc: parseHostRemoveOptions,
}

func parseHostRemoveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 1 {
		return fmt.Errorf("wrong usage")
	}

	{
		hostName := commandArgs[0]
		if !CheckHostName(hostName) {
			return fmt.Errorf("invalid hostName, `%s`", hostName)
		}

		op.Extra["HostName"] = hostName
	}

	return nil
}

func requestHostRemove(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	hostName := ov["HostName"].(string)

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	var response *responseMsg
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		clientPublicKey,
		"host.remove",
		hostRemoveRequestData{Host: hostName},
		nil,
	)
	if err != nil {
		return
	}
	if response.Error != nil {
		err = response.Error
		return
	}

	CommandOut.Printf("host, `%s` was removed", hostName)

	return
}

func responseHostRemove(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	err = pc.proxy.Registry.RemoveHost(data.Host)
	if err != nil {
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var response []byte
	response, err = newResponseMsg(
		nil,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
