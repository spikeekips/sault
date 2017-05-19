package sault

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var hostRemoveOptionsTemplate = OptionsTemplate{
	Name:      "remove",
	Help:      "remove host",
	Usage:     "[flags] <hostName> [<hostName>...]",
	ParseFunc: parseHostRemoveOptions,
}

func parseHostRemoveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	hostNames := op.FlagSet.Args()
	if len(hostNames) < 1 {
		return fmt.Errorf("hostName is missing")
	}

	{
		var names []string
		for _, hostName := range hostNames {
			if !CheckHostName(hostName) {
				return fmt.Errorf("invalid hostName, '%s'", hostName)
			}
			names = append(names, hostName)
		}

		op.Extra["Hosts"] = names
	}

	return nil
}

func requestHostRemove(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	var hosts []string
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		signer,
		"host.remove",
		hostRemoveRequestData{Hosts: ov["Hosts"].([]string)},
		&hosts,
	)
	if err != nil {
		return
	}
	if response.Error != nil {
		err = response.Error
		return
	}

	if len(hosts) < 1 {
		err = errors.New("no hosts removed")
		return
	}

	CommandOut.Printf("hosts, %s was removed", hosts)
	return
}

func responseHostRemove(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	var hosts []string
	for _, hostName := range data.Hosts {
		err = pc.proxy.Registry.RemoveHost(hostName)
		if err != nil {
			log.Error(err)
			continue
		}
		hosts = append(hosts, hostName)
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var response []byte
	response, err = newResponseMsg(
		hosts,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
