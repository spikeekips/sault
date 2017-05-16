package sault

import (
	"encoding/json"
	"fmt"
	"os"

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

func requestHostRemove(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	hostName := ov["HostName"].(string)
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"host.remove",
		hostRemoveRequestData{Host: hostName},
		nil,
	)
	if err != nil {
		log.Error(err)
		return
	}

	fmt.Fprintf(os.Stdout, "host, `%s` was removed", hostName)

	exitStatus = 0

	return
}

func responseHostRemove(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to remove host: %v", data)
	err = pc.proxy.Registry.RemoveHost(data.Host)
	if err != nil {
		log.Errorf("failed to remove host: %v", err)
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	channel.Write(toResponse(nil, nil))
	return
}
