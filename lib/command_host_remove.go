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

func requestHostRemove(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)
	serverName := gov["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	hostName := ov["HostName"].(string)
	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"host.remove",
			hostRemoveRequestData{Host: hostName},
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

		channel.Write(toResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(nil, nil))
	return
}
