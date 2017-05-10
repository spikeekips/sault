package sault

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var HostRemoveOptionsTemplate OptionsTemplate

func init() {
	HostRemoveOptionsTemplate = OptionsTemplate{
		Name:      "remove",
		Help:      "remove host",
		Usage:     "[flags] <hostName>",
		Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
		ParseFunc: ParseHostRemoveOptions,
	}
}

func ParseHostRemoveOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
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

func RequestHostRemove(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)
	address := ov["SaultServerAddress"].(string)
	serverName := ov["SaultServerName"].(string)

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
		msg, err := NewCommandMsg(
			"host.remove",
			HostRemoveRequestData{Host: hostName},
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

	fmt.Fprintf(os.Stdout, "host, `%s` was removed", hostName)

	exitStatus = 0

	return
}

func ResponseHostRemove(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data HostRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to remove host: %v", data)
	err = pc.proxy.Registry.RemoveHost(data.Host)
	if err != nil {
		log.Errorf("failed to remove host: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(nil, nil))
	return
}
