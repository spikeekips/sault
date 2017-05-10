package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var hostActiveOptionsTemplate = OptionsTemplate{
	Name: "active",
	Help: "set host active or not",
	Description: `
The deactivated host will be not allowed to be authenticated. The difference with "host remove" is, the "host remove" will remove host data, but the data of the deactivated host will be kept, so the *deactivating* host will be safer way to manage hosts.

To active "spikeekips",
$ sault host active server0

To deactivate "spikeekips",
$ sault host active server0-
	`,
	Usage:     "[flags] <hostName>[-]",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseHostActiveOptions,
}

func ParseHostActiveOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("<hostName> is missing")
	}

	hostName := args[0]

	var active bool
	if regexp.MustCompile(`\-$`).FindString(hostName) == "" {
		active = true
	} else {
		hostName = hostName[0 : len(hostName)-1]
		active = false
	}

	op.Extra["HostName"] = hostName
	op.Extra["Active"] = active

	return nil
}

func RequestHostActive(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
	active := ov["Active"].(bool)

	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"host.active",
			HostActiveRequestData{Host: hostName, Active: active},
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

	var hostData HostRegistryData
	if err := json.Unmarshal(responseMsg.Result, &hostData); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostData, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := ov["SaultServerHostName"].(string)

	fmt.Fprintf(os.Stdout, PrintHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func ResponseHostActive(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data HostActiveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to active: %v", data)
	err = pc.proxy.Registry.SetHostActive(data.Host, data.Active)
	if err != nil {
		log.Errorf("failed to set active: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	var hostData HostRegistryData
	hostData, _ = pc.proxy.Registry.GetHostByHostName(data.Host)

	channel.Write(ToResponse(hostData, nil))
	return
}
