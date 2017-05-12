package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/spikeekips/sault/ssh"
)

var hostActiveOptionsTemplate = OptionsTemplate{
	Name: "active",
	Help: "set host active or not",
	Description: `
The deactivated host will be not allowed to be authenticated. The difference with "host remove" is, the "host remove" will remove host data, but the data of the deactivated host will be kept, so the *deactivating* host will be safer way to manage hosts.

To active "spikeekips",
{{ "$ sault host active server0" | magenta }}

To deactivate "spikeekips",
{{ "$ sault host active server0-" | magenta }}
	`,
	Usage:     "[flags] <hostName>[-]",
	ParseFunc: parseHostActiveOptions,
}

func parseHostActiveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
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

func requestHostActive(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
	active := ov["Active"].(bool)

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"host.active",
			hostActiveRequestData{Host: hostName, Active: active},
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

	var hostData hostRegistryData
	if err := json.Unmarshal(rm.Result, &hostData); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostData, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	fmt.Fprintf(os.Stdout, printHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func responseHostActive(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostActiveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to active: %v", data)
	err = pc.proxy.Registry.SetHostActive(data.Host, data.Active)
	if err != nil {
		log.Errorf("failed to set active: %v", err)

		channel.Write(toResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	var hostData hostRegistryData
	hostData, _ = pc.proxy.Registry.GetHostByHostName(data.Host)

	channel.Write(toResponse(hostData, nil))
	return
}
