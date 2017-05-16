package sault

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/spikeekips/sault/ssh"
)

var hostActiveOptionsTemplate = OptionsTemplate{
	Name: "active",
	Help: "set host active or not",
	Description: `
The deactivated host will be not allowed to be authenticated. The difference with "host remove" is, the "host remove" will remove host data, but the data of the deactivated host will be kept, so the *deactivating* host will be safer way to manage hosts.

To active "server0",
{{ "$ sault host active server0" | magenta }}

To deactivate "server0", just add "{{ "-" | yellow }}" in the end of host name,
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

func requestHostActive(
	options OptionsValues,
	globalOptions OptionsValues,
) (exitStatus int, err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	var hostData hostRegistryData
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		address,
		"host.active",
		hostActiveRequestData{
			Host:   ov["HostName"].(string),
			Active: ov["Active"].(bool),
		},
		&hostData,
	)
	if err != nil {
		log.Error(err)
		return
	}

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	CommandOut.Println(printHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func responseHostActive(
	pc *proxyConnection,
	channel saultSsh.Channel,
	msg commandMsg,
) (exitStatus uint32, err error) {
	var data hostActiveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to active: %v", data)
	err = pc.proxy.Registry.SetHostActive(data.Host, data.Active)
	if err != nil {
		log.Errorf("failed to set active: %v", err)
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var hostData hostRegistryData
	hostData, _ = pc.proxy.Registry.GetHostByHostName(data.Host)

	channel.Write(toResponse(hostData, nil))
	return
}
