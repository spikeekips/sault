package sault

import (
	"encoding/json"
	"fmt"

	"github.com/spikeekips/sault/ssh"
)

var hostActiveOptionsTemplate = OptionsTemplate{
	Name: "active",
	Help: "set host active or not",
	Description: `
With {{ "host active" | yellow }} command, you can activate the host or vice versa.

The deactivated host will be not allowed to access. {{ "host remove" | yellow }} will deactivate and also remove host data, but the the deactivated host will keep it's data, so the *deactivating* host will be safer way to manage hosts.

Appending "{{ "-" | yellow }}" to the end of hostName, makes the host to be deactivated.

Activating "server0":
 {{ "$ sault host active server0" | magenta }}

Deactivating "server0":
 {{ "$ sault host active server0-" | magenta }}
	`,
	Usage:     "[flags] <hostName>[-] [<hostName>[-]...]",
	ParseFunc: parseHostActiveOptions,
}

func parseHostActiveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	hostNames := op.FlagSet.Args()
	if len(hostNames) < 1 {
		return fmt.Errorf("hostName is missing")
	}

	names := map[string]bool{}
	for _, h := range hostNames {
		name, active := parseNameActive(h)
		if !CheckHostName(name) {
			return fmt.Errorf("invalid hostName, '%s'", name)
		}
		names[name] = active
	}

	op.Extra["Hosts"] = names

	return nil
}

func requestHostActive(
	options OptionsValues,
	globalOptions OptionsValues,
) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	var hosts []hostRegistryData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		address,
		signer,
		"host.active",
		hostActiveRequestData{
			Hosts: ov["Hosts"].(map[string]bool),
		},
		&hosts,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	CommandOut.Println(printHosts(hosts, saultServerHostName, saultServerPort))
	return
}

func responseHostActive(
	pc *proxyConnection,
	channel saultSsh.Channel,
	msg commandMsg,
) (exitStatus uint32, err error) {
	var data hostActiveRequestData
	json.Unmarshal(msg.Data, &data)

	var hosts []hostRegistryData
	for hostName, active := range data.Hosts {
		err = pc.proxy.Registry.SetHostActive(hostName, active)
		if err != nil {
			log.Error(err)
			continue
		}
		hostData, _ := pc.proxy.Registry.GetHostByHostName(hostName)
		hosts = append(hosts, hostData)
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
