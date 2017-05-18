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
The deactivated host will be not allowed to be authenticated. The difference with "host remove" is, the "host remove" will remove host data, but the data of the deactivated host will be kept, so the *deactivating* host will be safer way to manage hosts.

To active "server0",
{{ "$ sault host active server0" | magenta }}

To deactivate "server0", just add "{{ "-" | yellow }}" in the end of host name,
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

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	var response *responseMsg
	var hosts []hostRegistryData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		address,
		clientPublicKey,
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
