package sault

import (
	"github.com/spikeekips/sault/ssh"
)

var reloadRegistryOptionsTemplate = OptionsTemplate{
	Name:      "registry",
	Help:      "reload registry from source",
	Usage:     "[flags]",
	ParseFunc: parseReloadRegistryOptions,
	//Description: ,
}

func parseReloadRegistryOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestReloadRegistry(options OptionsValues, globalOptions OptionsValues) (err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		signer,
		"server.reload.registry",
		nil,
		nil,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	CommandOut.Println("registry was successfully reloaded")
	return
}

func responseReloadRegistry(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	cs, err := pc.proxy.Config.Registry.GetSource()
	if err != nil {
		return
	}

	var registry *Registry
	registry, err = newRegistry(pc.proxy.Config.Registry.Type, cs, false)
	if err != nil {
		return
	}
	pc.proxy.Registry = registry

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
