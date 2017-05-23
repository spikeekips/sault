package sault

import (
	"github.com/spikeekips/sault/ssh"
)

var reloadConfigOptionsTemplate = OptionsTemplate{
	Name:      "config",
	Help:      "reload config from source",
	Usage:     "[flags]",
	ParseFunc: parseReloadConfigOptions,
	//Description: ,
}

func parseReloadConfigOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestReloadConfig(options OptionsValues, globalOptions OptionsValues) (err error) {
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
		"server.reload.config",
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

	CommandOut.Println("config was successfully reloaded")
	return
}

func responseReloadConfig(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	newConfig, err := loadConfig(pc.proxy.Config.args)
	if err != nil {
		return
	}

	pc.proxy.Config = newConfig

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
