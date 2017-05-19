package sault

import (
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var showConfigOptionsTemplate = OptionsTemplate{
	Name:      "config",
	Help:      "show server configuration",
	Usage:     "[flags]",
	ParseFunc: parseShowConfigOptions,
}

func parseShowConfigOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestShowConfig(options OptionsValues, globalOptions OptionsValues) (err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	var response *responseMsg
	var data serverConfigResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		signer,
		"server.config",
		nil,
		&data,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	result, _ := ExecuteCommonTemplate(`
{{ .line }}
{{ .config | escape }}
{{ .line }}
	`,
		map[string]interface{}{
			"config": data.Config,
		},
	)

	CommandOut.Println(strings.TrimSpace(result))
	return
}

func responseShowConfig(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var response []byte
	response, err = newResponseMsg(
		serverConfigResponseData{Config: pc.proxy.Config.String()},
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
