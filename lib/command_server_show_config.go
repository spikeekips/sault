package sault

import (
	"fmt"
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

	var data serverConfigResponseData
	err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"server.config",
		nil,
		&data,
	)
	if err != nil {
		log.Error(err)
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
	fmt.Println(strings.TrimSpace(result))

	return
}

func responseShowConfig(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	data := serverConfigResponseData{Config: pc.proxy.Config.String()}
	channel.Write(toResponse(data, nil))
	return
}
