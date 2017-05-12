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
	Options:   []OptionTemplate{atOptionTemplate, pOptionTemplate},
	ParseFunc: parseShowConfigOptions,
}

func parseShowConfigOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestShowConfig(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)
	address := ov["SaultServerAddress"].(string)
	serverName := ov["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	var output []byte
	{
		var err error
		log.Debug("msg sent")
		output, exitStatus, err = runCommand(connection, &commandMsg{Command: "server.config"})
		if err != nil {
			log.Error(err)
			return
		}
	}

	result, _ := ExecuteCommonTemplate(`
{{ .line }}
{{ .config | escape }}
{{ .line }}
json format config.
	`,
		map[string]interface{}{
			"config": string(output),
		},
	)
	fmt.Println(strings.TrimSpace(result))

	exitStatus = 0

	return
}

func responseShowConfig(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	jsoned := pc.proxy.Config.ToJSON()
	channel.Write([]byte(jsoned))
	return
}
