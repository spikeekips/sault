package sault

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var hostGetOptionsTemplate = OptionsTemplate{
	Name:      "get",
	Help:      "get host",
	Usage:     "[flags] <hostName>",
	ParseFunc: parseHostGetOptions,
}

func parseHostGetOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 1 {
		return fmt.Errorf("wrong usage")
	}

	{
		hostName := commandArgs[0]
		if !CheckHostName(hostName) {
			return fmt.Errorf("invalid hostName, `%s`", hostName)
		}

		op.Extra["HostName"] = hostName
	}

	return nil
}

func requestHostGet(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	var response *responseMsg
	var hostData hostRegistryData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		address,
		"host.get",
		hostGetRequestData{
			Host: ov["HostName"].(string),
		},
		&hostData,
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

	CommandOut.Println(printHost(saultServerHostName, saultServerPort, hostData))

	return
}

func responseHostGet(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostGetRequestData
	json.Unmarshal(msg.Data, &data)

	hostData, err := pc.proxy.Registry.GetHostByHostName(data.Host)
	if err != nil {
		return
	}

	var response []byte
	response, err = newResponseMsg(
		hostData,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return
}

func printHost(saultServerHostName string, saultServerPort uint64, hostData hostRegistryData) string {
	result, err := ExecuteCommonTemplate(`
{{ "Host:"|green }}      {{ .host.Host | green }} {{ if .host.Deactivated }}{{ "(deactivated)" | red }}{{ end }}
Address:   {{ .host.DefaultAccount }}@{{ .host.Address }}:{{ .host.Port }}
Accounts:  [ {{ .accounts }} ]
Connect:   {{ .Connect | magenta }}
`,
		map[string]interface{}{
			"host":     hostData,
			"accounts": strings.Join(hostData.Accounts, " "),
			"Connect": fmt.Sprintf(
				`$ ssh -p %d %s+%s@%s`,
				saultServerPort,
				hostData.DefaultAccount,
				hostData.Host,
				saultServerHostName,
			),
		},
	)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(result)
}
