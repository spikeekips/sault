package sault

import (
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var hostListOptionsTemplate = OptionsTemplate{
	Name:      "list",
	Help:      "get hosts",
	Usage:     "[flags]",
	ParseFunc: parseHostListOptions,
}

func parseHostListOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestHostList(options OptionsValues, globalOptions OptionsValues) (err error) {
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	var response *responseMsg
	var hostList map[string]hostRegistryData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		address,
		"host.list",
		nil,
		&hostList,
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

	hostsPrinted := []string{}
	for _, hostData := range hostList {
		hostsPrinted = append(
			hostsPrinted,
			printHost(saultServerHostName, saultServerPort, hostData),
		)
	}

	var result string
	result, err = ExecuteCommonTemplate(`
{{ $length := len .hostList }}
{{ if ne $length 0 }}{{ .line}}
{{ .hostsPrinted | escape }}
{{ .line}}
found {{ $length }} hosts
{{ else }}
no hosts
{{ end }}
`,
		map[string]interface{}{
			"hostList":     hostList,
			"hostsPrinted": strings.Join(hostsPrinted, "\n\n"),
		},
	)
	if err != nil {
		return
	}
	CommandOut.Println(strings.TrimSpace(result))

	return
}

func responseHostList(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var response []byte
	response, err = newResponseMsg(
		pc.proxy.Registry.GetHosts(activeFilterAll),
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
