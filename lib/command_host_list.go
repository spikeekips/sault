package sault

import (
	"fmt"
	"os"
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

func requestHostList(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	var hostList map[string]hostRegistryData
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		address,
		"host.list",
		nil,
		&hostList,
	)
	if err != nil {
		log.Error(err)
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
		log.Error(err)
		return
	}
	fmt.Fprintf(os.Stdout, strings.TrimSpace(result))

	exitStatus = 0

	return
}

func responseHostList(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	channel.Write(toResponse(pc.proxy.Registry.GetHosts(activeFilterAll), nil))
	return
}
