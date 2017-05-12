package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var hostListOptionsTemplate = OptionsTemplate{
	Name:      "list",
	Help:      "get hosts",
	Usage:     "[flags]",
	Options:   []OptionTemplate{atOptionTemplate, pOptionTemplate},
	ParseFunc: parseHostListOptions,
}

func parseHostListOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestHostList(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		output, exitStatus, err = runCommand(connection, &commandMsg{Command: "host.list"})
		if err != nil {
			log.Error(err)
			return
		}
	}

	var rm responseMsg
	if err := saultSsh.Unmarshal(output, &rm); err != nil {
		log.Errorf("got invalid response: %v", err)
		exitStatus = 1
		return
	}

	if rm.Error != "" {
		log.Errorf("%s", rm.Error)
		exitStatus = 1

		return
	}

	var hostList map[string]hostRegistryData
	if err := json.Unmarshal(rm.Result, &hostList); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostList, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := ov["SaultServerHostName"].(string)

	hostsPrinted := []string{}
	for _, hostData := range hostList {
		hostsPrinted = append(
			hostsPrinted,
			printHost(saultServerHostName, saultServerPort, hostData),
		)
	}

	result, err := ExecuteCommonTemplate(`
{{ $length := len .hostList }}
{{ if ne $length 0 }}
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
		exitStatus = 1
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
