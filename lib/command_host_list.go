package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var HostListOptionsTemplate OptionsTemplate

func ParseHostListOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func RequestHostList(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		output, exitStatus, err = runCommand(connection, &CommandMsg{Command: "host.list"})
		if err != nil {
			log.Error(err)
			return
		}
	}

	var responseMsg ResponseMsg
	if err := saultSsh.Unmarshal(output, &responseMsg); err != nil {
		log.Errorf("got invalid response: %v", err)
		exitStatus = 1
		return
	}

	if responseMsg.Error != "" {
		log.Errorf("%s", responseMsg.Error)
		exitStatus = 1

		return
	}

	var hostList map[string]HostRegistryData
	if err := json.Unmarshal(responseMsg.Result, &hostList); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostList, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := ov["SaultServerHostName"].(string)

	hostsPrinted := []string{}
	for _, hostData := range hostList {
		hostsPrinted = append(
			hostsPrinted,
			PrintHost(saultServerHostName, saultServerPort, hostData),
		)
	}

	result := FormatResponse(`
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
	fmt.Fprintf(os.Stdout, result)

	exitStatus = 0

	return
}

func ResponseHostList(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	channel.Write(ToResponse(pc.proxy.Registry.GetHosts(ActiveFilterAll), nil))
	return
}
