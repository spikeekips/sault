package sault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var HostGetOptionsTemplate = OptionsTemplate{
	Name:      "get",
	Help:      "get host",
	Usage:     "[flags] <hostName>",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseHostGetOptions,
}

func ParseHostGetOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
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

func RequestHostGet(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		msg, err := NewCommandMsg(
			"host.get",
			HostGetRequestData{
				Host: ov["HostName"].(string),
			},
		)
		if err != nil {
			log.Errorf("failed to make message: %v", err)
			exitStatus = 1
			return
		}

		log.Debug("msg sent")
		output, exitStatus, err = runCommand(connection, msg)
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

	var hostData HostRegistryData
	if err := json.Unmarshal(responseMsg.Result, &hostData); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostData, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := ov["SaultServerHostName"].(string)

	fmt.Fprintf(os.Stdout, PrintHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func ResponseHostGet(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data HostGetRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to get host: %v", data)
	hostData, err := pc.proxy.Registry.GetHostByHostName(data.Host)
	if err != nil {
		log.Errorf("failed to get host: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(hostData, nil))
	return
}

func PrintHost(saultServerHostName string, saultServerPort uint64, hostData HostRegistryData) string {
	result := FormatResponse(`
{{ "Host:"|green }}             {{ .host.Host | escape | green }} {{ if .host.Deactivated }}{{ "(deactivated)" | red }}{{ end }}
Address:          {{ .host.DefaultAccount }}@{{ .host.Address }}:{{ .host.Port }}
Accounts:         [ {{ .accounts }} ]
ClientPrivateKey: {{ $l := len .clientPrivateKey }}{{ if eq $l 0 }}-{{ else }}
{{ .clientPrivateKey | escape }}{{end}}
Connect: $ {{ .Connect | escape }}
`,
		map[string]interface{}{
			"host":             hostData,
			"accounts":         strings.Join(hostData.Accounts, " "),
			"clientPrivateKey": strings.TrimSpace(string(hostData.ClientPrivateKey)),
			"Connect": fmt.Sprintf(
				`ssh -p %d %s+%s@%s`,
				saultServerPort,
				hostData.DefaultAccount,
				hostData.Host,
				saultServerHostName,
			),
		},
	)

	bw := bytes.NewBuffer([]byte{})
	fmt.Fprintf(bw, result)

	return bw.String()
}
