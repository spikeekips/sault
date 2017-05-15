package sault

import (
	"encoding/json"
	"fmt"
	"os"
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

func requestHostGet(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)
	serverName := gov["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"host.get",
			hostGetRequestData{
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

	var hostData hostRegistryData
	if err := json.Unmarshal(rm.Result, &hostData); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostData, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	fmt.Fprintf(os.Stdout, printHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func responseHostGet(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostGetRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to get host: %v", data)
	hostData, err := pc.proxy.Registry.GetHostByHostName(data.Host)
	if err != nil {
		log.Errorf("failed to get host: %v", err)

		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(hostData, nil))
	return
}

func printHost(saultServerHostName string, saultServerPort uint64, hostData hostRegistryData) string {
	result, err := ExecuteCommonTemplate(`
{{ "Host:"|green }}             {{ .host.Host | green }} {{ if .host.Deactivated }}{{ "(deactivated)" | red }}{{ end }}
Address:          {{ .host.DefaultAccount }}@{{ .host.Address }}:{{ .host.Port }}
Accounts:         [ {{ .accounts }} ]
ClientPrivateKey: {{ $l := len .clientPrivateKey }}{{ if eq $l 0 }}-{{ else }}
{{ .clientPrivateKey | escape }}{{end}}
Connect: {{ .Connect | magenta }}
`,
		map[string]interface{}{
			"host":             hostData,
			"accounts":         strings.Join(hostData.Accounts, " "),
			"clientPrivateKey": strings.TrimSpace(string(hostData.ClientPrivateKey)),
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
		log.Errorf("failed to templating: %v", err)
		return ""
	}

	return strings.TrimSpace(result)
}
