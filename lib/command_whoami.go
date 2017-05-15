package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var whoAmIOptionsTemplate = OptionsTemplate{
	Name:      "whoami",
	Help:      "show mine",
	Usage:     "[flags]",
	ParseFunc: parseWhoAmIOptions,
}

func parseWhoAmIOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestWhoAmI(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		log.Debug("msg sent")
		output, exitStatus, err = runCommand(connection, &commandMsg{Command: "whoami"})
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

	var data userResponseData
	if err := json.Unmarshal(rm.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	fmt.Fprintf(os.Stdout, printUser(data)+"\n")
	exitStatus = 0

	return
}

func responseWhoAmI(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	data := newUserResponseData(pc.proxy.Registry, pc.userData)
	if pc.clientType == saultClient {
		channel.Write(toResponse(data, nil))
		return
	}

	result := printUser(data)
	fmt.Fprintf(channel, result+"\n")

	return
}

func printUser(data userResponseData) string {
	result, err := ExecuteCommonTemplate(`
{{ "User:"|yellow }}      {{ .user.User | yellow }} {{ if .user.IsAdmin }} {{ "(admin)" | green }} {{ end }} {{ if .user.Deactivated }}{{ "(deactivated)" | red }}{{ end }}
PublicKey: {{ .user.PublicKey | escape }}
{{ $length := len .linked }}Linked hosts and it's accounts: {{ if eq $length 0 }}-{{ else }}
{{ range $key, $accounts := .linked }}{{ $key | escape }} {{ $accounts }}
{{ end }}{{ end }}
`,
		map[string]interface{}{
			"user":   data.UserData,
			"linked": data.Linked,
		},
	)
	if err != nil {
		log.Errorf("failed to templating: %v", err)
		return ""
	}
	return strings.TrimSpace(result)
}
