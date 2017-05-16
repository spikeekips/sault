package sault

import (
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

func requestWhoAmI(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var data userResponseData
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"whoami",
		nil,
		&data,
	)
	if err != nil {
		log.Error(err)
		return
	}

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
{{ range $key, $accounts := .linked }} - {{ $key | escape }}: {{ $accounts | join}}
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
