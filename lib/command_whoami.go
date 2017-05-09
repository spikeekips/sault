package sault

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var WhoAmIOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name:      "whoami",
	Help:      "show mine",
	Usage:     "[flags]",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseWhoAmIOptions,
}

func ParseWhoAmIOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func RequestWhoAmI(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	address := options["SaultServerAddress"].(string)
	serverName := options["SaultServerName"].(string)

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
		output, exitStatus, err = runCommand(connection, &CommandMsg{Command: "whoami"})
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

	var data UserResponseData
	if err := json.Unmarshal(responseMsg.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	fmt.Fprintf(os.Stdout, PrintUser(data)+"\n")
	exitStatus = 0

	return
}

func ResponseWhoAmI(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	data := NewUserResponseData(pc.proxy.Registry, pc.userData)
	if pc.clientType == SAULT_CLIENT {
		channel.Write(ToResponse(data, nil))
		return
	}

	result := PrintUser(data)
	fmt.Fprintf(channel, result+"\n")

	return
}

func PrintUser(userResponseData UserResponseData) string {
	return FormatResponse(`
{{ "User:"|yellow }}      {{ .user.User | escape | yellow }} {{ if .user.IsAdmin }} {{ "(admin)" | green }} {{ end }} {{ if .user.Deactivated }}{{ "(deactivated)" | red }}{{ end }}
PublicKey: {{ .user.PublicKey | escape }}
{{ $length := len .connected }}Connected hosts and it's accounts: {{ if eq $length 0 }}-{{ else }}
{{ range $key, $accounts := .connected }}{{ $key | escape }} {{ $accounts }}
{{ end }}{{ end }}
`,
		map[string]interface{}{
			"user":      userResponseData.UserData,
			"connected": userResponseData.Connected,
		},
	)
}
