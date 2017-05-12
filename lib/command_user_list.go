package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var userListOptionsTemplate = OptionsTemplate{
	Name:      "list",
	Help:      "list users",
	Usage:     "[flags]",
	Options:   []OptionTemplate{atOptionTemplate, pOptionTemplate},
	ParseFunc: parseUserLlstOptions,
}

func parseUserLlstOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestUserList(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		output, exitStatus, err = runCommand(connection, &commandMsg{Command: "user.list"})
		if err != nil {
			log.Error(err)
			return
		}
	}

	var rm responseMsg
	if err := saultSsh.Unmarshal(output, &rm); err != nil {
		log.Error(err)
		exitStatus = 1
		return
	}

	var data []userResponseData
	if err := json.Unmarshal(rm.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	var printedUsers []string
	for _, u := range data {
		printedUsers = append(printedUsers, printUser(u))
	}

	result, err := ExecuteCommonTemplate(
		`
{{ $length := len .users }}{{ if ne $length 0 }}{{ .line }}{{ range $user := .users }}
{{ $user | escape }}
{{ end }}{{ .line }}
found {{ len .users }} user(s){{ else }}no users{{ end }}
`,
		map[string]interface{}{
			"users": printedUsers,
		},
	)
	if err := saultSsh.Unmarshal(output, &rm); err != nil {
		log.Error(err)
		exitStatus = 1
		return
	}
	fmt.Fprintf(os.Stdout, strings.TrimSpace(result))

	exitStatus = 0

	return
}

func responseUserList(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data []userResponseData
	for _, u := range pc.proxy.Registry.GetUsers(activeFilterAll) {
		data = append(data, newUserResponseData(pc.proxy.Registry, u))
	}

	channel.Write(toResponse(data, nil))
	return
}
