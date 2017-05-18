package sault

import (
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var userListOptionsTemplate = OptionsTemplate{
	Name:      "list",
	Help:      "list users",
	Usage:     "[flags]",
	ParseFunc: parseUserLlstOptions,
}

func parseUserLlstOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestUserList(options OptionsValues, globalOptions OptionsValues) (err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var response *responseMsg
	var data []userResponseData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.list",
		nil,
		&data,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	var printedUsers []string
	for _, u := range data {
		printedUsers = append(printedUsers, printUser(u))
	}

	var result string
	result, err = ExecuteCommonTemplate(
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

	CommandOut.Println(strings.TrimSpace(result))
	return
}

func responseUserList(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data []userResponseData
	for _, u := range pc.proxy.Registry.GetUsers(activeFilterAll) {
		data = append(data, newUserResponseData(pc.proxy.Registry, u))
	}

	var response []byte
	response, err = newResponseMsg(
		data,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
