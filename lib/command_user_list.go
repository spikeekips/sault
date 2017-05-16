package sault

import (
	"fmt"
	"os"
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

func requestUserList(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var data []userResponseData
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.list",
		nil,
		&data,
	)
	if err != nil {
		log.Error(err)
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
