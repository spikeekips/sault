package sault

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var UserListOptionsTemplate OptionsTemplate

func init() {
	UserListOptionsTemplate = OptionsTemplate{
		Name:      "list",
		Help:      "list users",
		Usage:     "[flags]",
		Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
		ParseFunc: ParseUserLlstOptions,
	}
}

func ParseUserLlstOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func RequestUserList(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		output, exitStatus, err = runCommand(connection, &CommandMsg{Command: "user.list"})
		if err != nil {
			log.Error(err)
			return
		}
	}

	var responseMsg ResponseMsg
	if err := saultSsh.Unmarshal(output, &responseMsg); err != nil {
		log.Error(err)
		exitStatus = 1
		return
	}

	var data []UserResponseData
	if err := json.Unmarshal(responseMsg.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	var printedUsers []string
	for _, u := range data {
		printedUsers = append(printedUsers, PrintUser(u))
	}

	result := FormatResponse(
		`
{{ $length := len .users }}{{ if ne $length 0 }}{{ .line }}{{ range $user := .users }}
{{ $user | escape }}
{{ end }}
{{ .line }}
found {{ len .users }} users{{ else }}no users{{ end }}
`,
		map[string]interface{}{
			"users": printedUsers,
		},
	)
	fmt.Fprintf(os.Stdout, result)

	exitStatus = 0

	return
}

func ResponseUserList(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data []UserResponseData
	for _, u := range pc.proxy.Registry.GetUsers(UserFilterAll) {
		data = append(data, NewUserResponseData(pc.proxy.Registry, u))
	}

	channel.Write(ToResponse(data, nil))
	return
}
