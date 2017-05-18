package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var userGetOptionsTemplate = OptionsTemplate{
	Name:  "get",
	Help:  "get user",
	Usage: "[flags] [<userName>...]",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:         "A",
			Help:         "get all hosts",
			DefaultValue: false,
		},
		OptionTemplate{
			Name:         "Filter",
			Help:         "filter hosts by state, [ active deactive ]",
			DefaultValue: "",
		},
		OptionTemplate{
			Name:      "PublicKey",
			Help:      "find user by public key; you can find user without userName",
			ValueType: &struct{ Type flagPublicKey }{flagPublicKey("")},
		},
	},
	ParseFunc: parseUserGetOptions,
}

type flagPublicKey string

func (f *flagPublicKey) String() string {
	return string(*f)
}

func (f *flagPublicKey) Set(v string) error {
	if _, err := os.Stat(v); err != nil {
		return err
	}

	b, err := ioutil.ReadFile(v)
	if err != nil {
		return err
	}

	{
		_, err := ParsePublicKeyFromString(string(b))
		if err != nil {
			return err
		}
	}

	*f = flagPublicKey(v)

	return nil
}

func parseUserGetOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	values := op.Values(false)
	publicKeyFile := string(*values["Options"].(OptionsValues)["PublicKey"].(*flagPublicKey))

	userNames := op.FlagSet.Args()
	{
		op.Extra["UserNames"] = []string{}
		for _, userName := range userNames {
			if !CheckUserName(userName) {
				return fmt.Errorf("invalid userName, `%s` found", userName)
			}
		}
		op.Extra["UserNames"] = userNames
	}

	op.Extra["publicKeyString"] = ""
	if publicKeyFile != "" {
		b, _ := ioutil.ReadFile(publicKeyFile)
		op.Extra["publicKeyString"] = string(b)
	}

	{
		var filter activeFilter
		f := *op.Vars["Filter"].(*string)
		if f != "" {
			switch f {
			case "active":
				filter = activeFilterActive
			case "deactive":
				filter = activeFilterDeactivated
			default:
				return fmt.Errorf("invalid filter, `%s` found", f)

			}

			op.Extra["ActiveFilter"] = filter
		}
	}

	{
		if op.Extra["ActiveFilter"] == nil && *op.Vars["A"].(*bool) {
			op.Extra["ActiveFilter"] = activeFilterAll
		}
	}

	return nil
}

func requestUserGet(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	req := userGetRequestData{
		Users:     ov["UserNames"].([]string),
		PublicKey: ov["publicKeyString"].(string),
	}

	if v, ok := ov["ActiveFilter"]; ok && v != nil {
		fmt.Printf(">> %v %T\n", v, v)
		req.Filter = v.(activeFilter)
	}

	var response *responseMsg
	var data []userResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		clientPublicKey,
		"user.get",
		req,
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

func responseUserGet(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userGetRequestData
	json.Unmarshal(msg.Data, &data)

	var list []UserRegistryData
	if data.Filter == activeFilterAll || len(data.Users) < 1 {
		for _, userData := range pc.proxy.Registry.GetUsers(data.Filter) {
			list = append(list, userData)
		}
	} else {
		for _, userName := range data.Users {
			userData, err := pc.proxy.Registry.GetUserByUserName(userName)
			if err != nil {
				continue
			}
			list = append(list, userData)
		}
	}

	var filtered0 []UserRegistryData
	switch data.Filter {
	case activeFilterActive:
		for _, userData := range list {
			if userData.Deactivated {
				continue
			}
			filtered0 = append(filtered0, userData)
		}
	case activeFilterDeactivated:
		for _, userData := range list {
			if !userData.Deactivated {
				continue
			}
			filtered0 = append(filtered0, userData)
		}
	default:
		filtered0 = list
	}

	var filtered1 []UserRegistryData
	if data.PublicKey == "" {
		filtered1 = filtered0
	} else {
		var publicKey saultSsh.PublicKey
		publicKey, err = ParsePublicKeyFromString(data.PublicKey)
		if err != nil {
			log.Errorf("invalid PublicKey received: %v", err)
			return
		}

		var userDataOfPublicKey UserRegistryData
		userDataOfPublicKey, err = pc.proxy.Registry.GetUserByPublicKey(publicKey)
		for _, userData := range filtered0 {
			if userData.User == userDataOfPublicKey.User {
				filtered1 = append(filtered1, userData)
				break
			}
		}
	}

	var result []userResponseData
	for _, userData := range filtered1 {
		result = append(
			result,
			newUserResponseData(pc.proxy.Registry, userData),
		)
	}

	var response []byte
	response, err = newResponseMsg(
		result,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
