package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var userAddOptionsTemplate = OptionsTemplate{
	Name:      "add",
	Help:      "add user",
	Usage:     "[flags] <userName> <publicKeyFile>",
	ParseFunc: parseUserAddOptions,
}

func parseUserAddOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 2 {
		return fmt.Errorf("wrong usage")
	}

	userName, publicKeyFile := commandArgs[0], commandArgs[1]

	if !CheckUserName(userName) {
		return fmt.Errorf("invalid userName, `%s`", userName)
	}

	op.Extra["UserName"] = userName

	publicKeyString, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}
	if _, err := ParsePublicKeyFromString(string(publicKeyString)); err != nil {
		return err
	}

	op.Extra["PublicKey"] = string(publicKeyString)

	return nil
}

func requestUserAdd(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	userName := ov["UserName"].(string)
	publicKeyString := ov["PublicKey"].(string)

	var data userResponseData
	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.add",
		userAddRequestData{
			User:      userName,
			PublicKey: publicKeyString,
		},
		&data,
	)
	if err != nil {
		log.Error(err)
		return
	}

	fmt.Fprintf(os.Stdout, printAddedUser(data))

	exitStatus = 0

	return
}

func responseUserAdd(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userAddRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to add new user: %v", data)
	userData, err := pc.proxy.Registry.AddUser(data.User, data.PublicKey)
	if err != nil {
		log.Errorf("failed to add user: %v", err)
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	channel.Write(toResponse(newUserResponseData(pc.proxy.Registry, userData), nil))
	return
}

func printAddedUser(data userResponseData) string {
	result, err := ExecuteCommonTemplate(`
{{ .user | escape }}
{{ .line }}
new user added`,
		map[string]interface{}{
			"user": printUser(data),
		},
	)
	if err != nil {
		log.Errorf("failed to templating: %v", err)
		return ""
	}

	return strings.TrimSpace(result)
}
