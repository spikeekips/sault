package sault

import (
	"io/ioutil"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var showClientKeysOptionsTemplate = OptionsTemplate{
	Name:      "clientKeys",
	Help:      "show publicKey for host client",
	Usage:     "[flags]",
	ParseFunc: parseShowClientKeysOptions,
}

func parseShowClientKeysOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	return nil
}

func requestShowClientKeys(options OptionsValues, globalOptions OptionsValues) (err error) {
	gov := globalOptions["Options"].(OptionsValues)

	var response *responseMsg
	var data clientKeysResponseData
	response, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"server.clientKeys",
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

	result, _ := ExecuteCommonTemplate(`
{{ "* private key" | yellow }}
{{ .line }}
{{ .privateKey | escape }}
{{ .line }}

{{ "* public key" | yellow }}
{{ .line }}
{{ .publicKey | escape }}
{{ .line }}
	`,
		map[string]interface{}{
			"privateKey": strings.TrimSpace(data.PrivateKey),
			"publicKey":  strings.TrimSpace(data.PublicKey),
		},
	)

	CommandOut.Println(strings.TrimSpace(result))
	return
}

func responseShowClientKeys(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	b, err := ioutil.ReadFile(pc.proxy.Config.Server.GlobalClientKeyPath)
	if err != nil {
		log.Errorf("failed to read GlobalClientKey file: %v", err)
		return
	}

	data := clientKeysResponseData{
		PrivateKey: string(b),
		PublicKey:  GetAuthorizedKey(pc.proxy.Config.Server.globalClientKeySigner.PublicKey()),
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
