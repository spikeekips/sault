package sault

import (
	"encoding/json"
	"fmt"
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

func requestShowClientKeys(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		output, exitStatus, err = runCommand(connection, &commandMsg{Command: "server.clientKeys"})
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

	var data clientKeysResponseData
	if err := json.Unmarshal(rm.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	result, _ := ExecuteCommonTemplate(`
* private key
{{ .line }}
{{ .privateKey | escape }}
{{ .line }}

* public key
{{ .line }}
{{ .publicKey | escape }}
{{ .line }}
	`,
		map[string]interface{}{
			"privateKey": strings.TrimSpace(data.PrivateKey),
			"publicKey":  strings.TrimSpace(data.PublicKey),
		},
	)
	fmt.Println(strings.TrimSpace(result))

	exitStatus = 0

	return
}

func responseShowClientKeys(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to get hosts")

	b, err := ioutil.ReadFile(pc.proxy.Config.Server.GlobalClientKeyPath)
	if err != nil {
		log.Errorf("failed to read GlobalClientKey file: %v", err)

		channel.Write(toResponse(nil, err))
		return
	}

	data := clientKeysResponseData{
		PrivateKey: string(b),
		PublicKey:  GetAuthorizedKey(pc.proxy.Config.Server.globalClientKeySigner.PublicKey()),
	}
	channel.Write(toResponse(data, nil))

	return
}
