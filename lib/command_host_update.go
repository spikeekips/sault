package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var HostUpdateOptionsTemplate OptionsTemplate

func init() {
	HostUpdateOptionsTemplate = OptionsTemplate{
		Name:      "update",
		Help:      "update host",
		Usage:     "[flags] <hostName> [hostName <newHostName>] [defaultAccount <defaultAccount>] [accounts \"<account1>,[<account>]\"] [address <address>] [port <port>] [clientPrivateKey <clientPrivateKey>]",
		Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
		ParseFunc: ParseHostUpdateOptions,
	}
}

func ParseHostUpdateOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()

	if len(commandArgs) < 3 || len(commandArgs[1:])%2 == 1 {
		return fmt.Errorf("wrong usage")
	}

	var argsSet [][]string

	{
		hostName := commandArgs[0]
		if !CheckHostName(hostName) {
			return fmt.Errorf("invalid hostName, `%s`", hostName)
		}
		op.Extra["HostName"] = hostName
	}

	for i := 0; i < len(commandArgs[1:])/2; i++ {
		argsSet = append(argsSet, commandArgs[(i*2)+1:1+(i*2)+2])
	}

	for _, i := range argsSet {
		switch i[0] {
		case "hostName":
			if !CheckHostName(i[1]) {
				return fmt.Errorf("invalid hostName, `%s`", i[1])
			}
			op.Extra["NewHostName"] = i[1]
		case "defaultAccount":
			if !CheckUserName(i[1]) {
				return fmt.Errorf("invalid defaultAccount, `%s`", i[1])
			}
			op.Extra["NewDefaultAccount"] = i[1]
		case "accounts":
			n := StringMap(
				StringFilter(
					strings.Split(i[1], ","),
					func(n string) bool {
						return len(strings.TrimSpace(n)) > 0
					},
				),
				func(s string) string {
					return strings.TrimSpace(s)
				},
			)
			if len(n) < 1 {
				return fmt.Errorf("accounts can be seperated by comma(,)")
			}
			for _, a := range n {
				if !CheckUserName(a) {
					return fmt.Errorf("invalid account, `%s`", a)
				}
			}
			op.Extra["NewAccounts"] = n
		case "address":
			op.Extra["NewAddress"] = i[1]
		case "port":
			port, err := strconv.ParseUint(i[1], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid port: `%v`", err)
			}
			op.Extra["NewPort"] = port
		case "clientPrivateKey":
			keyFile := filepath.Clean(i[1])

			b, err := ioutil.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("clientPrivateKey: %v", err)
			}
			if _, err := GetPrivateKeySignerFromString(string(b)); err != nil {
				return fmt.Errorf("invalid clientPrivateKey; clientPrivateKey must be correct private key and without passphrase")
			}

			op.Extra["NewClientPrivateKey"] = keyFile
			op.Extra["NewClientPrivateKeyString"] = string(b)
		default:
			return fmt.Errorf("unknown value, `%v`", i)
		}
	}

	return nil
}

func RequestHostUpdate(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)
	address := ov["SaultServerAddress"].(string)
	serverName := options["Commands"].(OptionsValues)["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	hostName := ov["HostName"].(string)

	var newHostName, newDefaultAccount, newAddress, newClientPrivateKeyString string
	var newAccounts []string
	var newPort uint64

	if v, ok := ov["NewHostName"]; ok {
		newHostName = v.(string)
	}
	if v, ok := ov["NewDefaultAccount"]; ok {
		newDefaultAccount = v.(string)
	}
	if v, ok := ov["NewAddress"]; ok {
		newAddress = v.(string)
	}
	if v, ok := ov["NewClientPrivateKeyString"]; ok {
		newClientPrivateKeyString = v.(string)
	}
	if v, ok := ov["NewAccounts"]; ok {
		newAccounts = v.([]string)
	}
	if v, ok := ov["NewPort"]; ok {
		newPort = v.(uint64)
	}

	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"host.update",
			HostUpdateRequestData{
				Host:                hostName,
				NewHostName:         newHostName,
				NewDefaultAccount:   newDefaultAccount,
				NewAccounts:         newAccounts,
				NewAddress:          newAddress,
				NewPort:             newPort,
				NewClientPrivateKey: newClientPrivateKeyString,
			},
		)
		if err != nil {
			log.Errorf("failed to make message: %v", err)
			exitStatus = 1
			return
		}

		log.Debug("msg sent")
		output, exitStatus, err = runCommand(connection, msg)
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

	var hostData HostRegistryData
	if err := json.Unmarshal(responseMsg.Result, &hostData); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostData, "", "  ")
	log.Debugf("unmarshaled data: %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := ov["SaultServerHostName"].(string)

	fmt.Fprintf(os.Stdout, PrintHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func ResponseHostUpdate(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data HostUpdateRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to update host: %v", data)

	var hostData HostRegistryData
	if data.NewHostName != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostName(data.Host, data.NewHostName); err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}
	if data.NewDefaultAccount != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostDefaultAccount(data.Host, data.NewDefaultAccount); err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}
	if len(data.NewAccounts) > 0 {
		if hostData, err = pc.proxy.Registry.UpdateHostAccounts(data.Host, data.NewAccounts); err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}
	if data.NewAddress != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostAddress(data.Host, data.NewAddress); err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}
	if data.NewPort != 0 {
		if hostData, err = pc.proxy.Registry.UpdateHostPort(data.Host, data.NewPort); err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}
	if data.NewClientPrivateKey != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostClientPrivateKey(data.Host, data.NewClientPrivateKey); err != nil {
			channel.Write(ToResponse(nil, err))
			return
		}
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(hostData, nil))
	return
}
