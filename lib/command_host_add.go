package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

type FlagClientPrivateKey struct {
	Path string
	s    []byte
}

func (f *FlagClientPrivateKey) String() string {
	return f.Path
}

func (f *FlagClientPrivateKey) Bytes() []byte {
	return f.s
}

func (f *FlagClientPrivateKey) Set(v string) error {
	keyFile := filepath.Clean(v)

	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("-clientPrivateKey: %v", err)
	}
	if _, err := GetPrivateKeySignerFromString(string(b)); err != nil {
		return fmt.Errorf("invalid clientPrivateKey; clientPrivateKey must be without passphrase")
	}

	*f = FlagClientPrivateKey{Path: keyFile, s: b}

	return nil
}

type FlagAccounts []string

func (f *FlagAccounts) String() string {
	return fmt.Sprintf("%v", *f)
}

func (f *FlagAccounts) Set(v string) error {
	n := StringFilter(
		strings.Split(v, ","),
		func(n string) bool {
			return len(strings.TrimSpace(n)) > 0
		},
	)

	*f = FlagAccounts(n)

	return nil
}

var HostAddOptionsTemplate OptionsTemplate

func init() {
	HostAddOptionsTemplate = OptionsTemplate{
		Name:  "add",
		Help:  "add new host",
		Usage: "[flags] <hostName> <default account>@<address:port>",
		Options: []OptionTemplate{
			AtOptionTemplate,
			POptionTemplate,
			OptionTemplate{
				Name:      "Accounts",
				Help:      "available accounts of host",
				ValueType: &struct{ Type FlagAccounts }{FlagAccounts{}},
			},
			OptionTemplate{
				Name:      "ClientPrivateKey",
				Help:      "private key file to connect host",
				ValueType: &struct{ Type FlagClientPrivateKey }{FlagClientPrivateKey{}},
			},
		},
		ParseFunc: ParseHostAddOptions,
	}
}

func ParseHostAddOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 2 {
		return fmt.Errorf("wrong usage")
	}

	hostName, address := commandArgs[0], commandArgs[1]

	{
		if !CheckHostName(hostName) {
			return fmt.Errorf("invalid hostName, `%s`", hostName)
		}

		op.Extra["HostName"] = hostName
	}
	{
		defaultAccount, addressAndPort, err := ParseHostAccount(address)
		if defaultAccount == "" {
			return fmt.Errorf("<default account> is missing")
		}
		op.Extra["DefaultAccount"] = defaultAccount
		if err != nil {
			return fmt.Errorf("invalid address: %v", err)
		}

		host, port, err := SplitHostPort(addressAndPort, uint64(22))
		if err != nil {
			return fmt.Errorf("invalid address: %v", err)
		}
		op.Extra["Address"] = host
		op.Extra["Port"] = port
	}

	op.Extra["ClientPrivateKeyString"] = string(op.Vars["ClientPrivateKey"].(*FlagClientPrivateKey).Bytes())

	return nil
}

func RequestHostAdd(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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
		msg, err := NewCommandMsg(
			"host.add",
			HostAddRequestData{
				Host:           ov["HostName"].(string),
				DefaultAccount: ov["DefaultAccount"].(string),
				Accounts: []string(
					*ov["Options"].(OptionsValues)["Accounts"].(*FlagAccounts),
				),
				Address:          ov["Address"].(string),
				Port:             ov["Port"].(uint64),
				ClientPrivateKey: ov["ClientPrivateKeyString"].(string),
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

func ResponseHostAdd(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data HostAddRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to add new host: %v", data)
	hostData, err := pc.proxy.Registry.AddHost(
		data.Host,
		data.DefaultAccount,
		data.Address,
		data.Port,
		data.ClientPrivateKey,
		data.Accounts,
	)
	if err != nil {
		log.Errorf("failed to add host: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(hostData, nil))
	return
}
