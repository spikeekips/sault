package sault

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spikeekips/sault/ssh"
)

type flagClientPrivateKey struct {
	Path string
	s    []byte
}

func (f *flagClientPrivateKey) String() string {
	return f.Path
}

func (f *flagClientPrivateKey) Bytes() []byte {
	return f.s
}

func (f *flagClientPrivateKey) Set(v string) error {
	keyFile := filepath.Clean(v)

	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("-clientPrivateKey: %v", err)
	}
	if _, err := GetPrivateKeySignerFromString(string(b)); err != nil {
		return fmt.Errorf("invalid clientPrivateKey; clientPrivateKey must be without passphrase")
	}

	*f = flagClientPrivateKey{Path: keyFile, s: b}

	return nil
}

type flagAccounts []string

func (f *flagAccounts) String() string {
	return fmt.Sprintf("%v", *f)
}

func (f *flagAccounts) Set(v string) error {
	n := StringFilter(
		strings.Split(v, ","),
		func(n string) bool {
			return len(strings.TrimSpace(n)) > 0
		},
	)

	*f = flagAccounts(n)

	return nil
}

var hostAddOptionsTemplate = OptionsTemplate{
	Name:  "add",
	Help:  "add new host",
	Usage: "[flags] <hostName> <default account>@<address:port>",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:      "Accounts",
			Help:      "available accounts of host. ex) spike,bae",
			ValueType: &struct{ Type flagAccounts }{flagAccounts{}},
		},
		OptionTemplate{
			Name:      "ClientPrivateKey",
			Help:      "private key file to connect host",
			ValueType: &struct{ Type flagClientPrivateKey }{flagClientPrivateKey{}},
		},
	},
	ParseFunc: parseHostAddOptions,
}

func parseHostAddOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
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

	op.Extra["ClientPrivateKeyString"] = string(op.Vars["ClientPrivateKey"].(*flagClientPrivateKey).Bytes())

	return nil
}

func requestHostAdd(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
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
		msg, err := newCommandMsg(
			"host.add",
			hostAddRequestData{
				Host:             ov["HostName"].(string),
				DefaultAccount:   ov["DefaultAccount"].(string),
				Accounts:         []string(*ov["Accounts"].(*flagAccounts)),
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

	var hostData hostRegistryData
	if err := json.Unmarshal(rm.Result, &hostData); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(hostData, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	fmt.Fprintf(os.Stdout, printHost(saultServerHostName, saultServerPort, hostData))

	exitStatus = 0

	return
}

func responseHostAdd(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostAddRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("check the connectivity: %v", data)
	var signer saultSsh.Signer
	if data.ClientPrivateKey == "" {
		signer = pc.proxy.Config.Server.globalClientKeySigner
		log.Debugf("ClientPrivateKey is missing, GlobalClientKeySigner will be used")
	} else {
		signer, err = GetPrivateKeySignerFromString(data.ClientPrivateKey)
		if err != nil {
			err = fmt.Errorf("invalid ClientPrivateKey: %v", err)

			channel.Write(toResponse(nil, err))
			return
		}
		log.Debugf("ClientPrivateKey for host will be used")
	}

	_, err = createSSHClient(
		signer,
		data.DefaultAccount,
		data.getFullAddress(),
		time.Second*3,
	)
	if err != nil {
		err = fmt.Errorf("failed to check the connectivity: %v", err)

		channel.Write(toResponse(nil, err))
		return
	}

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

		channel.Write(toResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(hostData, nil))
	return
}
