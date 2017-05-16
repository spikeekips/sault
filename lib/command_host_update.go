package sault

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spikeekips/sault/ssh"
)

var hostUpdateOptionsTemplate = OptionsTemplate{
	Name:  "update",
	Help:  "update host",
	Usage: "[flags] <hostName> [hostName <newHostName>] [defaultAccount <defaultAccount>] [accounts \"<account1>,[<account>]\"] [address <address>] [port <port>]",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:         "Force",
			Help:         "pass to inject client public key to host",
			DefaultValue: false,
		},
	},
	ParseFunc: parseHostUpdateOptions,
}

func parseHostUpdateOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
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
		default:
			return fmt.Errorf("unknown value, `%v`", i)
		}
	}

	return nil
}

func requestHostUpdate(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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

	hostName := ov["HostName"].(string)

	var newHostName, newDefaultAccount, newAddress string
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
	if v, ok := ov["NewAccounts"]; ok {
		newAccounts = v.([]string)
	}
	if v, ok := ov["NewPort"]; ok {
		newPort = v.(uint64)
	}

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"host.update",
			hostUpdateRequestData{
				Host:              hostName,
				NewHostName:       newHostName,
				NewDefaultAccount: newDefaultAccount,
				NewAccounts:       newAccounts,
				NewAddress:        newAddress,
				NewPort:           newPort,
				Force:             *ov["Force"].(*bool),
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

func responseHostUpdate(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostUpdateRequestData
	json.Unmarshal(msg.Data, &data)

	hostData, err := pc.proxy.Registry.GetHostByHostName(data.Host)
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	if data.Force {
		log.Debugf("skip to check connectivity: %v", data)
	} else {
		log.Debugf("check the connectivity: %v", data)

		defaultAccount := hostData.DefaultAccount
		if data.NewDefaultAccount != "" {
			defaultAccount = data.NewDefaultAccount
		}

		address := hostData.Address
		port := hostData.GetPort()
		if data.NewAddress != "" {
			address = data.NewAddress
		}
		if data.NewPort != 0 {
			port = data.NewPort
		}

		sc := newsshClient(defaultAccount, fmt.Sprintf("%s:%d", address, port))
		sc.addAuthMethod(saultSsh.PublicKeys(pc.proxy.Config.Server.globalClientKeySigner))
		sc.setTimeout(time.Second * 3)
		if err = sc.connect(); err != nil {
			err = fmt.Errorf("failed to check the connectivity: %v", err)

			channel.Write(toResponse(nil, err))
			return
		}
	}

	log.Debugf("trying to update host: %v", data)
	if data.NewHostName != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostName(data.Host, data.NewHostName); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}
	if data.NewDefaultAccount != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostDefaultAccount(data.Host, data.NewDefaultAccount); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}
	if len(data.NewAccounts) > 0 {
		if hostData, err = pc.proxy.Registry.UpdateHostAccounts(data.Host, data.NewAccounts); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}
	if data.NewAddress != "" {
		if hostData, err = pc.proxy.Registry.UpdateHostAddress(data.Host, data.NewAddress); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}
	if data.NewPort != 0 {
		if hostData, err = pc.proxy.Registry.UpdateHostPort(data.Host, data.NewPort); err != nil {
			channel.Write(toResponse(nil, err))
			return
		}
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(hostData, nil))
	return
}
