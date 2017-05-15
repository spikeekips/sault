package sault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/spikeekips/sault/ssh"
)

var sshDirectory = "~/.ssh"
var authorizedKeyFile = "~/.ssh/authorized_keys"

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

	return nil
}

var maxAuthTries int = 3

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

	authMethosTries := []string{
		"publicKey",
	}
	for i := 0; i < maxAuthTries; i++ {
		authMethosTries = append(authMethosTries, "password")
	}

	data := hostAddRequestData{
		Host:           ov["HostName"].(string),
		DefaultAccount: ov["DefaultAccount"].(string),
		Accounts:       []string(*ov["Accounts"].(*flagAccounts)),
		Address:        ov["Address"].(string),
		Port:           ov["Port"].(uint64),
	}

	var rm responseMsg
	var previousAuthMethod string

Tries:
	for _, method := range authMethosTries {
		var output []byte
		var password string
		var err error

		data.AuthMethod = method
		switch method {
		case "password":
			if previousAuthMethod != method {
				prompt, _ := ExecuteCommonTemplate(`{{ "NOTICE: sault does not store your input password" | red }}`, nil)
				fmt.Println(strings.TrimSpace(prompt))
			}

			var tries int
			for {
				if tries > (maxAuthTries - 1) {
					break
				}

				fmt.Print("Password: ")
				bytePassword, err := terminal.ReadPassword(0)
				fmt.Println("")
				if err != nil {
					log.Error(err)
					exitStatus = 1
					return
				}
				bp := strings.TrimSpace(string(bytePassword))
				if len(bp) < 1 {
					tries++
					continue
				}

				password = bp
				break
			}

			if len(password) < 1 {
				log.Errorf("cancel password authentication")
				exitStatus = 1
				return
			}
			data.Password = password
		default:
			//
		}

		msg, err := newCommandMsg("host.add", data)
		if err != nil {
			log.Errorf("failed to make message: %v", err)
			exitStatus = 1
			return
		}

		log.Debugf("msg sent: %v", msg)
		output, exitStatus, err = runCommand(connection, msg)
		if err != nil {
			log.Error(err)
			return
		}
		previousAuthMethod = method

		if err := saultSsh.Unmarshal(output, &rm); err != nil {
			log.Errorf("got invalid response: %v", err)
			exitStatus = 1
			return
		}

		if rm.Error == "" {
			log.Debugf("authMethod: %s is passed", method)
			break Tries
		}

		log.Debugf("authMethod: %s is failed: %s", method, rm.Error)
		ce, err := parseCommandError(rm.Error)
		if err != nil {
			break Tries
		}

		switch ce.Type {
		case commandErrorAuthFailed:
			log.Debugf("got `commandErrorAuthFailed`")
			continue
		case commandErrorInjectClientKey:
			log.Debugf("got `commandErrorInjectClientKey`")
			log.Error(ce)
			exitStatus = 1
			return
		default:
			break Tries
		}
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

	_, err = pc.proxy.Registry.GetHostByHostName(data.Host)
	if err == nil {
		channel.Write(toResponse(nil, fmt.Errorf("host, `%s` already exists.", data.Host)))
		return
	}

	log.Debugf("check the connectivity: %v", data)
	signer := pc.proxy.Config.Server.globalClientKeySigner

	var authMethod []saultSsh.AuthMethod
	switch data.AuthMethod {
	case "publicKey":
		authMethod = []saultSsh.AuthMethod{
			saultSsh.PublicKeys(signer),
		}
	case "password":
		authMethod = []saultSsh.AuthMethod{
			saultSsh.Password(data.Password),
		}
	default:
		err = errors.New("invalid request; missing `AuthMethod`")
		channel.Write(toResponse(nil, err))
		return
	}

	sc := newsshClient(data.DefaultAccount, data.getFullAddress())
	sc.addAuthMethod(authMethod...)
	sc.setTimeout(time.Second * 2)

	err = sc.connect()
	if err != nil {
		channel.Write(toResponse(nil, newCommandError(commandErrorAuthFailed, err)))
		return
	}

	err = injectClientKeyToHost(sc, signer.PublicKey())
	if err != nil {
		channel.Write(toResponse(nil, newCommandError(commandErrorInjectClientKey, err)))
		return
	}

	log.Debugf("trying to add new host: %v", data)
	hostData, err := pc.proxy.Registry.AddHost(
		data.Host,
		data.DefaultAccount,
		data.Address,
		data.Port,
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

func injectClientKeyToHost(sc *sshClient, publicKey saultSsh.PublicKey) (err error) {
	log.Debugf("trying to inject client public key to host")

	checkCmd := fmt.Sprintf("sh -c '[ -d %s ] && echo 1 || echo 0'", sshDirectory)
	output, err := sc.Run(checkCmd)
	if err != nil {
		log.Errorf("failed to check ssh directory, %s: %v", sshDirectory, err)
		return
	}

	if strings.TrimSpace(string(output)) == "0" {
		log.Debugf("ssh directory, `%s` does not exist, create new", sshDirectory)
		if err = sc.MakeDir(sshDirectory, 0700, true); err != nil {
			log.Debugf("failed to create ssh directory, `%s`: %v", sshDirectory, err)
			return
		}
		err = sc.PutFile(GetAuthorizedKey(publicKey)+"\n", authorizedKeyFile, 0600)
		if err != nil {
			log.Debugf("failed to create new authorized_keys file, `%s`: %v", authorizedKeyFile, err)
			return
		}
		log.Debugf("created new authorized_keys file, `%s`", authorizedKeyFile)

		return nil
	}

	authorizedPublicKey := GetAuthorizedKey(publicKey)
	output, err = sc.GetFile(authorizedKeyFile)
	if err != nil {
		err = sc.PutFile(authorizedPublicKey+"\n", authorizedKeyFile, 0600)
		if err != nil {
			return
		}

		return
	}

	var foundSame bool
	r := bufio.NewReader(bytes.NewBuffer(output))
	for {
		c, err := r.ReadString(10)
		if err == io.EOF {
			break
		} else if err != nil {
			break
		}
		if len(strings.TrimSpace(c)) < 1 {
			continue
		}

		p, err := ParsePublicKeyFromString(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if GetAuthorizedKey(p) == authorizedPublicKey {
			foundSame = true
			break
		}
	}

	if foundSame {
		log.Debugf("client public key already added.")
		err = nil
		return
	}

	content := fmt.Sprintf(`%s
%s
`,
		strings.TrimSpace(string(output)),
		authorizedPublicKey,
	)

	err = sc.PutFile(content, authorizedKeyFile, 0600)
	if err != nil {
		return
	}

	return nil
}
