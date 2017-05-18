package sault

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/spikeekips/sault/ssh"
)

func init() {
	// terminal.ReadPassword was hanged after interruped with 'control-c'
	oldState, _ := terminal.GetState(0)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			syscall.Syscall6(syscall.SYS_IOCTL, uintptr(0), syscall.TIOCSETA, uintptr(unsafe.Pointer(oldState)), 0, 0, 0)
			os.Exit(1)
		}
	}()
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
			Name:         "Force",
			Help:         "pass to inject client public key to host",
			DefaultValue: false,
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

func requestHostAdd(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	data := hostAddRequestData{
		Host:           ov["HostName"].(string),
		DefaultAccount: ov["DefaultAccount"].(string),
		Accounts:       []string(*ov["Accounts"].(*flagAccounts)),
		Address:        ov["Address"].(string),
		Port:           ov["Port"].(uint64),
		Force:          *ov["Force"].(*bool),
	}

	var previousAuthMethod string
	var hostData hostRegistryData
	var response *responseMsg

Tries:
	for _, method := range authMethosTries {
		data.AuthMethod = method
		switch method {
		case "password":
			if previousAuthMethod != method {
				prompt, _ := ExecuteCommonTemplate(`{{ "NOTICE: sault does not store your input password" | red }}`, nil)
				fmt.Fprintln(os.Stdout, strings.TrimSpace(prompt))
			}

			var password string
			password, err = ReadPassword(maxAuthTries)
			if err != nil {
				log.Error(err)
			}

			if len(password) < 1 {
				log.Errorf("cancel password authentication")
				return
			}

			data.Password = password
		default:
			//
		}

		var clientPublicKey saultSsh.PublicKey
		if gov["ClientPublicKey"] != nil {
			clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
		}

		response, err = runCommand(
			gov["SaultServerName"].(string),
			address,
			clientPublicKey,
			"host.add",
			data,
			&hostData,
		)
		if err != nil {
			return
		}
		if response.Error == nil {
			log.Debugf("authMethod: %s is passed", method)
			break Tries
		}

		previousAuthMethod = method

		log.Debugf("authMethod: %s is failed: %v", method, response.Error)

		switch response.Error.ErrorType {
		case commandErrorAuthFailed:
			log.Debugf("got `commandErrorAuthFailed`: %v", response.Error)
			CommandOut.Errorf("failed to be authenticated")
			continue
		case commandErrorInjectClientKey:
			log.Debugf("got `commandErrorInjectClientKey`: %v", response.Error)
			CommandOut.Errorf("failed to inject client key")
			return
		default:
			CommandOut.Error(response.Error)
			return
		}
	}
	if response.Error != nil {
		CommandOut.Errorf("failed to add host: %v", response.Error)
		return
	}

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	CommandOut.Println(printHost(saultServerHostName, saultServerPort, hostData))
	return
}

func responseHostAdd(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostAddRequestData
	json.Unmarshal(msg.Data, &data)

	_, err = pc.proxy.Registry.GetHostByHostName(data.Host)
	if err == nil {
		err = fmt.Errorf("HostName, `%s` already added", data.Host)
		return
	}

	if data.Force {
		log.Debugf("skip to check connectivity: %v", data)
	} else {
		log.Debugf("check the connectivity: %v", data)
		var authMethod []saultSsh.AuthMethod
		switch data.AuthMethod {
		case "publicKey":
			authMethod = []saultSsh.AuthMethod{
				saultSsh.PublicKeys(pc.proxy.Config.Server.globalClientKeySigner),
			}
		case "password":
			authMethod = []saultSsh.AuthMethod{
				saultSsh.Password(data.Password),
			}
		default:
			err = errors.New("invalid request; missing `AuthMethod`")
			return
		}

		sc := newsshClient(data.DefaultAccount, data.getFullAddress())
		sc.addAuthMethod(authMethod...)
		sc.setTimeout(time.Second * 2)
		defer sc.close()

		err = sc.connect()
		if err != nil {
			log.Errorf("failed to connect host: %v", err)
			err = &ResponseMsgError{commandErrorAuthFailed, err.Error()}
			return
		}

		err = injectClientKeyToHost(sc, pc.proxy.Config.Server.globalClientKeySigner.PublicKey())
		if err != nil {
			err = &ResponseMsgError{commandErrorInjectClientKey, err.Error()}
			return
		}
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
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	var response []byte
	response, err = newResponseMsg(
		hostData,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
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
