package saultcommands

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
	"github.com/spikeekips/sault/saultssh/agent"
)

var hostInjectFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "host inject" | yellow }} will inject the internal client key to the remote host.

{{ "host inject" | yellow }} will authenticate to the remote host by your ssh agent, if failed, will ask your passphrase. This is the same process of {{ "ssh-copy-id" | yellow }}. If you can connect to the remote host in local by public key or passphrase, you can inject the sault internal client key.
		`,
		nil,
	)

	hostInjectFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "host inject",
		Name:         "inject",
		Help:         "inject the internal client key to the remote host",
		Usage:        "<account>@<host address, hostname:port> [flags]",
		Description:  description,
		IsPositioned: true,
		ParseFunc:    parseHostInjectCommandFlags,
	}

	sault.Commands[hostInjectFlagsTemplate.ID] = &hostInjectCommand{}
}

func parseHostInjectCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	if len(subArgs) < 1 {
		err = fmt.Errorf("wrong usage")
		return
	}

	fullAddress := subArgs[0]
	log.Debugf("parsed subArgs: %v", fullAddress)

	var account, address string
	if account, address, err = saultcommon.ParseHostAccount(fullAddress); err != nil {
		return
	}
	if len(account) < 1 {
		err = fmt.Errorf("account name must be set in host address")
		return
	}

	var hostName string
	var port uint64
	if hostName, port, err = saultcommon.SplitHostPort(address, uint64(22)); err != nil {
		return
	}

	f.Values["Host"] = hostInjectRequestData{
		HostName: hostName,
		Port:     port,
		Account:  account,
	}

	return nil
}

type hostInjectRequestData struct {
	HostName string
	Port     uint64
	Account  string
}

type hostInjectCommand struct{}

func (c *hostInjectCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := thisFlags.Values["Host"].(hostInjectRequestData)

	var host saultregistry.HostRegistry
	_, err = runCommand(
		allFlags[0],
		hostInjectFlagsTemplate.ID,
		data,
		&host,
	)
	if err == nil {
		fmt.Fprintf(os.Stdout, "successfully the sault client key was injected to the remote host\n")
		return nil
	}

	var responseMsgErr *saultcommon.ResponseMsgError
	var ok bool
	if responseMsgErr, ok = err.(*saultcommon.ResponseMsgError); !ok {
		return
	}

	// if auth failed, user will directly connect to remote host thru
	// sault(direct-tcpip)
	if responseMsgErr.IsError(saultcommon.CommandErrorAuthFailed) {
		err = injectClientKeyToHostThruSault(
			allFlags[0],
			data,
		)
		if err != nil {
			if responseMsgErr, ok = err.(*saultcommon.ResponseMsgError); !ok {
				return
			}
		}

		if err == nil {
			fmt.Fprintf(os.Stdout, "successfully the sault client key was injected to the remote host\n")
			return
		}
	}

	switch {
	case responseMsgErr.IsError(saultcommon.CommandErrorDialError):
		t, _ := saultcommon.SimpleTemplating(`
failed to inject the internal client key, because could not connect to the host.
		`, nil)
		responseMsgErr.Message = strings.TrimSpace(t)
		return responseMsgErr
	case responseMsgErr.IsError(saultcommon.CommandErrorAuthFailed):
		t, _ := saultcommon.SimpleTemplating(`
failed to inject the internal client key, because could not authenticate the remote host.
		`, nil)
		responseMsgErr.Message = strings.TrimSpace(t)
	case responseMsgErr.IsError(saultcommon.CommandErrorInjectClientKey):
		t, _ := saultcommon.SimpleTemplating(`
failed to inject the internal client key, because something wrong to inject it to the remote host.
		`, nil)
		responseMsgErr.Message = strings.TrimSpace(t)
		return responseMsgErr
	}

	return
}

func (c *hostInjectCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	err = c.response(channel, msg, registry, config)
	if err != nil {
		if responseMsgErr, ok := err.(*saultcommon.ResponseMsgError); ok {
			var response []byte
			response, err = saultcommon.NewResponseMsg(nil, saultcommon.CommandErrorNone, responseMsgErr).ToJSON()
			if err != nil {
				return
			}
			channel.Write(response)
			return
		}
		return
	}

	var response []byte
	response, err = saultcommon.NewResponseMsg(
		nil,
		saultcommon.CommandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return nil
}

func (c *hostInjectCommand) response(channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data hostInjectRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	address := fmt.Sprintf("%s:%d", data.HostName, data.Port)
	rlog := log.WithFields(logrus.Fields{
		"host": address,
	})

	err = checkConnectivity(
		data.Account,
		address,
		config.Server.GetClientKeySigner(),
		time.Second*3,
	)
	if err != nil {
		rlog.Debugf("failed to connect to the remote host")
		return
	}

	rlog.Debugf("trying to inject the client key with client private key")

	// trying to inject client key
	sc := saultcommon.NewSSHClient(data.Account, fmt.Sprintf("%s:%d", data.HostName, data.Port))
	sc.AddAuthMethod(saultssh.PublicKeys(config.Server.GetClientKeySigner()))
	sc.SetTimeout(time.Second * 3)
	defer sc.Close()

	if err = sc.Connect(); err != nil {
		var errType saultcommon.CommandErrorType
		if _, ok := err.(*net.OpError); ok {
			errType = saultcommon.CommandErrorDialError
		} else {
			errType = saultcommon.CommandErrorAuthFailed
		}

		err = &saultcommon.ResponseMsgError{ErrorType: errType, Message: err.Error()}
		rlog.Debug(err)
		return
	}

	err = injectClientKeyToHost(sc, config.Server.GetClientKeySigner().PublicKey())
	if err != nil {
		rlog.Debug(err)
		return saultcommon.NewCommandError(saultcommon.CommandErrorInjectClientKey, err.Error())
	}

	rlog.Debug("successfully injected the client key")
	return nil
}

func injectClientKeyToHostThruSault(
	mainFlags *saultflags.Flags,
	data hostInjectRequestData,
) (err error) {
	log.Debugf("trying to retrieve the client public key from sault server")
	var clientKeyData serverPrintResponseData
	_, err = runCommand(
		mainFlags,
		serverPrintFlagsTemplate.ID,
		[]string{"clientkey"},
		&clientKeyData,
	)
	if err != nil {
		return
	}

	clientPublicKey, _ := saultcommon.ParsePublicKey(clientKeyData.ClientKey[1])
	log.Debugf("got the client public key from sault server: %s", clientKeyData.ClientKey[1])

	log.Debugf("trying to open direct-tcpip connection to sault server")
	saultServer := mainFlags.Values["Sault"].(saultcommon.FlagSaultServer)
	identity := mainFlags.Values["Identity"].(saultcommon.FlagPrivateKey).Signer

	var connection *saultssh.Client
	connection, err = connectSaultServer(saultServer.SaultServerName, saultServer.Address, identity)
	if err != nil {
		return
	}
	defer connection.Close()

	log.Debugf("trying to connect to the remote host thru sault server")
	remoteAddress := fmt.Sprintf("%s:%d", data.HostName, data.Port)
	var conn net.Conn
	conn, err = connection.Dial("tcp", remoteAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	var agent saultsshAgent.Agent
	agent, err = saultcommon.GetSSHAgent()
	if err != nil {
		return
	}

	authMethods := []saultssh.AuthMethod{
		saultssh.PublicKeysCallback(agent.Signers),
		saultssh.RetryableAuthMethod(
			saultssh.PasswordCallback(func() (string, error) {
				return saultcommon.ReadPassword(3)
			}),
			3,
		),
	}

	clientConfig := &saultssh.ClientConfig{
		User:            data.Account,
		Auth:            authMethods,
		HostKeyCallback: saultssh.InsecureIgnoreHostKey(),
	}

	var sc *saultcommon.SSHClient
	{
		c, chans, reqs, err := saultssh.NewClientConn(conn, remoteAddress, clientConfig)
		if err != nil {
			return err
		}
		sc = &saultcommon.SSHClient{
			Client: saultssh.NewClient(c, chans, reqs),
		}
	}

	log.Debugf("successfully connected to the remote host thru sault server")
	err = injectClientKeyToHost(sc, clientPublicKey)
	if err != nil {
		err = saultcommon.NewCommandError(saultcommon.CommandErrorInjectClientKey, err.Error())
		return
	}

	return nil
}
