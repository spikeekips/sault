package saultcommands

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/sault"
	"github.com/spikeekips/sault/sssh"
)

var HostAddFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "host add" | yellow }} will add the new host in the registry of sault server.
		`,
		nil,
	)

	HostAddFlagsTemplate = &saultflags.FlagsTemplate{
		ID:          "host add",
		Name:        "add",
		Help:        "add new sault host",
		Usage:       "[flags] <host id> <account>@<host address, hostname:port> [additional accounts...]",
		Description: description,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "IsActive",
				Help:  "set active user",
				Value: true,
			},
		},
		ParseFunc: parseHostAddCommandFlags,
	}

	sault.Commands[HostAddFlagsTemplate.ID] = &HostAddCommand{}
}

func parseHostAddCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.FlagSet.Args()
	if len(subArgs) < 2 {
		err = fmt.Errorf("wrong usage")
		return
	}

	hostID, fullAddress, accounts := subArgs[0], subArgs[1], subArgs[2:]
	log.Debugf("parsed subArgs: hostID=%v fullAddress=%v accounts=%v", hostID, fullAddress, accounts)

	if !saultcommon.CheckHostID(hostID) {
		err = &saultcommon.InvalidHostIDError{ID: hostID}
		return
	}

	var account, address string
	if account, address, err = saultcommon.ParseHostAccount(fullAddress); err != nil {
		return
	}
	if len(account) < 1 {
		err = fmt.Errorf("account name must be set in host address")
		return
	}

	accounts = append(accounts, account)
	for _, a := range accounts {
		if !saultcommon.CheckAccountName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}

	var hostName string
	var port uint64
	if hostName, port, err = saultcommon.SplitHostPort(address, uint64(22)); err != nil {
		return
	}

	f.Values["Host"] = HostAddRequestData{
		ID:       hostID,
		HostName: hostName,
		Port:     port,
		Accounts: accounts,
		IsActive: f.Values["IsActive"].(bool),
	}

	return nil
}

type HostAddRequestData struct {
	ID         string
	HostName   string
	Port       uint64
	Accounts   []string
	IsActive   bool
	Passphrase string
}

type HostAddCommand struct{}

var hostAddHelpFirstMessage = `
{{ "error" | red }} failed to complete to add host, because not authenticated to your host from sault server'.
{{ line "-" }}
{{ "note" | note }}
* sault supports to inject the public key into your host automatically with passphrase.
* If your host does not support password authentication, or you don't know it's passphrase, just hit Control-C. You can manually append the sault client public key into your host account.
* To verify the sault client public key, use {{ "$ sault server print clientkey" | magenta }}
* sault does not remember your passphrase :)
{{ line "-" }}
Enter passphrase to inject the sault client key into your host, or you can skip this step with {{ "-f" | yellow }} flag.
`

var hostAddHelpNextMessage = `
{{ "error" | red }} failed to authenticate, it maybe wrong passphrase. Try again.
`

func (c *HostAddCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := thisFlags.Values["Host"].(HostAddRequestData)

	run := func(passphrase string) error {
		data.Passphrase = passphrase

		var host saultregistry.HostRegistry
		_, err := runCommand(
			allFlags[0],
			HostAddFlagsTemplate.ID,
			data,
			&host,
		)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, PrintHostData(
			"host-added",
			allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
			host,
			nil,
		))

		return nil
	}

	err = passphraseChallenge(run)
	return
}

func (c *HostAddCommand) Response(channel sssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data HostAddRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	if _, err = registry.GetHost(data.ID, saultregistry.HostFilterNone); err == nil {
		err = &saultregistry.HostExistError{ID: data.ID}
		return
	}

	slog := log.WithFields(logrus.Fields{
		"Address": fmt.Sprintf("%s@%s:%d", data.Accounts[0], data.HostName, data.Port),
	})

	slog.Debugf("trying to connect")

	var authMethod sssh.AuthMethod
	if len(data.Passphrase) < 1 {
		authMethod = sssh.PublicKeys(config.Server.GetClientKeySigner())
	} else {
		authMethod = sssh.Password(data.Passphrase)
	}

	sc := saultcommon.NewSSHClient(data.Accounts[0], fmt.Sprintf("%s:%d", data.HostName, data.Port))
	sc.AddAuthMethod(authMethod)
	sc.SetTimeout(time.Second * 3)
	defer sc.Close()

	if err = sc.Connect(); err != nil {
		slog.Error(err)

		var errType saultcommon.CommandErrorType
		if _, ok := err.(*net.OpError); ok {
			errType = saultcommon.CommandErrorDialError
		} else {
			errType = saultcommon.CommandErrorAuthFailed
		}

		var response []byte
		response, err = saultcommon.NewResponseMsg(nil, errType, err).ToJSON()
		if err != nil {
			return
		}

		channel.Write(response)
		return
	}

	slog.Debugf("successfully connected; and then trying to inject client key.")

	err = injectClientKeyToHost(sc, config.Server.GetClientKeySigner().PublicKey())
	if err != nil {
		slog.Error(err)
		var response []byte
		response, err = saultcommon.NewResponseMsg(nil, saultcommon.CommandErrorInjectClientKey, err).ToJSON()
		if err != nil {
			return
		}

		channel.Write(response)
		return
	}

	var host saultregistry.HostRegistry
	if host, err = registry.AddHost(data.ID, data.HostName, data.Port, data.Accounts); err != nil {
		return
	}
	if host.IsActive != data.IsActive {
		host.IsActive = data.IsActive
		host, _ = registry.UpdateHost(host.ID, host)
	}

	registry.Save()

	var response []byte
	response, err = saultcommon.NewResponseMsg(
		host,
		saultcommon.CommandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return nil
}
