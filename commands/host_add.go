package saultcommands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var hostAddFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "host add" | yellow }} will add the new host in the registry of sault server.
By default, the sault server tries to check the connection to your host. If authentication error is orrucred, 

* {{ "host inject" | yellow }} helps to inject the internal client key to remote host
* or with {{ "-f" | yellow }} flag, you can force to add the host.
		`,
		nil,
	)

	hostAddFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "host add",
		Name:         "add",
		Help:         "add new remote host",
		Usage:        "<host id> <account>@<host address, hostname:port> [additional accounts...] [flags]",
		Description:  description,
		IsPositioned: true,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "SkipTest",
				Help:  "skip connectivity check",
				Value: false,
			},
			saultflags.FlagTemplate{
				Name:  "IsActive",
				Help:  "set active user",
				Value: true,
			},
		},
		ParseFunc: parseHostAddCommandFlags,
	}

	sault.Commands[hostAddFlagsTemplate.ID] = &hostAddCommand{}
}

func parseHostAddCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
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

	f.Values["Host"] = hostAddRequestData{
		ID:       hostID,
		HostName: hostName,
		Port:     port,
		Accounts: accounts,
		IsActive: f.Values["IsActive"].(bool),
		SkipTest: f.Values["SkipTest"].(bool),
	}

	return nil
}

type hostAddRequestData struct {
	ID       string
	HostName string
	Port     uint64
	Accounts []string
	IsActive bool

	SkipTest bool
}

type hostAddCommand struct{}

func (c *hostAddCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := thisFlags.Values["Host"].(hostAddRequestData)

	var host saultregistry.HostRegistry
	_, err = runCommand(
		allFlags[0],
		hostAddFlagsTemplate.ID,
		data,
		&host,
	)
	if err == nil {
		fmt.Fprintf(os.Stdout, printHostData(
			"host-added",
			allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
			host,
			nil,
		))
	}

	var responseMsgErr *saultcommon.ResponseMsgError
	var ok bool
	if responseMsgErr, ok = err.(*saultcommon.ResponseMsgError); !ok {
		return
	}

	if responseMsgErr.IsError(saultcommon.CommandErrorDialError) {
		t, _ := saultcommon.SimpleTemplating(`
failed to add host, because could not connect to the host.
{{ "HELP" | note }} You can use {{ "-skiptest" | yellow }} flag, it can skip the connectivity test.
		`, nil)
		responseMsgErr.Message = strings.TrimSpace(t)
	}

	return responseMsgErr
}

func (c *hostAddCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data hostAddRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	if _, err = registry.GetHost(data.ID, saultregistry.HostFilterNone); err == nil {
		err = &saultcommon.HostExistError{ID: data.ID}
		return
	}

	if !data.SkipTest {
		err = checkConnectivity(
			data.Accounts[0],
			fmt.Sprintf("%s:%d", data.HostName, data.Port),
			config.Server.GetClientKeySigner(),
			time.Second*3,
		)

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
