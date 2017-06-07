package saultcommands

import (
	"fmt"
	"os"

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
	ID       string
	HostName string
	Port     uint64
	Accounts []string
	IsActive bool
}

type HostAddCommand struct{}

func (c *HostAddCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := thisFlags.Values["Host"]

	var host saultregistry.HostRegistry
	_, err = runCommand(
		allFlags[0],
		HostAddFlagsTemplate.ID,
		data,
		&host,
	)
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, PrintHostData(
		"host-added",
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		host,
		nil,
	))

	return nil
}

func (c *HostAddCommand) Response(channel sssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data HostAddRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	// TODO: inject client key
	// TODO: check connectivity

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
