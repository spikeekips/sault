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

var hostUpdateFlagsTemplate *saultflags.FlagsTemplate

type flagHostUpdateNewID struct {
	IsSet bool
	Value string
}

func (f *flagHostUpdateNewID) String() string { return f.Value }

func (f *flagHostUpdateNewID) Set(v string) error {
	f.Value = v
	f.IsSet = true
	return nil
}

type flagHostUpdateNewIsActive struct {
	IsSet bool
	Value bool
}

func (f *flagHostUpdateNewIsActive) String() string { return "true" }

func (f *flagHostUpdateNewIsActive) Set(v string) error {
	p, err := saultcommon.ParseBooleanString(v)
	if err != nil {
		return err
	}
	f.Value = p
	f.IsSet = true
	return nil
}

type flagHostUpdateNewAddress struct {
	IsSet    bool
	HostName string
	Port     uint64
}

func (f *flagHostUpdateNewAddress) String() string { return "true" }

func (f *flagHostUpdateNewAddress) Set(v string) error {
	hostName, port, err := saultcommon.SplitHostPort(v, uint64(22))
	if err != nil {
		return err
	}

	f.HostName = hostName
	f.Port = port
	f.IsSet = true
	return nil
}

type flagHostUpdateNewAccounts struct {
	IsSet bool
	Value []string
}

func (f *flagHostUpdateNewAccounts) String() string { return "true" }

func (f *flagHostUpdateNewAccounts) Set(v string) error {
	accounts := saultcommon.StringFilter(
		strings.Fields(v),
		func(s string) bool {
			return len(strings.TrimSpace(s)) > 0
		},
	)
	if len(accounts) < 1 {
		return fmt.Errorf("empty accounts")
	}

	for _, a := range accounts {
		if !saultcommon.CheckAccountName(a) {
			return &saultcommon.InvalidAccountNameError{Name: a}
		}
	}

	f.Value = accounts
	f.IsSet = true
	return nil
}

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "host update" | yellow }} will update the host in the registry of sault server.
		`,
		nil,
	)

	var hostUpdateNewIDFlag flagHostUpdateNewID
	var hostUpdateNewIsActiveFlag flagHostUpdateNewIsActive
	var hostUpdateNewAddress flagHostUpdateNewAddress
	var hostUpdateNewAccounts flagHostUpdateNewAccounts
	hostUpdateFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "host update",
		Name:         "update",
		Help:         "update the remote host",
		Usage:        "<host id> [flags]",
		Description:  description,
		IsPositioned: true,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "ID",
				Help:  "set new remote host id",
				Value: &hostUpdateNewIDFlag,
			},
			saultflags.FlagTemplate{
				Name:  "IsActive",
				Help:  "set active host [true false]",
				Value: &hostUpdateNewIsActiveFlag,
			},
			saultflags.FlagTemplate{
				Name:  "Accounts",
				Help:  "set accounts, \"A B C\"",
				Value: &hostUpdateNewAccounts,
			},
			saultflags.FlagTemplate{
				Name:  "Address",
				Help:  "set host adddress, \"<hostname or ip>:<port default 22>\"",
				Value: &hostUpdateNewAddress,
			},
			saultflags.FlagTemplate{
				Name:  "SkipTest",
				Help:  "skip connectivity check, only available with the new address",
				Value: false,
			},
		},
		ParseFunc: parseHostUpdateCommandFlags,
	}

	sault.Commands[hostUpdateFlagsTemplate.ID] = &hostUpdateCommand{}
}

func parseHostUpdateCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	if len(subArgs) != 1 {
		err = fmt.Errorf("wrong usage")
		return
	}

	if !saultcommon.CheckUserID(subArgs[0]) {
		err = &saultcommon.InvalidUserIDError{ID: subArgs[0]}
		return
	}

	newHost := hostUpdateRequestData{
		ID:       subArgs[0],
		SkipTest: f.Values["SkipTest"].(bool),
	}
	{
		v := f.Values["ID"].(flagHostUpdateNewID)
		if v.IsSet {
			newHost.NewID = v
		}
	}
	{
		v := f.Values["Accounts"].(flagHostUpdateNewAccounts)
		if v.IsSet {
			newHost.NewAccounts = v
		}
	}
	{
		v := f.Values["Address"].(flagHostUpdateNewAddress)
		if v.IsSet {
			newHost.NewAddress = v
		}
	}
	{
		v := f.Values["IsActive"].(flagHostUpdateNewIsActive)
		if v.IsSet {
			newHost.NewIsActive = v
		}
	}

	f.Values["NewHost"] = newHost

	return nil
}

type hostUpdateRequestData struct {
	ID          string
	NewID       flagHostUpdateNewID
	NewAddress  flagHostUpdateNewAddress
	NewAccounts flagHostUpdateNewAccounts
	NewIsActive flagHostUpdateNewIsActive
	SkipTest    bool
}

type hostUpdateResponsetData struct {
	Host saultregistry.HostRegistry
	Err  string
}

type hostUpdateCommand struct{}

func (c *hostUpdateCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := thisFlags.Values["NewHost"]

	var result hostUpdateResponsetData
	_, err = runCommand(
		allFlags[0],
		hostUpdateFlagsTemplate.ID,
		data,
		&result,
	)
	if err == nil {
		var resultErr error
		if len(result.Err) > 0 {
			resultErr = fmt.Errorf(result.Err)
		}

		fmt.Fprintf(os.Stdout, printHostData(
			"host-updated",
			allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
			result.Host,
			resultErr,
		))
	}

	var responseMsgErr *saultcommon.ResponseMsgError
	var ok bool
	if responseMsgErr, ok = err.(*saultcommon.ResponseMsgError); !ok {
		return
	}

	if responseMsgErr.IsError(saultcommon.CommandErrorDialError) {
		t, _ := saultcommon.SimpleTemplating(`
failed to update host, because could not connect to the host.
{{ "HELP" | note }} You can use {{ "-skiptest" | yellow }} flag, it can skip the connectivity test.
		`, nil)
		responseMsgErr.Message = strings.TrimSpace(t)
	}

	return responseMsgErr
}

func (c *hostUpdateCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data hostUpdateRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	var host saultregistry.HostRegistry
	if host, err = registry.GetHost(data.ID, saultregistry.HostFilterNone); err != nil {
		return
	}

	if !data.SkipTest {
		newAddress := fmt.Sprintf("%s:%d", data.NewAddress.HostName, data.NewAddress.Port)
		if host.GetAddress() != newAddress {
			err = checkConnectivity(
				host.Accounts[0],
				newAddress,
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
	}

	oldID := data.ID
	if data.NewID.IsSet {
		host.ID = data.NewID.Value
	}
	if data.NewAddress.IsSet {
		host.HostName = data.NewAddress.HostName
		host.Port = data.NewAddress.Port
	}
	if data.NewAccounts.IsSet {
		host.Accounts = data.NewAccounts.Value
	}
	if data.NewIsActive.IsSet {
		host.IsActive = data.NewIsActive.Value
	}

	var errString string
	var notUpdated bool
	if host, err = registry.UpdateHost(oldID, host); err != nil {
		errNothingToUpdate, ok := err.(*saultcommon.HostNothingToUpdate)
		if !ok {
			return
		}
		errString = errNothingToUpdate.Error()
		notUpdated = true
	}

	if !notUpdated {
		registry.Save()
	}

	var response []byte
	response, err = saultcommon.NewResponseMsg(
		hostUpdateResponsetData{
			Host: host,
			Err:  errString,
		},
		saultcommon.CommandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return nil
}
