package saultcommands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var userLinkFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "user link" | yellow }} will link the sault user to the host. For examples,

{{ "$ sault user link spikeekips prometeus ubuntu root" | magenta }}:
This will allow the user, 'spikeekips' to access to the 'prometeus' host with the account, 'ubuntu' and 'root'

{{ "$ sault user link spikeekips prometeus ubuntu- root" | magenta }}:
With appending '-' at the end of account name, it will disallow the user, 'spikeekips' to access to the 'prometeus' host with the account, 'ubuntu', but allow for 'root'

{{ "$ sault user link spikeekips prometeus" | magenta }}:
Such like this case, if the '<account>'s is not specified, the user 'spikeekips' can use the all the available accounts of 'prometeus' host.

{{ "$ sault user link spikeekips prometeus-" | magenta }}:
Such like appending '-' at the end of account name, this will disallow the user 'spikeekips' to access to the host, 'prometeus'.

		`,
		nil,
	)

	userLinkFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "user link",
		Name:         "link",
		Help:         "link to the remote host",
		Usage:        "<user id> <host id> [<account>...] [flags]",
		Description:  description,
		IsPositioned: true,
		Flags:        []saultflags.FlagTemplate{},
		ParseFunc:    parseUserLinkCommandFlags,
	}

	sault.Commands[userLinkFlagsTemplate.ID] = &userLinkCommand{}
}

func parseUserLinkCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	if len(subArgs) < 2 {
		err = fmt.Errorf("wrong usage")
		return
	}

	userID := subArgs[0]
	if !saultcommon.CheckUserID(userID) {
		err = &saultcommon.InvalidUserIDError{ID: userID}
		return
	}

	data := userLinkRequestData{UserID: userID}

	hostID, minus := saultcommon.ParseMinusName(subArgs[1])
	if !saultcommon.CheckHostID(hostID) {
		err = &saultcommon.InvalidHostIDError{ID: hostID}
		return
	}
	data.HostID = hostID
	data.UnlinkAll = minus

	if data.UnlinkAll {
		f.Values["Link"] = data
		return
	}

	accounts := subArgs[2:]
	if len(accounts) < 1 {
		data.LinkAll = true
		f.Values["Link"] = data
		return
	}

	var willAdd, willRemove []string
	for _, a := range accounts {
		account, minue := saultcommon.ParseMinusName(a)
		if !saultcommon.CheckAccountName(account) {
			err = &saultcommon.InvalidAccountNameError{Name: account}
			return
		}
		if minue {
			willRemove = append(willRemove, account)
		} else {
			willAdd = append(willAdd, account)
		}
	}
	if len(willAdd) < 1 && len(willRemove) < 1 {
		err = fmt.Errorf("nothing to update")
		return
	}
	data.AccountsAdd = willAdd
	data.AccountsRemove = willRemove

	f.Values["Link"] = data
	return nil
}

type userLinkRequestData struct {
	UserID         string
	HostID         string
	AccountsAdd    []string
	AccountsRemove []string
	UnlinkAll      bool
	LinkAll        bool
}

type userLinkCommand struct{}

func (c *userLinkCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	var result userListResponseUserData
	_, err = runCommand(
		allFlags[0],
		userLinkFlagsTemplate.ID,
		thisFlags.Values["Link"].(userLinkRequestData),
		&result,
	)

	if err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, printUserData(
		"one-user-updated",
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		result,
		nil,
	))

	return nil
}

func (c *userLinkCommand) Response(u saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data userLinkRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	var user saultregistry.UserRegistry
	if user, err = registry.GetUser(data.UserID, nil, saultregistry.UserFilterNone); err != nil {
		return
	}

	var host saultregistry.HostRegistry
	if host, err = registry.GetHost(data.HostID, saultregistry.HostFilterNone); err != nil {
		return
	}

	var unknowns []string
	if len(data.AccountsAdd) > 0 && !host.HasAccount(data.AccountsAdd...) {
		for _, a := range data.AccountsAdd {
			var found bool
			for _, b := range host.Accounts {
				if a == b {
					found = true
					break
				}
			}
			if !found {
				unknowns = append(unknowns, a)
			}
		}
	}

	if len(data.AccountsRemove) > 0 && !host.HasAccount(data.AccountsRemove...) {
		for _, a := range data.AccountsRemove {
			var found bool
			for _, b := range host.Accounts {
				if a == b {
					found = true
					break
				}
			}
			if !found {
				unknowns = append(unknowns, a)
			}
		}
	}

	if len(unknowns) > 0 {
		err = fmt.Errorf("unknown accounts found, %s", strings.Join(unknowns, ", "))
		return
	}

	if data.LinkAll {
		if err = registry.LinkAll(user.ID, host.ID); err != nil {
			return
		}
	} else if data.UnlinkAll {
		if err = registry.UnlinkAll(user.ID, host.ID); err != nil {
			return
		}
	} else {
		if len(data.AccountsAdd) > 0 {
			if err = registry.Link(user.ID, host.ID, data.AccountsAdd...); err != nil {
				return
			}
		}
		if len(data.AccountsRemove) > 0 {
			if err = registry.Unlink(user.ID, host.ID, data.AccountsRemove...); err != nil {
				return
			}
		}
	}

	var links []userLinkAccountData
	for hostID, link := range registry.GetLinksOfUser(user.ID) {
		_, err := registry.GetHost(hostID, saultregistry.HostFilterNone)
		if err != nil {
			log.Errorf("UserListCommand.Response: %v", err)
			continue
		}
		links = append(
			links,
			userLinkAccountData{
				Accounts: link.Accounts,
				All:      link.All,
				HostID:   hostID,
			},
		)
	}

	registry.Save()

	result := userListResponseUserData{
		User:  user,
		Links: links,
	}

	var response []byte
	response, err = saultcommon.NewResponseMsg(
		result,
		saultcommon.CommandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return nil
}
