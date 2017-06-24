package saultcommands

import (
	"fmt"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

func init() {
	sault.Commands["publickey"] = &userPublicKeyCommand{}
}

type userPublicKeyCommand struct{}

func (c *userPublicKeyCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	return nil
}

func (c *userPublicKeyCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {

	var args []string
	err = msg.GetData(&args)
	if err != nil {
		return err
	}

	if len(args) < 1 {
		return sault.Commands["whoami"].Response(user, channel, msg, registry, config)
	}

	var publicKey saultssh.PublicKey
	userID := args[0]

	if user.ID != userID {
		err = fmt.Errorf(`the connected user is '%s', not '%s'.
Usage: publickey <user id> <public key string>`, user.ID, userID)
		return
	}

	publicKeyString := strings.Join(args[1:], " ")
	publicKey, err = saultcommon.ParsePublicKey([]byte(publicKeyString))
	if err != nil {
		err = fmt.Errorf(`%s
Usage: publickey <user id> <public key string>`, err)
		return
	}

	if user.HasPublicKey(publicKey) {
		err = fmt.Errorf("this public key is already registered")
		return
	}

	user.PublicKey = []byte(publicKeyString)

	var newUser saultregistry.UserRegistry
	newUser, err = registry.UpdateUser(user.ID, user)
	if err != nil {
		return
	}

	registry.Save()

	var links []userLinkAccountData
	for hostID, link := range registry.GetLinksOfUser(newUser.ID) {
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

	printed := printUserData(
		"one-user-updated",
		"<sault server>",
		userListResponseUserData{
			User:  newUser,
			Links: links,
		},
		nil,
	)

	channel.Write([]byte(printed))

	return nil
}
