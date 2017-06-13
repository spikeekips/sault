package saultcommands

import (
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

func init() {
	sault.Commands["whoami"] = &UserWhoAmICommand{}
}

type UserWhoAmICommand struct{}

func (c *UserWhoAmICommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	return nil
}

func (c *UserWhoAmICommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var links []UserLinkAccountData
	for hostID, link := range registry.GetLinksOfUser(user.ID) {
		_, err := registry.GetHost(hostID, saultregistry.HostFilterNone)
		if err != nil {
			log.Errorf("UserListCommand.Response: %v", err)
			continue
		}
		links = append(
			links,
			UserLinkAccountData{
				Accounts: link.Accounts,
				All:      link.All,
				HostID:   hostID,
			},
		)
	}

	printed := PrintUserData(
		"whoami",
		"<sault server>",
		UserListResponseUserData{
			User:  user,
			Links: links,
		},
		nil,
	)

	channel.Write([]byte(printed))

	return nil
}
