package saultcommands

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var UserListFlagsTemplate *saultflags.FlagsTemplate

type flagUserFilters struct {
	Combined saultregistry.UserFilter
	Args     []string
}

func (f *flagUserFilters) String() string {
	return fmt.Sprintf("[ %s ]", strings.Join(f.Args, " "))
}

func (f *flagUserFilters) Set(v string) (err error) {
	filters := saultregistry.UserFilter(f.Combined)

	findUserFilter := func(u saultregistry.UserFilter) bool {
		return filters&u == u
	}

	var filter saultregistry.UserFilter
	switch v {
	case "admin":
		if findUserFilter(saultregistry.UserFilterIsNotAdmin) {
			err = fmt.Errorf("'admin' can not be with 'admin-'")
			return
		}

		filter = saultregistry.UserFilterIsAdmin
	case "admin-":
		if findUserFilter(saultregistry.UserFilterIsAdmin) {
			err = fmt.Errorf("'admin-' can not be with 'admin'")
			return
		}

		filter = saultregistry.UserFilterIsNotAdmin
	case "active":
		if findUserFilter(saultregistry.UserFilterIsNotActive) {
			err = fmt.Errorf("'active' can not be with 'active-'")
			return
		}

		filter = saultregistry.UserFilterIsActive
	case "active-":
		if findUserFilter(saultregistry.UserFilterIsActive) {
			err = fmt.Errorf("'active-' can not be with 'active'")
			return
		}

		filter = saultregistry.UserFilterIsNotActive
	default:
		err = fmt.Errorf("unknown filter name, '%s'", v)
		return
	}

	filters |= filter

	args := f.Args
	args = append(args, v)
	*f = flagUserFilters{Combined: filters, Args: args}

	return
}

type flagPublicKey struct {
	Path        string
	PublicKey   []byte
	ErrorFormat string
}

func (f *flagPublicKey) String() string {
	return string(f.Path)
}

func (f *flagPublicKey) Set(v string) (err error) {
	if len(f.ErrorFormat) < 1 {
		f.ErrorFormat = "wrong -publicKey: %v"
	}

	if _, err = os.Stat(v); err != nil {
		if pathError, ok := err.(*os.PathError); ok {
			err = pathError.Err
		}
		return fmt.Errorf(f.ErrorFormat, err)
	}

	var b []byte
	if b, err = ioutil.ReadFile(v); err != nil {
		return fmt.Errorf(f.ErrorFormat, err)
	}

	if _, err = saultcommon.ParsePublicKey(b); err != nil {
		return fmt.Errorf(f.ErrorFormat, err)
	}

	*f = flagPublicKey{Path: v, PublicKey: b}

	return nil
}

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "user list" | yellow }} gets the registered sault users information from sault server.

The belowed flags help to get the sault users from sault server, by default, it shows all registered sault users.
{{ "-publicKey <public key file>" | yellow }}:
  If you set the public key file with '{{ "-publicKey" | yellow }}', the user, which has the public key will be listed.
  {{ "NOTE" | note }} In sault, the public key is unique in sault users.

{{ "-filter <mode>" | yellow }}:
  With filter, you can filter the users list, {{ "admin" | yellow }} is only for admin users and {{ "active" | yellow }}: is only for active users. With appending '{{ "-" | yellow }}', you can remove the admin or active user. For examples,
  * {{ "-filter \"admin\"" | yellow }}: admin users
  * {{ "-filter \"active\"" | yellow }}: active users
  * {{ "-filter \"admin active\"" | yellow }}: admin and active users
  * {{ "-filter \"admin- active\"" | yellow }}: not admin and active users
		`,
		nil,
	)

	publicKeyFlag := new(flagPublicKey)
	userFilters := new(flagUserFilters)
	UserListFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "user list",
		Name:         "list",
		Help:         "get users information",
		Usage:        "[<user id>...] [flags]",
		Description:  description,
		IsPositioned: true,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "Filter",
				Help:  "filter users, [ admin[-] active[-]]",
				Value: userFilters,
			},
			saultflags.FlagTemplate{
				Name:  "PublicKey",
				Help:  "get user, matched with public key",
				Value: publicKeyFlag,
			},
		},
		ParseFunc: parseUserListCommandFlags,
	}

	sault.Commands[UserListFlagsTemplate.ID] = &UserListCommand{}
}

func parseUserListCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()

	for _, a := range subArgs {
		if !saultcommon.CheckUserID(a) {
			err = &saultcommon.InvalidUserIDError{ID: a}
			return
		}
	}

	f.Values["UserIDs"] = subArgs

	return nil
}

type UserListRequestData struct {
	Filters   saultregistry.UserFilter
	UserIDs   []string
	PublicKey []byte
}

type UserLinkAccountData struct {
	HostID   string
	Accounts []string
	All      bool
}

type UserListResponseUserData struct {
	User  saultregistry.UserRegistry
	Links []UserLinkAccountData
}

type UserListResponseData []UserListResponseUserData

type UserListCommand struct{}

func (c *UserListCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	var users []UserListResponseUserData

	flagFilter := thisFlags.Values["Filter"].(flagUserFilters)
	log.Debugf("get users, filters: %s UserIDs: %s PublicKey: %s", flagFilter.Args, thisFlags.Values["UserIDs"], thisFlags.Values["PublicKey"].(flagPublicKey).Path)

	_, err = runCommand(
		allFlags[0],
		UserListFlagsTemplate.ID,
		UserListRequestData{
			Filters:   saultregistry.UserFilter(flagFilter.Combined),
			UserIDs:   thisFlags.Values["UserIDs"].([]string),
			PublicKey: thisFlags.Values["PublicKey"].(flagPublicKey).PublicKey,
		},
		&users,
	)
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, PrintUsersData(
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		users,
	))

	return nil
}

func (c *UserListCommand) Response(channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data UserListRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	var parsedPublicKey saultssh.PublicKey
	if len(data.PublicKey) > 0 {
		parsedPublicKey, err = saultcommon.ParsePublicKey(data.PublicKey)
		if err != nil {
			return
		}
	}

	result := []UserListResponseUserData{}
	for _, u := range registry.GetUsers(data.Filters, data.UserIDs...) {
		if parsedPublicKey != nil && !u.HasPublicKey(parsedPublicKey) {
			continue
		}

		var links []UserLinkAccountData
		for hostID, link := range registry.GetLinksOfUser(u.ID) {
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

		result = append(
			result,
			UserListResponseUserData{
				User:  u,
				Links: links,
			},
		)
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
