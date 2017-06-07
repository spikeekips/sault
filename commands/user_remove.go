package saultcommands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/sault"
	"github.com/spikeekips/sault/sssh"
)

var UserRemoveFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "user remove" | yellow }} will remove the existing sault user in the registry of sault server.
		`,
		nil,
	)

	UserRemoveFlagsTemplate = &saultflags.FlagsTemplate{
		ID:          "user remove",
		Name:        "remove",
		Help:        "remove the existing sault user",
		Usage:       "[flags] <user id> [<user id>...]",
		Description: description,
		Flags:       []saultflags.FlagTemplate{},
		ParseFunc:   parseUserRemoveCommandFlags,
	}

	sault.Commands[UserRemoveFlagsTemplate.ID] = &UserRemoveCommand{}
}

func parseUserRemoveCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.FlagSet.Args()
	if len(subArgs) < 1 {
		err = fmt.Errorf("<user id>s are missing")
		return
	}

	for _, a := range subArgs {
		if !saultcommon.CheckUserID(a) {
			err = fmt.Errorf("invalid <user id>, '%s'", a)
			return
		}
	}

	f.Values["UserIDs"] = subArgs

	return nil
}

type UserRemoveCommand struct{}

func (c *UserRemoveCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	ids := thisFlags.Values["UserIDs"].([]string)
	_, err = runCommand(
		allFlags[0],
		UserRemoveFlagsTemplate.ID,
		ids,
		nil,
	)
	if err != nil {
		return
	}

	var m string
	if len(ids) < 2 {
		m = fmt.Sprintf("user, %s was successfully removed", ids[0])
	} else {
		m = fmt.Sprintf("users, %s were successfully removed", strings.Join(ids, ", "))
	}
	fmt.Fprintf(os.Stdout, m+"\n")

	return nil
}

func (c *UserRemoveCommand) Response(channel sssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data []string
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	if len(data) < 1 {
		err = fmt.Errorf("nothing to remove!")
		return
	}

	for _, a := range data {
		if !saultcommon.CheckUserID(a) {
			err = &saultcommon.InvalidUserIDError{ID: a}
			return
		}
		if _, err = registry.GetUser(a, nil, saultregistry.UserFilterNone); err != nil {
			return
		}
	}

	for _, a := range data {
		if err = registry.RemoveUser(a); err != nil {
			return
		}
	}

	registry.Save()

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
