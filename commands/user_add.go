package saultcommands

import (
	"fmt"
	"os"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var UserAddFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "user add" | yellow }} will add the new sault user in the registry of sault server.

		`,
		nil,
	)

	UserAddFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "user add",
		Name:         "add",
		Help:         "add new sault user",
		Usage:        "<user id> <public key file> [flags]",
		Description:  description,
		IsPositioned: true,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "IsAdmin",
				Help:  "set admin (default is not admin)",
				Value: false,
			},
			saultflags.FlagTemplate{
				Name:  "IsActive",
				Help:  "set active user",
				Value: true,
			},
		},
		ParseFunc: parseUserAddCommandFlags,
	}

	sault.Commands[UserAddFlagsTemplate.ID] = &UserAddCommand{}
}

func parseUserAddCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	if len(subArgs) < 1 {
		err = fmt.Errorf("<user id> and <public key file> are missing")
		return
	}

	if len(subArgs) < 2 {
		err = fmt.Errorf("<public key file> is missing")
		return
	}

	userID, publicKey := subArgs[0], subArgs[1]
	if !saultcommon.CheckUserID(userID) {
		err = fmt.Errorf("invalid <user id>, '%s'", userID)
		return
	}
	publicKeyFlag := &flagPublicKey{ErrorFormat: "wrong <pubic key file>: %v"}
	err = publicKeyFlag.Set(publicKey)
	if err != nil {
		return
	}

	f.Values["ID"] = userID
	f.Values["PublicKey"] = publicKeyFlag.PublicKey

	return nil
}

type UserAddRequestData struct {
	ID        string
	PublicKey []byte
	IsAdmin   bool
	IsActive  bool
}

type UserAddCommand struct{}

func (c *UserAddCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := UserAddRequestData{
		ID:        thisFlags.Values["ID"].(string),
		PublicKey: thisFlags.Values["PublicKey"].([]byte),
		IsActive:  thisFlags.Values["IsActive"].(bool),
		IsAdmin:   thisFlags.Values["IsAdmin"].(bool),
	}

	var user saultregistry.UserRegistry
	_, err = runCommand(
		allFlags[0],
		UserAddFlagsTemplate.ID,
		data,
		&user,
	)
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, PrintUserData(
		"one-user",
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		UserListResponseUserData{User: user},
		nil,
	))

	return nil
}

func (c *UserAddCommand) Response(u saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data UserAddRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	var user saultregistry.UserRegistry
	if user, err = registry.AddUser(data.ID, data.PublicKey); err != nil {
		return
	}

	user.IsAdmin = data.IsAdmin
	user.IsActive = data.IsActive
	if user, err = registry.UpdateUser(user.ID, user); err != nil {
		return
	}

	registry.Save()

	var response []byte
	response, err = saultcommon.NewResponseMsg(
		user,
		saultcommon.CommandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return nil
}
