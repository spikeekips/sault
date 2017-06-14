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

var userUpdateFlagsTemplate *saultflags.FlagsTemplate

type flagUserUpdateNewID struct {
	IsSet bool
	Value string
}

func (f *flagUserUpdateNewID) String() string { return f.Value }

func (f *flagUserUpdateNewID) Set(v string) error {
	f.Value = v
	f.IsSet = true
	return nil
}

type flagUserUpdateNewIsAdmin struct {
	IsSet bool
	Value bool
}

func (f *flagUserUpdateNewIsAdmin) String() string { return "true" }

func (f *flagUserUpdateNewIsAdmin) Set(v string) error {
	p, err := saultcommon.ParseBooleanString(v)
	if err != nil {
		return err
	}

	f.Value = p
	f.IsSet = true
	return nil
}

type flagUserUpdateNewIsActive struct {
	IsSet bool
	Value bool
}

func (f *flagUserUpdateNewIsActive) String() string { return "true" }

func (f *flagUserUpdateNewIsActive) Set(v string) error {
	p, err := saultcommon.ParseBooleanString(v)
	if err != nil {
		return err
	}
	f.Value = p
	f.IsSet = true
	return nil
}

type flagUserUpdateNewPublicKey struct {
	IsSet bool
	Value []byte
}

func (f *flagUserUpdateNewPublicKey) String() string { return "true" }

func (f *flagUserUpdateNewPublicKey) Set(v string) (err error) {
	fp := &flagPublicKey{ErrorFormat: "wrong -publicKey: %v"}
	if err = fp.Set(v); err != nil {
		return
	}

	f.IsSet = true
	f.Value = fp.PublicKey
	return nil
}

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "user update" | yellow }} will update the sault user in the registry of sault server.
		`,
		nil,
	)

	var userUpdateNewIDflag flagUserUpdateNewID
	var userUpdateNewIsAdminflag flagUserUpdateNewIsAdmin
	var userUpdateNewIsActiveflag flagUserUpdateNewIsActive
	var userUpdateNewPublicKey flagUserUpdateNewPublicKey

	userUpdateFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "user update",
		Name:         "update",
		Help:         "update the sault user",
		Usage:        "<user id> [flags]",
		Description:  description,
		IsPositioned: true,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "ID",
				Help:  "set new sault user id",
				Value: &userUpdateNewIDflag,
			},
			saultflags.FlagTemplate{
				Name:  "IsAdmin",
				Help:  "set admin [true false]",
				Value: &userUpdateNewIsAdminflag,
			},
			saultflags.FlagTemplate{
				Name:  "IsActive",
				Help:  "set active user [true false]",
				Value: &userUpdateNewIsActiveflag,
			},
			saultflags.FlagTemplate{
				Name:  "PublicKey",
				Help:  "set public key file",
				Value: &userUpdateNewPublicKey,
			},
		},
		ParseFunc: parseUserUpdateCommandFlags,
	}

	sault.Commands[userUpdateFlagsTemplate.ID] = &userUpdateCommand{}
}

func parseUserUpdateCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	if len(subArgs) < 1 {
		err = fmt.Errorf("<user id> is missing")
		return
	}
	if len(subArgs) != 1 {
		err = fmt.Errorf("wrong usage")
		return
	}
	if !saultcommon.CheckUserID(subArgs[0]) {
		err = &saultcommon.InvalidUserIDError{ID: subArgs[0]}
		return
	}

	newUser := userUpdateRequestData{}

	var hasValue bool
	{
		v := f.Values["ID"].(flagUserUpdateNewID)
		if v.IsSet {
			newUser.NewID = v
			hasValue = true
		}
	}
	{
		v := f.Values["IsAdmin"].(flagUserUpdateNewIsAdmin)
		if v.IsSet {
			newUser.NewIsAdmin = v
			hasValue = true
		}
	}
	{
		v := f.Values["IsActive"].(flagUserUpdateNewIsActive)
		if v.IsSet {
			newUser.NewIsActive = v
			hasValue = true
		}
	}
	{
		v := f.Values["PublicKey"].(flagUserUpdateNewPublicKey)
		if v.IsSet {
			newUser.NewPublicKey = v
			hasValue = true
		}
	}
	if !hasValue {
		err = fmt.Errorf("set the one more new values")
		return
	}

	newUser.ID = subArgs[0]
	f.Values["NewUser"] = newUser

	return nil
}

type userUpdateRequestData struct {
	ID           string
	NewID        flagUserUpdateNewID
	NewPublicKey flagUserUpdateNewPublicKey
	NewIsAdmin   flagUserUpdateNewIsAdmin
	NewIsActive  flagUserUpdateNewIsActive
}

type userUpdateResponseData struct {
	User saultregistry.UserRegistry
	Err  string
}

type userUpdateCommand struct{}

func (c *userUpdateCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	data := thisFlags.Values["NewUser"].(userUpdateRequestData)

	var result userUpdateResponseData
	_, err = runCommand(
		allFlags[0],
		userUpdateFlagsTemplate.ID,
		data,
		&result,
	)

	if err != nil {
		return
	}

	var resultErr error
	if len(result.Err) > 0 {
		resultErr = fmt.Errorf(result.Err)
	}

	fmt.Fprintf(os.Stdout, printUserData(
		"one-user-updated",
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		userListResponseUserData{User: result.User},
		resultErr,
	))

	return nil
}

func (c *userUpdateCommand) Response(u saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data userUpdateRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	var user saultregistry.UserRegistry
	if user, err = registry.GetUser(data.ID, nil, saultregistry.UserFilterNone); err != nil {
		return
	}

	oldID := user.ID
	if data.NewID.IsSet {
		user.ID = data.NewID.Value
	}
	if data.NewIsAdmin.IsSet {
		user.IsAdmin = data.NewIsAdmin.Value
	}
	if data.NewIsActive.IsSet {
		user.IsActive = data.NewIsActive.Value
	}
	if data.NewPublicKey.IsSet {
		user.PublicKey = data.NewPublicKey.Value
	}

	var errString string
	var notUpdated bool
	if user, err = registry.UpdateUser(oldID, user); err != nil {
		errNothingToUpdate, ok := err.(*saultcommon.UserNothingToUpdate)
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
		userUpdateResponseData{
			User: user,
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
