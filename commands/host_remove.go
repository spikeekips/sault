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

var HostRemoveFlagsTemplate *saultflags.FlagsTemplate

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "host remove" | yellow }} will remove the hosts in the registry of sault server.
		`,
		nil,
	)

	HostRemoveFlagsTemplate = &saultflags.FlagsTemplate{
		ID:          "host remove",
		Name:        "remove",
		Help:        "remove the sault hosts",
		Usage:       "[flags] <host id> [<host id>...]",
		Description: description,
		Flags:       []saultflags.FlagTemplate{},
		ParseFunc:   parseHostRemoveCommandFlags,
	}

	sault.Commands[HostRemoveFlagsTemplate.ID] = &HostRemoveCommand{}
}

func parseHostRemoveCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.FlagSet.Args()
	if len(subArgs) < 1 {
		err = fmt.Errorf("set host ids")
		return
	}

	for _, a := range subArgs {
		if !saultcommon.CheckHostID(a) {
			err = &saultcommon.InvalidHostIDError{ID: a}
			return
		}
	}

	f.Values["IDs"] = subArgs

	return nil
}

type HostRemoveCommand struct{}

func (c *HostRemoveCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	ids := thisFlags.Values["IDs"].([]string)
	_, err = runCommand(
		allFlags[0],
		HostRemoveFlagsTemplate.ID,
		ids,
		nil,
	)
	if err != nil {
		return
	}

	var m string
	if len(ids) < 2 {
		m = fmt.Sprintf("host, %s was successfully removed", ids[0])
	} else {
		m = fmt.Sprintf("hosts, %s were successfully removed", strings.Join(ids, ", "))
	}
	fmt.Fprintf(os.Stdout, m+"\n")

	return nil
}

func (c *HostRemoveCommand) Response(channel sssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data []string
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	for _, h := range data {
		if !saultcommon.CheckHostID(h) {
			err = &saultcommon.InvalidHostIDError{ID: h}
			return
		}
		if _, err = registry.GetHost(h, saultregistry.HostFilterNone); err != nil {
			return
		}
	}

	for _, h := range data {
		if err = registry.RemoveHost(h); err != nil {
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
