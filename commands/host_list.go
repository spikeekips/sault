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

var HostListFlagsTemplate *saultflags.FlagsTemplate

type flagHostFilters struct {
	Combined saultregistry.HostFilter
	Args     []string
}

func (f *flagHostFilters) String() string {
	return fmt.Sprintf("[ %s ]", strings.Join(f.Args, " "))
}

func (f *flagHostFilters) Set(v string) (err error) {
	filters := saultregistry.HostFilter(f.Combined)

	findUserFilter := func(u saultregistry.HostFilter) bool {
		return filters&u == u
	}

	var filter saultregistry.HostFilter
	switch v {
	case "active":
		if findUserFilter(saultregistry.HostFilterIsNotActive) {
			err = fmt.Errorf("'active' can not be with 'active-'")
			return
		}

		filter = saultregistry.HostFilterIsActive
	case "active-":
		if findUserFilter(saultregistry.HostFilterIsActive) {
			err = fmt.Errorf("'active-' can not be with 'active'")
			return
		}

		filter = saultregistry.HostFilterIsNotActive
	default:
		err = fmt.Errorf("unknown filter name, '%s'", v)
		return
	}

	filters |= filter

	args := f.Args
	args = append(args, v)
	*f = flagHostFilters{Combined: filters, Args: args}

	return
}

func init() {
	description, _ := saultcommon.SimpleTemplating(`{{ "host list" | yellow }} gets the registered remote hosts information from sault server.

The belowed flags help to get the remote hosts from sault server, by default, it shows all registered remote hosts.
{{ "-filter <mode>" | yellow }}:
  With filter, you can filter the hosts list, {{ "active" | yellow }}: is only for active hosts. With appending '{{ "-" | yellow }}', you can remove the admin or active host. For examples,
  * {{ "-filter \"active\"" | yellow }}: active hosts
  * {{ "-filter \"active-\"" | yellow }}: not active hosts
		`,
		nil,
	)

	hostFilters := new(flagHostFilters)
	HostListFlagsTemplate = &saultflags.FlagsTemplate{
		ID:          "host list",
		Name:        "list",
		Help:        "get hosts information",
		Usage:       "[flags] [<host id>...]",
		Description: description,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "Filter",
				Help:  "filter hosts, [ active[-]]",
				Value: hostFilters,
			},
		},
		ParseFunc:    parseHostListCommandFlags,
		IsPositioned: true,
	}

	sault.Commands[HostListFlagsTemplate.ID] = &HostListCommand{}
}

func parseHostListCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	for _, a := range subArgs {
		if !saultcommon.CheckHostID(a) {
			err = &saultcommon.InvalidHostIDError{ID: a}
			return
		}
	}

	f.Values["HostIDs"] = subArgs

	return nil
}

type HostListRequestData struct {
	Filters saultregistry.HostFilter
	HostIDs []string
}

type HostListCommand struct{}

func (c *HostListCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	flagFilter := thisFlags.Values["Filter"].(flagHostFilters)
	log.Debugf("get hosts, filters: %s HostIDs: %s", flagFilter.Args, thisFlags.Values["HostIDs"])

	var hosts []saultregistry.HostRegistry
	_, err = runCommand(
		allFlags[0],
		HostListFlagsTemplate.ID,
		HostListRequestData{
			Filters: saultregistry.HostFilter(flagFilter.Combined),
			HostIDs: thisFlags.Values["HostIDs"].([]string),
		},
		&hosts,
	)
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, PrintHostsData(
		"host-list",
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		hosts,
		nil,
	))

	return nil
}

func (c *HostListCommand) Response(channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data HostListRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	result := []saultregistry.HostRegistry{}
	for _, h := range registry.GetHosts(data.Filters, data.HostIDs...) {
		result = append(result, h)
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
