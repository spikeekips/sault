package saultcommands

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var hostListFlagsTemplate *saultflags.FlagsTemplate

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

{{ "-reverse" | yellow }}:
By default, sault orders the remote hosts by the updated time, that is, the last updated host will be listed at last. This flag will list them by reverse order.
		`,
		nil,
	)

	hostFilters := new(flagHostFilters)
	hostListFlagsTemplate = &saultflags.FlagsTemplate{
		ID:          "host list",
		Name:        "list",
		Help:        "get hosts information",
		Usage:       "[flags] [<host id>...]",
		Description: description,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "Reverse",
				Help:  "list reverse order by the updated time",
				Value: false,
			},
			saultflags.FlagTemplate{
				Name:  "Filter",
				Help:  "filter hosts, [ active[-]]",
				Value: hostFilters,
			},
		},
		ParseFunc:    parseHostListCommandFlags,
		IsPositioned: true,
	}

	sault.Commands[hostListFlagsTemplate.ID] = &hostListCommand{}
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

type hostListRequestData struct {
	Filters saultregistry.HostFilter
	HostIDs []string
}

type hostListResponseData []saultregistry.HostRegistry

func (s hostListResponseData) Len() int {
	return len(s)
}

func (s hostListResponseData) Less(i, j int) bool {
	return s[i].DateUpdated.Before(s[j].DateUpdated)
}

func (s hostListResponseData) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
	return
}

type hostListCommand struct{}

func (c *hostListCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	flagFilter := thisFlags.Values["Filter"].(flagHostFilters)
	log.Debugf("get hosts, filters: %s HostIDs: %s", flagFilter.Args, thisFlags.Values["HostIDs"])

	var hosts hostListResponseData
	_, err = runCommand(
		allFlags[0],
		hostListFlagsTemplate.ID,
		hostListRequestData{
			Filters: saultregistry.HostFilter(flagFilter.Combined),
			HostIDs: thisFlags.Values["HostIDs"].([]string),
		},
		&hosts,
	)
	if err != nil {
		return
	}

	if thisFlags.Values["Reverse"].(bool) {
		sort.Sort(sort.Reverse(hosts))
	} else {
		sort.Sort(hosts)
	}

	fmt.Fprintf(os.Stdout, printHostsData(
		"host-list",
		allFlags[0].Values["Sault"].(saultcommon.FlagSaultServer).Address,
		hosts,
		nil,
	))

	return nil
}

func (c *hostListCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data hostListRequestData
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	result := hostListResponseData{}
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
