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

var VersionFlagsTemplate *saultflags.FlagsTemplate

func init() {
	VersionFlagsTemplate = &saultflags.FlagsTemplate{
		ID:   "version",
		Name: "version",
		Help: "print build informations",
	}

	sault.Commands[VersionFlagsTemplate.ID] = &VersionCommand{}
}

type VersionCommand struct {
}

func (c *VersionCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) error {
	o, err := saultcommon.SimpleTemplating(`
     version: {{ .version }}
  build date: {{ .date }}
build commit: {{ .commit }}
`,
		map[string]interface{}{
			"version": sault.BuildVersion,
			"date":    sault.BuildDate,
			"commit":  sault.BuildCommit,
		},
	)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, strings.TrimLeft(o, "\n"))
	return nil
}

func (c *VersionCommand) Response(channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) error {
	return nil
}
