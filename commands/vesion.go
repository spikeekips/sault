package saultcommands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/sault"
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
	o, err := saultcommon.Templating(`
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

func (c *VersionCommand) Response(msg sault.CommandMsg) error { return nil }
