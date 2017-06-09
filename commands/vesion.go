package saultcommands

import (
	"encoding/base64"
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
	buildEnv, _ := base64.StdEncoding.DecodeString(sault.BuildEnv)
	tab := strings.Repeat(" ", 15)

	o, err := saultcommon.SimpleTemplating(`
     version: {{ .buildversion }}
  build date: {{ .builddate }}
build commit: {{ .buildcommit }}
build branch: {{ .buildbranch }}
  build repo: {{ .buildrepo }}
   build env:
{{ .tab }}{{ .buildenv }}
`,
		map[string]interface{}{
			"buildversion": sault.BuildVersion,
			"builddate":    sault.BuildDate,
			"buildcommit":  sault.BuildCommit,
			"buildbranch":  sault.BuildBranch,
			"buildrepo":    sault.BuildRepo,
			"tab":          tab,
			"buildenv":     strings.TrimSpace(strings.Replace(string(buildEnv), "\n", "\n"+tab, -1)),
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
