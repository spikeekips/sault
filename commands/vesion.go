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
	fmt.Fprintf(os.Stdout, getSaultVersion())
	return nil
}

func (c *VersionCommand) Response(channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) error {
	return nil
}

func getSaultVersion() string {
	buildEnv, _ := base64.StdEncoding.DecodeString(sault.BuildEnv)
	tab := strings.Repeat(" ", 15)

	o, _ := saultcommon.SimpleTemplating(`
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

	return strings.TrimLeft(o, "\n")
}
