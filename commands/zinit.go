package saultcommands

import (
	"github.com/spikeekips/sault/flags"
)

var (
	ServerFlagsTemplate,
	HostFlagsTemplate,
	UserFlagsTemplate *saultflags.FlagsTemplate
)

func init() {
	ServerFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "server",
		Help: "sault server",
		Description: `
Run {{ "sault" | yellow }} server.
		`,
		Subcommands: []*saultflags.FlagsTemplate{
			ServerInitFlagsTemplate,
			ServerRunFlagsTemplate,
		},
	}

	UserFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "user",
		Help: "manage users",
		Description: `
Mange users of sault server.
		`,
		Subcommands: []*saultflags.FlagsTemplate{},
	}

	HostFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "host",
		Help: "manage hosts",
		Description: `
Mange hosts of sault server.
		`,
		Subcommands: []*saultflags.FlagsTemplate{},
	}
}
