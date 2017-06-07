package saultcommands

import (
	"github.com/spikeekips/sault/flags"
)

var (
	ServerFlagsTemplate,
	UserFlagsTemplate,
	HostFlagsTemplate *saultflags.FlagsTemplate
)

func init() {
	ServerFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "server",
		Help: "sault server",
		Description: `
Run {{ "sault" | yellow }} server.
		`,
		Subcommands: []*saultflags.FlagsTemplate{
			ServerRunFlagsTemplate,
			ServerPrintFlagsTemplate,
			ServerInitFlagsTemplate,
		},
	}

	UserFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "user",
		Help: "manage users",
		Description: `Manage sault users.
				`,
		Subcommands: []*saultflags.FlagsTemplate{
			UserListFlagsTemplate,
			UserLinkFlagsTemplate,
			UserUpdateFlagsTemplate,
			UserRemoveFlagsTemplate,
			UserAddFlagsTemplate,
		},
	}
	HostFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "host",
		Help: "manage hosts",
		Description: `
Mange hosts of sault server.
		`,
		Subcommands: []*saultflags.FlagsTemplate{
			HostListFlagsTemplate,
			HostUpdateFlagsTemplate,
			HostRemoveFlagsTemplate,
			HostAddFlagsTemplate,
		},
	}
}
