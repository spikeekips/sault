package saultcommands

import (
	"github.com/spikeekips/sault/flags"
)

var (
	ServerFlagsTemplate,
	UserFlagsTemplate,
	VersionFlagsTemplate,
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
			serverRunFlagsTemplate,
			serverPrintFlagsTemplate,
			serverInitFlagsTemplate,
		},
	}

	UserFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "user",
		Help: "manage users",
		Description: `Manage sault users.
				`,
		Subcommands: []*saultflags.FlagsTemplate{
			userListFlagsTemplate,
			userLinkFlagsTemplate,
			userUpdateFlagsTemplate,
			userRemoveFlagsTemplate,
			userAddFlagsTemplate,
		},
	}
	HostFlagsTemplate = &saultflags.FlagsTemplate{
		Name: "host",
		Help: "manage hosts",
		Description: `
Mange hosts of sault server.
		`,
		Subcommands: []*saultflags.FlagsTemplate{
			hostListFlagsTemplate,
			hostUpdateFlagsTemplate,
			hostRemoveFlagsTemplate,
			hostAddFlagsTemplate,
			hostInjectFlagsTemplate,
		},
	}
}
