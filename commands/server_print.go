package saultcommands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/sssh"
)

var ServerPrintFlagsTemplate *saultflags.FlagsTemplate

var availableServerPrintKinds = []string{
	"clientkey",
	"config",
	"registry",
}

func init() {
	ServerPrintFlagsTemplate = &saultflags.FlagsTemplate{
		ID:    "server print",
		Name:  "print",
		Help:  "prints the sault server informations",
		Usage: fmt.Sprintf("[ %s ] [flags]", strings.Join(availableServerPrintKinds, " ")),
		Description: `{{ "server print" | yellow }} prints the sault server informations.
* {{ "cilentkey" | yellow }}: prints the private and public key to connect the host
* {{ "config" | yellow }}: prints the current running sault configurations
* {{ "registry" | yellow }}: prints the current running sault registry
		`,
		IsPositioned: true,
		ParseFunc:    parseServerPrintCommandFlags,
	}

	sault.Commands[ServerPrintFlagsTemplate.ID] = &ServerPrintCommand{}
}

func parseServerPrintCommandFlags(f *saultflags.Flags, args []string) (err error) {
	subArgs := f.Args()
	if len(subArgs) < 1 {
		err = fmt.Errorf("select one of kinds, %s", availableServerPrintKinds)
		return
	}

	for _, s := range subArgs {
		var found bool
		for _, i := range availableServerPrintKinds {
			if s == i {
				found = true
				continue
			}
		}
		if !found {
			err = fmt.Errorf("wrong kind of information, %s", s)
			return
		}
	}

	f.Values["Kinds"] = subArgs
	return nil
}

type serverPrintResponseData struct {
	ClientKey [][]byte
	Config    []byte
	Registry  []byte
}

type ServerPrintCommand struct{}

func (c *ServerPrintCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	kinds := thisFlags.Values["Kinds"].([]string)
	var data serverPrintResponseData
	_, err = runCommand(
		allFlags[0],
		ServerPrintFlagsTemplate.ID,
		kinds,
		&data,
	)
	if err != nil {
		return
	}

	for _, kind := range kinds {
		switch kind {
		case "clientkey":
			fmt.Fprintf(
				os.Stdout,
				"%s\n%s\n",
				printServerKind("default", "client private key", strings.TrimSpace(string(data.ClientKey[0]))),
				printServerKind("default", "client public key", strings.TrimSpace(string(data.ClientKey[1]))),
			)
		case "config":
			fmt.Fprintf(
				os.Stdout,
				"%s\n",
				printServerKind("default", "sault configuration", strings.TrimSpace(string(data.Config))),
			)
		case "registry":
			fmt.Fprintf(
				os.Stdout,
				"%s\n",
				printServerKind("default", "sault registry", strings.TrimSpace(string(data.Registry))),
			)
		}
	}

	return nil
}

func (c *ServerPrintCommand) Response(channel sssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) (err error) {
	var data []string
	err = msg.GetData(&data)
	if err != nil {
		return err
	}

	result := serverPrintResponseData{}
	for _, kind := range data {
		switch kind {
		case "registry":
			result.Registry = registry.Bytes()
		case "config":
			result.Config = config.Bytes()
		case "clientkey":
			encoded, _ := saultcommon.EncodePublicKey(config.Server.GetClientKeySigner().PublicKey())
			result.ClientKey = [][]byte{
				config.Server.GetClientKey(),
				encoded,
			}
		}
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
