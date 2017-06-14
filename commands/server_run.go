package saultcommands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var serverRunFlagsTemplate *saultflags.FlagsTemplate

type flagEnvDirs []string

func (f *flagEnvDirs) String() string {
	// if set `return string(jsoned)`, the default value in the help message was
	// `(default [])`, this is not what I want.
	//
	//	jsoned, _ := json.Marshal(*f)
	//	return string(jsoned)

	return "./"
}

func (f *flagEnvDirs) Set(v string) error {
	if fi, err := os.Stat(v); err != nil {
		if os.IsNotExist(err) {
			log.Error(err)
			return fmt.Errorf("envDir, '%s' does not exists, skipped", v)
		}
		return fmt.Errorf("failed to check the envDir, '%s': %v", v, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("envDir, '%s' not directory, skipped", v)
	}

	absed, _ := filepath.Abs(filepath.Clean(v))
	*f = append(*f, absed)

	return nil
}

func init() {
	defaultEnvDir := flagEnvDirs{}

	serverRunFlagsTemplate = &saultflags.FlagsTemplate{
		ID:          "server run",
		Name:        "run",
		Help:        "run sault server.",
		Usage:       "[flags]",
		Description: `{{ "server run" | yellow }} launches the sault server`,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "Env",
				Help:  "This sault environment directory (default is current directory)",
				Value: &defaultEnvDir,
			},
		},
		ParseFunc: parseServerRunCommandFlags,
	}
	sault.Commands[serverRunFlagsTemplate.ID] = &serverRunCommand{}
}

func parseServerRunCommandFlags(f *saultflags.Flags, args []string) error {
	SetupLog(log.Level, log.Out, saultcommon.GetServerLogrusFormatter())
	sault.SetupLog(log.Level, log.Out, saultcommon.GetServerLogrusFormatter())
	saultflags.SetupLog(log.Level, log.Out, saultcommon.GetServerLogrusFormatter())
	saultcommon.SetupLog(log.Level, log.Out, saultcommon.GetServerLogrusFormatter())

	envDirs := f.Values["Env"].(flagEnvDirs)
	if len(envDirs) < 1 {
		currentDirectory, _ := filepath.Abs("./")
		envDirs = []string{currentDirectory}
		f.Values["Env"] = flagEnvDirs(envDirs)
	}

	config, err := sault.LoadConfigs(envDirs)
	if err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}

	f.Values["Config"] = config

	return nil
}

type serverRunCommand struct {
}

func (c *serverRunCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	var proxy *sault.Server
	config := thisFlags.Values["Config"].(*sault.Config)

	cr := config.Registry.GetSources()

	registry := saultregistry.NewRegistry()
	if err = registry.AddSource(cr...); err != nil {
		return
	}

	if err = registry.Load(); err != nil {
		return
	}

	proxy, err = sault.NewServer(
		registry,
		config,
		config.Server.GetHostKeySigner(),
		config.Server.GetClientKeySigner(),
		config.Server.SaultServerName,
	)
	if err != nil {
		return err
	}

	if err = proxy.Run(config.Server.Bind); err != nil {
		return
	}

	return nil
}

func (c *serverRunCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) error {
	return nil
}
