package sault

import (
	"errors"
	"os"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
)

var DefaultConfigDir = "./"

func init() {
	DefaultConfigDir, _ = filepath.Abs(filepath.Clean(DefaultConfigDir))
}

type FlagConfigDirs []string

func (f *FlagConfigDirs) String() string {
	// if set `return string(jsoned)`, the default value in the help message was
	// `(default [])`, this is not what I want.
	//
	//	jsoned, _ := json.Marshal(*f)
	//	return string(jsoned)

	return ""
}

func (f *FlagConfigDirs) Set(v string) error {
	if fi, err := os.Stat(v); err != nil {
		log.Errorf("configDir, `%s` does not exists, skipped", v)
		return nil
	} else if !fi.IsDir() {
		log.Errorf("configDir, `%s` not directory, skipped", v)
		return nil
	}

	absed, _ := filepath.Abs(filepath.Clean(v))
	*f = append(*f, absed)

	return nil
}

var ServerOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name:  "server",
	Help:  "run sault server",
	Usage: "[flags]",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:      "ConfigDir",
			Help:      "This directory contains the configuration files (default is current directory)",
			ValueType: &struct{ Type FlagConfigDirs }{FlagConfigDirs{}},
		},
	},
	ParseFunc: ParseServerOptions,
}

func ParseServerOptions(op *Options, args []string) error {
	options := op.Values(false)

	op.Extra = map[string]interface{}{}

	var configFiles []string
	var baseDirectory string

	configDirs := options["Options"].(OptionsValues)["ConfigDir"].(*FlagConfigDirs)
	if len(*configDirs) < 1 {
		configDirs.Set(DefaultConfigDir)
	}

	for _, configDir := range *configDirs {
		files, err := filepath.Glob(BaseJoin(configDir, "*.conf"))
		if err != nil {
			msg := "failed to load config files from `%s`: %v"
			log.Errorf(msg, configDir, err)
			continue
		}
		files = StringFilter(
			files,
			func(s string) bool {
				return string([]rune(filepath.Base(s))[0]) != "."
			},
		)
		configFiles = append(configFiles, files...)

		baseDirectory = configDir // last config directory will be `baseDirectory`
	}

	if len(configFiles) < 1 {
		return errors.New("sault config files not found in configDir(s)")
	}

	op.Extra = map[string]interface{}{
		"BaseDirectory": baseDirectory,
		"Configs":       configFiles,
	}

	return nil
}

func RunServer(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	log.Info("Hallå världen...")
	var config *Config
	{
		var err error

		flagArgs := map[string]interface{}{
			"BaseDirectory": options["BaseDirectory"].(string),
			"Configs":       options["Configs"].([]string),
			"LogFormat":     string(*globalOptions["LogFormat"].(*FlagLogFormat)),
			"LogLevel":      string(*globalOptions["LogLevel"].(*FlagLogLevel)),
			"LogOutput":     string(*globalOptions["LogOutput"].(*FlagLogOutput)),
		}
		config, err = LoadConfig(flagArgs)
		if err != nil {
			log.Errorf("failed to load configs: %v", err)

			exitStatus = 1
			return
		}

		if err := config.Validate(); err != nil {
			log.Errorf("%v", err)

			exitStatus = 1
			return
		}

		// reset logging
		logOutput, _ := ParseLogOutput(config.Log.Output, config.Log.Level)
		log.SetOutput(logOutput)
		level, _ := ParseLogLevel(config.Log.Level)
		log.SetLevel(level)

		if config.Log.Format == "json" {
			log.SetFormatter(&log.JSONFormatter{})
		} else {
			log.SetFormatter(DefaultLogFormatter)
		}
	}

	configSourceRegistry, err := config.Registry.GetSource()
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}
	registry, err := NewRegistry(config.Registry.Type, configSourceRegistry)
	if err != nil {
		log.Errorf("failed to load registry: %v", err)

		exitStatus = 1
		return
	}

	var proxy *Proxy
	{
		var err error
		if proxy, err = NewProxy(config, registry); err != nil {
			log.Fatalf("something wrong: %v", err)
		}

		if err = proxy.Run(); err != nil {
			log.Fatalf("something wrong: %v", err)
		}
	}

	log.Info("adjö~")

	return
}
