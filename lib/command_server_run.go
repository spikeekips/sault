package sault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
)

var defaultConfigDir = "./"
var serverRunOptionsTemplate = OptionsTemplate{
	Name:  "run",
	Help:  "run sault server",
	Usage: "[flags]",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:      "ConfigDir",
			Help:      "This directory contains the configuration files (default is current directory)",
			ValueType: &struct{ Type flagConfigDirs }{flagConfigDirs{}},
		},
	},
	ParseFunc: parseServerOptions,
}

func init() {
	defaultConfigDir, _ = filepath.Abs(filepath.Clean(defaultConfigDir))
}

type flagConfigDirs []string

func (f *flagConfigDirs) String() string {
	// if set `return string(jsoned)`, the default value in the help message was
	// `(default [])`, this is not what I want.
	//
	//	jsoned, _ := json.Marshal(*f)
	//	return string(jsoned)

	return ""
}

func (f *flagConfigDirs) Set(v string) error {
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

func parseServerOptions(op *Options, args []string) error {
	options := op.Values(false)

	op.Extra = map[string]interface{}{}

	var configFiles []string
	var baseDirectory string

	configDirs := options["Options"].(OptionsValues)["ConfigDir"].(*flagConfigDirs)
	if len(*configDirs) < 1 {
		configDirs.Set(defaultConfigDir)
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

func getRegistryFromConfig(config *Config, initialize bool) (Registry, error) {
	cs, err := config.Registry.GetSource()
	if err != nil {
		return nil, err
	}

	registry, err := NewRegistry(config.Registry.Type, cs, initialize)
	if err != nil {
		return nil, fmt.Errorf("failed to load registry: %v", err)
	}

	return registry, nil
}

func runServer(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	log.Info("Hallå världen...")

	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	var config *Config
	{
		flagArgs := map[string]interface{}{
			"BaseDirectory": ov["BaseDirectory"].(string),
			"Configs":       ov["Configs"].([]string),
			"LogFormat":     string(*gov["LogFormat"].(*FlagLogFormat)),
			"LogLevel":      string(*gov["LogLevel"].(*FlagLogLevel)),
			"LogOutput":     string(*gov["LogOutput"].(*FlagLogOutput)),
		}
		config, err = loadConfig(flagArgs)
		if err != nil {
			log.Errorf("failed to load configs: %v", err)

			return
		}

		if err = config.validate(); err != nil {
			log.Errorf("%v", err)

			return
		}

		// reset logging
		logOutput, _ := ParseLogOutput(config.Log.Output, config.Log.Level)
		log.Out = logOutput
		level, _ := ParseLogLevel(config.Log.Level)
		log.Level = level

		if config.Log.Format == "json" {
			log.Formatter = &logrus.JSONFormatter{}
		} else {
			log.Formatter = DefaultLogFormatter
		}
	}

	var registry Registry
	registry, err = getRegistryFromConfig(config, false)
	if err != nil {
		log.Error(err)

		return
	}

	var proxy *Proxy
	{
		if proxy, err = NewProxy(config, registry); err != nil {
			log.Fatalf("something wrong: %v", err)
		}

		if err = proxy.run(); err != nil {
			log.Fatalf("something wrong: %v", err)
		}
	}

	log.Info("adjö~")

	return
}
