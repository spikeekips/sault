package sault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/Sirupsen/logrus"
)

var GlobalOptionsTemplate OptionsTemplate
var DefaultLogFormat = "text"
var DefaultLogLevel = "info"
var DefaultLogOutput = "stdout"
var DefaultConfigDir = "./"

type FlagLogFormat string

func (l *FlagLogFormat) String() string {
	return string(*l)
}

func (l *FlagLogFormat) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogFormat(DefaultLogFormat)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range AvailableLogFormats {
		if f == nv {
			*l = FlagLogFormat(nv)
			return nil
		}
	}

	return errors.New("")
}

type FlagLogLevel string

func (l *FlagLogLevel) String() string {
	return string(*l)
}

func (l *FlagLogLevel) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogLevel(DefaultLogLevel)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range AvailableLogLevel {
		if f == nv {
			*l = FlagLogLevel(nv)
			return nil
		}
	}

	return errors.New("")
}

type FlagLogOutput string

func (l *FlagLogOutput) String() string {
	return string(*l)
}

func (l *FlagLogOutput) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogOutput(DefaultLogOutput)
		return nil
	}

	nv := strings.ToLower(value)
	_, err := ParseLogOutput(value, "")
	if err == nil {
		*l = FlagLogOutput(nv)
		return nil
	}

	return errors.New("")
}

type FlagConfigDirs []string

func (f *FlagConfigDirs) String() string {
	/*
		jsoned, _ := json.Marshal(*f)
		return string(jsoned)
	*/

	// if set `return string(jsoned)`, the default value in the help message was
	// `(default [])`, this is not what I want.
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

func ParseServerOptions(op *Options, args []string) error {
	values := op.Values(false)

	op.Extra = map[string]interface{}{}

	var configFiles []string
	var baseDirectory string

	configDirs := values["Options"].(map[string]interface{})["ConfigDir"].(*FlagConfigDirs)
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

		// last config directory will be `baseDirectory`
		baseDirectory = configDir
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

func init() {
	DefaultConfigDir, _ = filepath.Abs(filepath.Clean(DefaultConfigDir))

	GlobalOptionsTemplate = OptionsTemplate{
		Name:  os.Args[0],
		Usage: "[flags] command",
		Options: []OptionTemplate{
			OptionTemplate{
				Name:      "LogFormat",
				Help:      fmt.Sprintf("log format %s", AvailableLogFormats),
				ValueType: &struct{ Type FlagLogFormat }{FlagLogFormat(DefaultLogFormat)},
			},
			OptionTemplate{
				Name:      "LogLevel",
				Help:      fmt.Sprintf("log level %s", AvailableLogLevel),
				ValueType: &struct{ Type FlagLogLevel }{FlagLogLevel(DefaultLogLevel)},
			},
			OptionTemplate{
				Name:      "LogOutput",
				Help:      "log output [stdout stderr <filename>]",
				ValueType: &struct{ Type FlagLogOutput }{FlagLogOutput(DefaultLogOutput)},
			},
		},
		Commands: []OptionsTemplate{
			OptionsTemplate{
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
			},
			OptionsTemplate{
				Name:  "version",
				Help:  "show version information",
				Usage: "",
			},
		},
	}
}
