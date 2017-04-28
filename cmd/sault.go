package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault"
)

var config *sault.Config

type flagConfigDirs []string

func (f *flagConfigDirs) String() string {
	return "configs"
}

func (f *flagConfigDirs) Set(v string) error {
	*f = append(*f, v)
	return nil
}

var flagLogFormat string
var flagLogLevel string
var flagLogOutput string

var defaultLogFormatter = &log.TextFormatter{
	FullTimestamp: true,
	TimestampFormat:
	/* time.RFC3339 */
	"2006-01-02T15:04:05.000000-07:00", // with microseconds
}

func init() {
	// parse flags
	var valFlagConfigDirs flagConfigDirs
	flag.Var(&valFlagConfigDirs, "configDir", "sault config directory")

	flag.StringVar(&flagLogFormat, "log.Format", "text", "log format: json, text")
	flag.StringVar(
		&flagLogLevel,
		"log.Level",
		"info",
		fmt.Sprintf("log level: %s", sault.AvailableLogLevel),
	)
	flag.StringVar(&flagLogOutput, "log.Output", "stdout", "log output: [<file path> stdout stderr]")

	flag.Parse()

	logOutput, err := sault.ParseLogOutput(flagLogOutput, flagLogLevel)
	if err != nil {
		log.Fatalf("invalid `log.Output`, `%v`", flagLogOutput)
	}
	log.SetOutput(logOutput)
	level, err := sault.ParseLogLevel(flagLogLevel)
	if err != nil {
		log.Fatalf("invalid `log.Level`, `%v`", flagLogLevel)
	}
	log.SetLevel(level)
	log.SetFormatter(defaultLogFormatter)

	log.Info("Hallå världen...")

	// handling interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			log.Info("adjö~")
			os.Exit(1)
		}
	}()

	// load config files from flagConfigDirs
	var configFiles []string
	var BaseDirectory string
	for _, configDir := range []string(valFlagConfigDirs) {
		log.Debugf("trying to get config files from `%s`", configDir)

		isTolerated, d := sault.ParseTolerateFilePath(configDir)
		d, err = filepath.Abs(d)
		if err != nil {
			log.Errorf("failed to traverse the config directory, `%s`", configDir)
			continue
		}

		// last config directory will be `BaseDirectory`
		BaseDirectory = d

		files, err := filepath.Glob(sault.BaseJoin(d, "*.conf"))
		if err != nil {
			msg := "failed to load config files from `%s`: %v"
			if isTolerated {
				log.Errorf(msg, valFlagConfigDirs, err)
			} else {
				log.Fatalf(msg, valFlagConfigDirs, err)
			}
		}
		// prevent to load hidden files.
		files = sault.StringFilter(
			files,
			func(s string) bool {
				return string([]rune(filepath.Base(s))[0]) != "."
			},
		)
		configFiles = append(configFiles, files...)
	}

	{
		var err error

		flagArgs := map[string]interface{}{
			"BaseDirectory": BaseDirectory,
			"Configs":       configFiles,
			"Log.Format":    flagLogFormat,
			"Log.Level":     flagLogLevel,
			"Log.Output":    flagLogOutput,
		}
		config, err = sault.LoadConfig(flagArgs)
		if err != nil {
			log.Errorf("failed to load configs: %v", err)
			os.Exit(1)
		}
	}

	logOutput, err = sault.ParseLogOutput(config.Log.Output, config.Log.Level)
	if err != nil {
		log.Fatalf("invalid `log.Output`, `%v`", config.Log.Output)
	}
	log.SetOutput(logOutput)
	level, err = sault.ParseLogLevel(config.Log.Level)
	if err != nil {
		log.Fatalf("invalid `log.Level`, `%v`", config.Log.Level)
	}
	log.SetLevel(level)

	if config.Log.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(defaultLogFormatter)
	}
}

func main() {
	log.Infof(`loaded Config:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, config.String())

	if err := config.Validate(); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}

	configSourceRegistry, err := config.Registry.GetSource()
	if err != nil {
		log.Fatal(err)
	}
	registry, err := sault.NewRegistry(config.Registry.Type, configSourceRegistry)
	if err != nil {
		log.Fatalf("failed to load registry: %v", err)
	}

	var proxy *sault.Proxy
	{
		var err error
		if proxy, err = sault.NewProxy(config, registry); err != nil {
			log.Fatalf("something wrong: %v", err)
		}

		if err = proxy.Run(); err != nil {
			log.Fatalf("something wrong: %v", err)
		}
	}

	log.Info("adjö~")
}
