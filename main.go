package main

import (
	"fmt"
	"os"
	"os/signal"

	log "github.com/Sirupsen/logrus"
	sault "github.com/spikeekips/sault/lib"
)

var defaultLogFormatter = &log.TextFormatter{
	FullTimestamp: true,
	TimestampFormat:
	/* time.RFC3339 */
	"2006-01-02T15:04:05.000000-07:00", // with microseconds
}
var globalFlags *sault.GlobalFlags
var flags sault.ParsedFlags

func init() {
	// handling interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			log.Info("adjö~")
			os.Exit(1)
		}
	}()

	globalFlags = sault.NewGlobalFlags(os.Args[0])
	if err := globalFlags.ParseAll(); err != nil {
		os.Exit(1)
	}

	flags = globalFlags.ToMapAll()

	// logging
	logOutput, _ := sault.ParseLogOutput(
		string(flags["global"]["LogOutput"].(sault.FlagLogOutput)),
		string(flags["global"]["LogLevel"].(sault.FlagLogLevel)),
	)
	log.SetOutput(logOutput)
	level, _ := sault.ParseLogLevel(string(flags["global"]["LogLevel"].(sault.FlagLogLevel)))
	log.SetLevel(level)

	if string(flags["global"]["LogFormat"].(sault.FlagLogFormat)) == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(defaultLogFormatter)
	}

	if jsoned, err := globalFlags.ToJSONAll(); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	} else {
		log.Debugf(`flags:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, string(jsoned))
	}

}

func main() {
	command := flags["global"]["command"].(string)
	log.Debugf("command, `%s`:", command)
	switch command {
	case "server":
		log.Info("Hallå världen...")
		var config *sault.Config
		{
			var err error

			flagArgs := map[string]interface{}{
				"BaseDirectory": flags["command"]["BaseDirectory"].(string),
				"Configs":       flags["command"]["Configs"].([]string),
				"LogFormat":     string(flags["global"]["LogFormat"].(sault.FlagLogFormat)),
				"LogLevel":      string(flags["global"]["LogLevel"].(sault.FlagLogLevel)),
				"LogOutput":     string(flags["global"]["LogOutput"].(sault.FlagLogOutput)),
			}
			config, err = sault.LoadConfig(flagArgs)
			if err != nil {
				log.Errorf("failed to load configs: %v", err)
				os.Exit(1)
			}

			if err := config.Validate(); err != nil {
				log.Errorf("%v", err)
				os.Exit(1)
			}

			// reset logging
			logOutput, _ := sault.ParseLogOutput(config.Log.Output, config.Log.Level)
			log.SetOutput(logOutput)
			level, _ := sault.ParseLogLevel(config.Log.Level)
			log.SetLevel(level)

			if config.Log.Format == "json" {
				log.SetFormatter(&log.JSONFormatter{})
			} else {
				log.SetFormatter(defaultLogFormatter)
			}
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
	default:
		fmt.Println(command)
	}
}
