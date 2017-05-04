package main

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	sault "github.com/spikeekips/sault/lib"
)

var (
	Version    = "0.0"
	BuildDate  = "0000-00-00T00:00:00+0000"
	CommitHash = "XXXX"
	GitBranch  = "XXXX"
)

var options *sault.Options
var optionsValues map[string]interface{}
var globalOptionsValues map[string]interface{}
var defaultLogFormatter = &log.TextFormatter{
	FullTimestamp: true,
	TimestampFormat:
	/* time.RFC3339 */
	"2006-01-02T15:04:05.000000-07:00", // with microseconds
}

func init() {
	optionsTemplate := sault.GlobalOptionsTemplate

	options, err := sault.NewOptions(optionsTemplate)
	if err != nil {
		os.Exit(1)
	}

	if err := options.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	optionsValues = options.Values(true)

	// logging
	globalOptionsValues = optionsValues["Options"].(map[string]interface{})
	logOutput, _ := sault.ParseLogOutput(
		string(*globalOptionsValues["LogOutput"].(*sault.FlagLogOutput)),
		string(*globalOptionsValues["LogLevel"].(*sault.FlagLogLevel)),
	)
	log.SetOutput(logOutput)
	level, _ := sault.ParseLogLevel(string(*globalOptionsValues["LogLevel"].(*sault.FlagLogLevel)))
	log.SetLevel(level)

	if string(*globalOptionsValues["LogFormat"].(*sault.FlagLogFormat)) == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(defaultLogFormatter)
	}

	jsoned, _ := json.MarshalIndent(options.Values(true), "", "  ")
	log.Debugf(`parsed flags:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, string(jsoned))
}

func main() {
	commandOptions := optionsValues["Commands"].(map[string]interface{})
	command := commandOptions["Name"].(string)
	log.Debugf("got command, `%s`:", command)

	switch command {
	case "server":
		log.Info("Hallå världen...")
		var config *sault.Config
		{
			var err error

			flagArgs := map[string]interface{}{
				"BaseDirectory": commandOptions["BaseDirectory"].(string),
				"Configs":       commandOptions["Configs"].([]string),
				"LogFormat":     string(*globalOptionsValues["LogFormat"].(*sault.FlagLogFormat)),
				"LogLevel":      string(*globalOptionsValues["LogLevel"].(*sault.FlagLogLevel)),
				"LogOutput":     string(*globalOptionsValues["LogOutput"].(*sault.FlagLogOutput)),
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
	case "version":
		fmt.Printf(`   Version: %s
 BuildDate: %s
CommitHash: %s
 GitBranch: %s`,
			Version,
			BuildDate,
			CommitHash,
			GitBranch,
		)
	}
}
