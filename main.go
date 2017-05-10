package main

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	sault "github.com/spikeekips/sault/lib"
)

var (
	version    = "0.0"
	buildDate  = "0000-00-00T00:00:00+0000"
	commitHash = "XXXX"
	gitBranch  = "XXXX"
)

var options *sault.Options
var globalOptions sault.OptionsValues
var commandOptions sault.OptionsValues

func init() {
	// flags
	optionsTemplate := sault.GlobalOptionsTemplate

	optionsTemplate.Commands = append(
		optionsTemplate.Commands,
		sault.OptionsTemplate{ // add version options
			Name:  "version",
			Help:  "show version information",
			Usage: "",
		},
	)

	options, err := sault.NewOptions(optionsTemplate)
	if err != nil {
		os.Exit(1)
	}

	if err := options.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	ov := options.Values(true)
	globalOptions = ov["Options"].(sault.OptionsValues)
	commandOptions = ov["Commands"].(sault.OptionsValues)

	// logging
	logOutput, _ := sault.ParseLogOutput(
		string(*globalOptions["LogOutput"].(*sault.FlagLogOutput)),
		string(*globalOptions["LogLevel"].(*sault.FlagLogLevel)),
	)
	log.SetOutput(logOutput)
	level, _ := sault.ParseLogLevel(string(*globalOptions["LogLevel"].(*sault.FlagLogLevel)))
	log.SetLevel(level)

	if string(*globalOptions["LogFormat"].(*sault.FlagLogFormat)) == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(sault.DefaultLogFormatter)
	}

	jsoned, _ := json.MarshalIndent(options.Values(true), "", "  ")
	log.Debugf(`parsed flags:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, string(jsoned))
}

func main() {
	command := commandOptions["CommandName"].(string)
	log.Debugf("got command, `%s`:", command)

	if run, ok := sault.RequestCommands[command]; ok {
		exitStatus := run(commandOptions, globalOptions)
		os.Exit(exitStatus)
	}

	switch command {
	case "version":
		fmt.Printf(`   Version: %s
 BuildDate: %s
CommitHash: %s
 GitBranch: %s`,
			version,
			buildDate,
			commitHash,
			gitBranch,
		)
	}

	os.Exit(0)
}
