package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/lib"
	"github.com/spikeekips/sault/ssh"
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
	saultSsh.PackageVersion = fmt.Sprintf("%s-sault-%s", saultSsh.PackageVersion, version)

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

	globalOptions = options.Values(true)
	commandOptions = globalOptions["Commands"].(sault.OptionsValues)
	gov := globalOptions["Options"].(sault.OptionsValues)

	// logging
	logOutput, _ := sault.ParseLogOutput(
		string(*gov["LogOutput"].(*sault.FlagLogOutput)),
		string(*gov["LogLevel"].(*sault.FlagLogLevel)),
	)
	sault.Log.Out = logOutput
	level, _ := sault.ParseLogLevel(string(*gov["LogLevel"].(*sault.FlagLogLevel)))
	sault.Log.Level = level

	if string(*gov["LogFormat"].(*sault.FlagLogFormat)) == "json" {
		sault.Log.Formatter = &logrus.JSONFormatter{}
	} else {
		sault.Log.Formatter = sault.DefaultLogFormatter
	}

	jsoned, _ := json.MarshalIndent(options.Values(true), "", "  ")
	sault.Log.Debugf(`parsed flags:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, string(jsoned))
}

func main() {
	command := commandOptions["CommandName"].(string)
	sault.Log.Debugf("got command, `%s`:", command)

	if run, ok := sault.RequestCommands[command]; ok {
		exitStatus, err := run(commandOptions, globalOptions)
		if err != nil {
			sault.CommandOut.Error(err)
			if exitStatus == 0 {
				exitStatus = 1
			}
		}
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
	default:
		sault.CommandOut.Error(fmt.Errorf("unknown command: `%s`", command))
		os.Exit(1)
	}

	os.Exit(0)
}
