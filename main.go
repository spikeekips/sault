package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/spikeekips/sault/commands"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
)

var log *logrus.Logger

var mainFlags *saultflags.Flags

type flagLogLevel logrus.Level

func (l *flagLogLevel) String() string {
	return logrus.Level(*l).String()
}

func (l *flagLogLevel) Set(value string) error {
	if level, err := strconv.Atoi(value); err == nil {
		*l = flagLogLevel(level)
		return nil
	}

	level, err := logrus.ParseLevel(value)
	if err != nil {
		return fmt.Errorf("invalid LogLevel: '%s'", value)
	}

	*l = flagLogLevel(level)
	return nil
}

var defaultLogLevel = flagLogLevel(logrus.InfoLevel)

type flagLogOutput string

func (l *flagLogOutput) String() string {
	return string(*l)
}

func (l *flagLogOutput) Set(value string) error {
	o := strings.ToLower(value)

	switch o {
	case "stdout", "stderr":
		//
	default:
		f, err := os.OpenFile(o, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
	}

	*l = flagLogOutput(o)

	return nil
}

var defaultLogOutput = flagLogOutput("stdout")

var helpTemplate = `{{ $el := len .error }}{{ $dl := len .description }}{{ $sl := len .f.Subcommands }}
{{ "* sault *" | blue }}
{{ if ne $el 0 }}
{{ "error" | red }} {{ .error }}{{ else }}{{ if ne $dl 0 }}
{{ .description }}
{{ end }}{{ end }}
Usage: {{ join .commands " " }} {{ .f.Usage }}
{{ .defaults }}
{{ if ne $sl 0 }}
Commands:{{ end }}
{{ range $_, $sc := .f.Subcommands }}{{ $sc.Name | sprintf "%10s" | yellow }}  {{ $sc.Help }}
{{ end }}
`

func init() {
	log = logrus.New()
	log.Level = logrus.FatalLevel
	log.Formatter = saultcommon.GetDefaultLogrusFormatter()
	log.Out = os.Stdout

	identityFlag := saultcommon.FlagPrivateKey{}
	saultServerFlag := new(saultcommon.FlagSaultServer)

	subCommands := []*saultflags.FlagsTemplate{
		saultcommands.ServerFlagsTemplate,
		saultcommands.UserFlagsTemplate,
		saultcommands.HostFlagsTemplate,
		saultcommands.VersionFlagsTemplate,
	}

	mainFlagsTemplate := &saultflags.FlagsTemplate{
		Name:  os.Args[0],
		Usage: "[flags] command",
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "LogOutput",
				Value: &defaultLogOutput,
				Help:  "set log output, [discard stdout stderr <file>]",
			},
			saultflags.FlagTemplate{
				Name:  "LogLevel",
				Value: &defaultLogLevel,
				Help:  fmt.Sprintf("set log level [ debug info warn error fatal quiet ]"),
			},
			saultflags.FlagTemplate{
				Name:  "Identity",
				Value: &identityFlag,
				Help:  "set identity file (private key) for public key authentication to the sault server",
			},
			saultflags.FlagTemplate{
				Name:  "Sault",
				Value: saultServerFlag,
				Help: fmt.Sprintf(
					"set sault server address with sault server name, '%s@localhost:%d'",
					sault.DefaultSaultServerName,
					sault.DefaultServerPort,
				),
			},
		},
	}

	var err error
	mainFlags = saultflags.NewFlags(mainFlagsTemplate, nil)
	mainFlags.SetHelpTemplate(helpTemplate)

	if err = mainFlags.Parse(os.Args[1:]); err != nil {
		mainFlagsTemplate.Subcommands = subCommands
		mainFlags = saultflags.NewFlags(mainFlagsTemplate, nil)
		mainFlags.SetHelpTemplate(helpTemplate)

		if err = mainFlags.Parse(os.Args[1:]); err != nil {
			os.Exit(1)
		}
	}

	var logOutput io.Writer
	switch v := string(mainFlags.Values["LogOutput"].(flagLogOutput)); v {
	case "discard":
		logOutput = ioutil.Discard
	case "stdout":
		logOutput = os.Stdout
	case "stderr":
		logOutput = os.Stderr
	default:
		logOutput, _ = os.OpenFile(v, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	}
	log.Out = logOutput

	log.Level = logrus.Level(mainFlags.Values["LogLevel"].(flagLogLevel))

	sault.SetupLog(log.Level, log.Out, log.Formatter)
	saultflags.SetupLog(log.Level, log.Out, log.Formatter)
	saultcommands.SetupLog(log.Level, log.Out, log.Formatter)
	saultcommon.SetupLog(log.Level, log.Out, log.Formatter)

	mainFlagsTemplate.Subcommands = subCommands
	mainFlags = saultflags.NewFlags(mainFlagsTemplate, nil)
	mainFlags.SetHelpTemplate(helpTemplate)
	if err = mainFlags.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
}

func main() {
	log.Infof(
		"Hej världen, Det här är sault %s(%s, build at %s)",
		sault.BuildVersion,
		sault.BuildCommit,
		sault.BuildDate,
	)

	log.Debugf("args: %s", os.Args)

	subcommandFlags := mainFlags.GetSubcommands()

	var b bytes.Buffer
	for _, s := range subcommandFlags {
		jsoned, _ := json.MarshalIndent(s.Values, "", "  ")

		fmt.Fprintf(&b, "%s: %s\n", s.Name, jsoned)
	}
	log.Debugf("parsed flags:\n%s", b.String())

	thisCommandFlags := subcommandFlags[len(subcommandFlags)-1]

	var command sault.Command
	{
		var ok bool
		if command, ok = sault.Commands[thisCommandFlags.ID]; !ok {
			log.Error(fmt.Errorf("unknown command"))
			os.Exit(1)
		}
	}

	if err := command.Request(subcommandFlags, thisCommandFlags); err != nil {
		log.Error(err)

		var m string
		switch err.(type) {
		case *saultcommon.ResponseMsgError:
			m = err.(*saultcommon.ResponseMsgError).Error()
		case *saultcommon.CommandError:
			m = err.(*saultcommon.CommandError).Error()
		default:
			m = "unexpected error occured"
		}

		fmt.Fprintf(
			os.Stderr,
			fmt.Sprintf(
				"%s %s\n",
				saultcommon.ColorFunc(color.FgRed)("error"),
				m,
			),
		)

		os.Exit(1)
	}

	log.Info("hejdå vän~")
}
