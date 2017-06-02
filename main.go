package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/commands"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/sault"
	"github.com/spikeekips/sault/sssh"
)

var log *logrus.Logger

var defaultLogFormatter = &logrus.TextFormatter{
	DisableTimestamp: true,
}

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

type flagPrivateKey struct {
	Path   string
	Signer sssh.Signer
}

func (f *flagPrivateKey) String() string {
	return f.Path
}

func (f *flagPrivateKey) Set(file string) (err error) {
	file = filepath.Clean(file)

	{
		// trying to find signer from ssh agent with private key file name
		var signer sssh.Signer
		signer, err = saultcommon.FindSignerInSSHAgentFromFile(file)
		if err == nil {
			*f = flagPrivateKey{Path: file, Signer: signer}
			return
		}
	}

	{
		// trying to find signer from ssh agent with loading private key
		var signer sssh.Signer
		var tmpSigner sssh.Signer
		tmpSigner, err = saultcommon.GetSignerFromPrivateKeyString(file)
		if err != nil {
			log.Debugf("failed to load signer from '%s' without passpharase", file)
		} else {
			signer, err = saultcommon.FindSignerInSSHAgentFromPublicKey(tmpSigner.PublicKey())
			if err != nil {
				log.Error(err)
			} else {
				*f = flagPrivateKey{Path: file, Signer: signer}
				return
			}
		}
	}

	{
		// passpharase trial
		var signer sssh.Signer
		signer, err = saultcommon.LoadPrivateKeySignerWithPasspharaseTrial(file)
		if err != nil {
			log.Error(err)
		} else {
			*f = flagPrivateKey{Path: file, Signer: signer}
			return
		}
	}

	err = fmt.Errorf("failed to load private identity from '%s'", file)
	log.Error(err)
	return
}

type flagSaultServer string

func (f *flagSaultServer) String() string {
	return string(*f)
}

func (f *flagSaultServer) Set(v string) error {
	account, _, err := saultcommon.ParseHostAccount(v)
	if err != nil {
		return err
	}
	surplus, saultServerName, err := saultcommon.ParseSaultAccountName(account)
	if err != nil {
		return err
	}
	if len(surplus) > 0 {
		return fmt.Errorf("in 'inSaultServer', '+' connected account name is prohibited")
	}
	if len(saultServerName) < 1 {
		return fmt.Errorf("sault server name is missing")
	}

	*f = flagSaultServer(v)

	return nil
}

var defaultLogOutput = flagLogOutput("stdout")

var helpTemplate = `{{ $el := len .error }}{{ $dl := len .description }}{{ $sl := len .f.Subcommands }}
{{ "* sault *" | blue }}
{{ if ne $el 0 }}
{{ .error }}{{ else }}{{ if ne $dl 0 }}
{{ .description }}
{{ end }}{{ end }}
Usage: {{ join .commands " " }} {{ .f.Usage }}
{{ .defaults }}
{{ if ne $sl 0 }}
Commands:{{ end }}
{{ range $_, $sc := .f.Subcommands }}
{{ $sc.Name | name | alignFormat "%10s" | yellow }}  {{ $sc.Help }}{{ end }}
`

func init() {
	log = logrus.New()
	log.Level = logrus.FatalLevel
	log.Formatter = defaultLogFormatter
	log.Out = os.Stdout

	identityFlag := flagPrivateKey{}
	saultServerFlag := new(flagSaultServer)

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

	subcommandFlags := mainFlags.GetSubCommands()

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
		os.Exit(1)
	}

	log.Info("hejdå vän~")
}
