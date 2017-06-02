package saultflags // import "github.com/spikeekips/sault/flags"

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
)

var defaultHelpTemplate = `
{{ if .error }}{{ .error }}{{ end }}{{ if .error }}{{ else }}{{ .description }}{{ end }}
Usage: {{ .f.Name }} {{ .f.Usage }}
{{ .defaults }}

{{ $sl := len .f.Subcommands }}{{ if ne $sl 0 }}
Commands{{ end }}
{{ range $_, $sc := .f.Subcommands }}
{{ $sc.Name | name | alignFormat "%10s" | yellow }}  {{ $sc.Help }}{{ end }}
`

// ErrorOccured wraps error from Parse()
type ErrorOccured struct {
	Err error
}

func (e *ErrorOccured) Error() string {
	return e.Err.Error()
}

// MissingCommand represents the error when unknown command is inserted
type MissingCommand struct{}

func (e *MissingCommand) Error() string {
	return "command is missing"
}

// UnknownCommand represents the error when unknown command is inserted
type UnknownCommand struct {
	Command string
}

func (e *UnknownCommand) Error() string {
	return fmt.Sprintf("unknown command, '%s' found", e.Command)
}

// FlagsTemplate is the template for Flags
type FlagsTemplate struct {
	ID          string
	Name        string
	Usage       string
	Help        string
	Description string
	IsGroup     bool

	Flags       []FlagTemplate
	Subcommands []*FlagsTemplate

	ParseFuncBefore func(*Flags, []string) error
	ParseFunc       func(*Flags, []string) error
}

// FlagTemplate is the template for one flag flag
type FlagTemplate struct {
	Name  string
	Value interface{}
	Help  string
}

// HelpFlagTemplate is default flag for '-help'
var HelpFlagTemplate = FlagTemplate{
	Name:  "Help",
	Value: false,
	Help:  "help",
}

// Flags is the another FlagSet
type Flags struct {
	ID              string
	Name            string
	Help            string
	Description     string
	Usage           string
	IsGroup         bool
	Flags           []FlagTemplate
	Subcommands     []*Flags
	ParseFuncBefore func(*Flags, []string) error
	ParseFunc       func(*Flags, []string) error

	Template      *FlagsTemplate
	FlagSet       *flag.FlagSet
	rawFlagSet    *flag.FlagSet
	FlagSetValues map[string]interface{}
	Values        map[string]interface{}
	Subcommand    *Flags
	Parent        *Flags

	out          io.Writer
	helpTemplate string
}

// NewFlags renders FlagsTemplate
func NewFlags(ft *FlagsTemplate, parent *Flags) (fs *Flags) {
	fs = &Flags{
		ID:              ft.ID,
		Name:            ft.Name,
		Usage:           ft.Usage,
		Help:            ft.Help,
		Description:     ft.Description,
		IsGroup:         ft.IsGroup,
		ParseFuncBefore: ft.ParseFuncBefore,
		ParseFunc:       ft.ParseFunc,
		Template:        ft,
		Parent:          parent,
	}

	fs.FlagSetValues = map[string]interface{}{}

	rawflagset := flag.NewFlagSet(fs.Name, flag.ContinueOnError)
	fs.rawFlagSet = rawflagset

	flagset := flag.NewFlagSet(fs.Name, flag.ContinueOnError)
	fs.FlagSet = flagset
	flagset.SetOutput(ioutil.Discard)

	flags := ft.Flags
	for _, f := range flags {
		NewFlag(fs.rawFlagSet, f)
	}

	flags = append(flags, HelpFlagTemplate)
	for _, f := range flags {
		fs.FlagSetValues[f.Name] = NewFlag(fs.FlagSet, f)
	}

	for _, s := range ft.Subcommands {
		fs.Subcommands = append(fs.Subcommands, NewFlags(s, fs))
	}

	fs.SetOutput(os.Stdout)
	fs.helpTemplate = defaultHelpTemplate

	return
}

// SetHelpTemplate sets the template for help
func (f *Flags) SetHelpTemplate(t string) {
	f.helpTemplate = t
	for _, s := range f.Subcommands {
		s.SetHelpTemplate(t)
	}
}

// SetOutput sets output io.writer
func (f *Flags) SetOutput(out io.Writer) {
	f.out = out
	for _, s := range f.Subcommands {
		s.SetOutput(out)
	}
}

// Parse is similar with RawParse(), but Parse() handles errors
func (f *Flags) Parse(args []string) (err error) {
	err = f.RawParse(args)
	if err != nil {
		if err == flag.ErrHelp {
			f.PrintHelp(nil)
			return &ErrorOccured{Err: err}
		}

		switch err.(type) {
		case *ErrorOccured:
			// pass, help already printed
		case *MissingCommand:
			f.PrintHelp(err)
			return &ErrorOccured{Err: err}
		case *UnknownCommand:
			f.PrintHelp(err)
			return &ErrorOccured{Err: err}
		default:
			f.PrintHelp(err)
			return &ErrorOccured{Err: err}
		}
	}

	return
}

// RawParse parses arguments
func (f *Flags) RawParse(args []string) (err error) {
	if f.ParseFuncBefore != nil {
		if err = f.ParseFuncBefore(f, args); err != nil {
			return
		}
	}

	if err = f.FlagSet.Parse(args); err != nil {
		return
	}

	f.Values = parseFlagSetValues(f.FlagSetValues)

	if f.Values["Help"].(bool) {
		err = flag.ErrHelp
		return
	}

	if f.ParseFunc != nil {
		if err = f.ParseFunc(f, args); err != nil {
			return
		}
	}

	commandArgs := f.FlagSet.Args()

	var subCommand *Flags
	if len(f.Subcommands) > 0 {
		if len(commandArgs) < 1 {
			err = &MissingCommand{}
			return
		} else {
			for _, s := range f.Subcommands {
				if saultcommon.MakeFirstLowerCase(s.Name) == commandArgs[0] {
					subCommand = s
					break
				}
			}
			if subCommand == nil {
				err = &UnknownCommand{Command: commandArgs[0]}
				return
			}

			err = subCommand.Parse(commandArgs[1:])
			if err != nil {
				return err
			}
		}
	}
	f.Subcommand = subCommand

	return
}

// GetParentCommands parses arguments
func (f *Flags) GetParentCommands() []*Flags {
	parents := []*Flags{f}

	if f.Parent == nil {
		return parents
	}

	s := f.Parent.GetParentCommands()
	return append(s, parents...)
}

// GetSubCommands parses arguments
func (f *Flags) GetSubCommands() []*Flags {
	s := []*Flags{f}

	if len(f.Subcommands) < 1 {
		return s
	}

	return append(s, f.Subcommand.GetSubCommands()...)
}

// PrintHelp prints help
func (f *Flags) PrintHelp(err error) {
	if err == flag.ErrHelp {
		err = nil
	}

	var defaultFlags string
	{
		var b bytes.Buffer
		f.rawFlagSet.SetOutput(&b)
		f.rawFlagSet.PrintDefaults()

		defaultFlags = b.String()
		defaultFlags = fmt.Sprintf("%s  -h -help", defaultFlags)
	}

	var errorString string
	if err != nil {
		errorString = saultcommon.MakeOutputString(log, err.Error(), logrus.ErrorLevel)
	}

	var commandNames []string
	for _, n := range f.GetParentCommands() {
		commandNames = append(commandNames, n.Name)
	}

	fmt.Println(">>", f.Name, f.Subcommands)
	values := map[string]interface{}{
		"error":    errorString,
		"f":        f,
		"defaults": defaultFlags,
		"commands": commandNames[1:],
	}

	var description string
	if len(strings.TrimSpace(f.Description)) > 0 {
		description, err = saultcommon.Templating(f.Description, values)
		if err != nil {
			return
		}
	}
	values["description"] = strings.TrimSpace(description)

	o, err := saultcommon.Templating(f.helpTemplate, values)
	if err != nil {
		return
	}
	fmt.Fprint(
		f.out,
		strings.TrimSpace(o)+"\n"+"\n",
	)

	return
}

// NewFlag renders FlagTemplate
func NewFlag(flagSet *flag.FlagSet, ft FlagTemplate) interface{} {
	name := saultcommon.MakeFirstLowerCase(ft.Name)
	defaultValue := ft.Value
	help := ft.Help

	switch ft.Value.(type) {
	case string:
		var val string
		flagSet.StringVar(&val, name, defaultValue.(string), help)
		return &val
	case bool:
		var val bool
		flagSet.BoolVar(&val, name, defaultValue.(bool), help)
		return &val
	case int:
		var val int
		flagSet.IntVar(&val, name, defaultValue.(int), help)
		return &val
	case float64:
		var val float64
		flagSet.Float64Var(&val, name, defaultValue.(float64), help)
		return &val
	default:
		val := reflect.ValueOf(defaultValue).Interface().(flag.Value)
		flagSet.Var(val, name, help)

		return val
	}
}

func parseFlagSetValues(flagsetValues map[string]interface{}) (values map[string]interface{}) {
	values = map[string]interface{}{}
	for name, value := range flagsetValues {
		values[name] = parseFlagSetValue(name, value)
	}

	return
}

func parseFlagSetValue(name string, value interface{}) interface{} {
	switch value.(type) {
	case *string:
		return *value.(*string)
	case *bool:
		return *value.(*bool)
	case *int:
		return *value.(*int)
	case *float64:
		return *value.(*float64)
	default:
		return reflect.Indirect(reflect.ValueOf(value)).Interface()
	}

	return nil
}
