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

	"github.com/spikeekips/sault/common"
)

var defaultHelpTemplate = `{{ $el := len .error }}{{ $dl := len .description }}{{ $sl := len .f.Subcommands }}
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

// ErrorOccured wraps error from Parse()
type ErrorOccured struct {
	Err error
}

func (e *ErrorOccured) Error() string {
	return e.Err.Error()
}

// SkipSubCommandError represents the error when unknown command is inserted
type SkipSubCommandError struct{}

func (e *SkipSubCommandError) Error() string {
	return "skip sub command"
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
	IsPositioned    bool
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
	IsPositioned    bool

	Template      *FlagsTemplate
	FlagSet       *flag.FlagSet
	rawFlagSet    *flag.FlagSet
	FlagSetValues map[string]interface{}
	Values        map[string]interface{}
	Subcommand    *Flags
	Parent        *Flags

	out          io.Writer
	helpTemplate string
	args         []string
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
		IsPositioned:    ft.IsPositioned,
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

func (f *Flags) Args() []string {
	return f.args
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

	f.args = f.FlagSet.Args()

	return
}

func (f *Flags) ParsePositioned(args []string) (err error) {
	var positioned, none_positioned []string

	var foundFlag bool
	for _, a := range args {
		if !foundFlag && strings.HasPrefix(a, "-") {
			foundFlag = true
		}

		if foundFlag {
			none_positioned = append(none_positioned, a)
		} else {
			positioned = append(positioned, a)
		}
	}

	f.args = positioned
	err = f.Parse(none_positioned)

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

	var skipSubCommand bool
	if f.ParseFunc != nil {
		if err = f.ParseFunc(f, args); err != nil {
			if _, skipSubCommand = err.(*SkipSubCommandError); skipSubCommand {
				skipSubCommand = true
				err = nil
			} else {
				return
			}
		}
	}

	if !skipSubCommand {
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

				if subCommand.IsPositioned {
					err = subCommand.ParsePositioned(commandArgs[1:])
				} else {
					err = subCommand.Parse(commandArgs[1:])
				}
				if err != nil {
					return err
				}
			}
		}
		f.Subcommand = subCommand
	}

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

// GetSubcommands parses arguments
func (f *Flags) GetSubcommands() []*Flags {
	s := []*Flags{f}

	if f.Subcommand == nil || len(f.Subcommands) < 1 {
		return s
	}

	return append(s, f.Subcommand.GetSubcommands()...)
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
		errorString = err.Error()
	}

	var commandNames []string
	for _, n := range f.GetParentCommands() {
		commandNames = append(commandNames, n.Name)
	}

	values := map[string]interface{}{
		"error":    errorString,
		"f":        f,
		"defaults": defaultFlags,
		"commands": commandNames[1:],
	}

	var description string
	if len(strings.TrimSpace(f.Description)) > 0 {
		description, err = saultcommon.SimpleTemplating(f.Description, values)
		if err != nil {
			return
		}
	}
	values["description"] = strings.TrimSpace(description)

	o, err := saultcommon.SimpleTemplating(f.helpTemplate, values)
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
	name := strings.ToLower(ft.Name)
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
