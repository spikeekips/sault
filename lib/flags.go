package sault

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/fatih/color"
)

var helpTemplate = `
{{ if eq .error "" }}{{ if ne .description "" }}
{{ "*sault*   " | center | blue }}

{{ .description | escape}}
{{ end }}{{ end }}
{{ if ne .error "" }}{{ "error" | red }}: {{ .error | escape }}
{{end}}{{ "usage" | magenta }}: {{.command | escape }} {{.usage | escape }}

{{.globalFlags | escape }}{{.commands | escape}}
`

var helpGlobalTempalte = `flags:
%s
`

var helpCommandTemplate = `
There are serveral commands:
{{.commands | escape}}
`

var helpOption = OptionTemplate{
	Name:         "H",
	Help:         "help",
	DefaultValue: false,
}

// OptionsValues is the values of flag options
type OptionsValues map[string]interface{}

// PrintHelp will print help message
func PrintHelp(options *Options, inputError error) {
	var errorString string
	if inputError == flag.ErrHelp {
		inputError = nil
	} else {
		switch inputError.(type) {
		case *missingCommandError:
			inputError = nil
		case *UnknownCommandError:
			errorString = inputError.Error()
			inputError = nil
		default:
			errorString = inputError.Error()
		}
	}

	val := reflect.ValueOf(options).Elem()
	command := val.FieldByName("Name").Interface().(string)
	usage := val.FieldByName("Usage").Interface().(string)
	flagSet := val.FieldByName("FlagSet").Interface().(*flag.FlagSet)

	var err error
	var commandsHelps string
	if inputError == nil && options.hasCommands() {
		var ch []string

		var maxLen int
		for _, c := range options.Commands {
			if maxLen < len(c.Name) {
				maxLen = len(c.Name)
			}
		}

		format := fmt.Sprintf("   %%%ds  ", maxLen)
		for _, c := range options.Commands {
			var l string
			if c.IsGroup {
				l = fmt.Sprintf("\n%s", c.Help)
			} else {
				l = fmt.Sprintf(
					"%s  %s",
					colorFunc(color.FgYellow)(fmt.Sprintf(format, c.Name)),
					c.Help,
				)
			}
			ch = append(ch, l)
		}
		commandsHelps, err = ExecuteCommonTemplate(
			helpCommandTemplate,
			map[string]interface{}{
				"commands": strings.Join(ch, "\n"),
			},
		)
	}

	var globalFlags string
	globalFlagsDefaults := getDefaults(flagSet)
	if strings.TrimSpace(globalFlagsDefaults) == "" {
		globalFlags = ""
	} else {
		globalFlags = fmt.Sprintf(
			helpGlobalTempalte,
			strings.TrimRight(globalFlagsDefaults, " \n"),
		)
	}
	description, err := ExecuteCommonTemplate(options.Description, nil)
	if err != nil {
		log.Error(err)
		CommandOut.Errorf("something wrong")
		return
	}

	helpString, err := ExecuteCommonTemplate(
		helpTemplate,
		map[string]interface{}{
			"error":       errorString,
			"command":     command,
			"usage":       usage,
			"description": description,
			"globalFlags": globalFlags,
			"commands":    commandsHelps,
			"line":        strings.Repeat("-", int(currentTermSize.Col)),
		},
	)
	if err != nil {
		log.Error(err)
		return
	}

	CommandOut.Println(
		strings.TrimRight(strings.TrimLeft(helpString, " \n"), "\n") + "\n\n",
	)
}

func getDefaults(flagSet *flag.FlagSet) string {
	bw := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(bw)
	flagSet.PrintDefaults()

	return bw.String()
}

// Options is the flag option set
type Options struct {
	Name        string
	Help        string
	Description string
	Usage       string
	IsGroup     bool
	FlagSet     *flag.FlagSet
	Options     []OptionTemplate
	Commands    []*Options
	ParseFunc   func(*Options, []string) error

	Vars map[string]interface{}

	Command        string   // parsed command
	CommandOptions *Options // parsed command options

	Extra map[string]interface{}
}

func setFlagFromOption(fs *flag.FlagSet, option OptionTemplate) interface{} {
	name := MakeFirstLowerCase(option.Name)
	if fs.Lookup(name) != nil {
		log.Errorf("`%s` flag already defined", name)
		return nil
	}

	if option.ValueType != nil {
		val := reflect.ValueOf(option.ValueType).Elem().FieldByName("Type").Addr().Interface().(flag.Value)
		fs.Var(val, name, option.Help)

		return val
	}

	switch option.DefaultValue.(type) {
	case string:
		var val string
		fs.StringVar(&val, name, option.DefaultValue.(string), option.Help)
		return &val
	case bool:
		var val bool
		fs.BoolVar(&val, name, option.DefaultValue.(bool), option.Help)
		return &val
	case int:
		var val int
		fs.IntVar(&val, name, option.DefaultValue.(int), option.Help)
		return &val
	case float64:
		var val float64
		fs.Float64Var(&val, name, option.DefaultValue.(float64), option.Help)
		return &val
	default:
		log.Errorf("found invalid flag, `%v`", option)
	}

	return nil
}

// NewOptions make new Options
func NewOptions(ost OptionsTemplate) (*Options, error) {
	var options []OptionTemplate

	co := Options{Name: ost.Name}

	for _, option := range ost.Options {
		options = append(options, option)
	}
	options = append(options, helpOption)

	fs := flag.NewFlagSet(ost.Name, flag.ContinueOnError)
	fs.SetOutput(ioutil.Discard)

	vars := map[string]interface{}{}
	for _, o := range options {
		val := setFlagFromOption(fs, o)
		if val == nil {
			continue
		}

		vars[o.Name] = val
	}

	co.FlagSet = fs
	co.Options = options
	co.Help = ost.Help
	co.Description = strings.TrimSpace(ost.Description)
	co.Usage = ost.Usage
	co.IsGroup = ost.IsGroup
	co.ParseFunc = ost.ParseFunc
	co.Vars = vars

	var commands []*Options
	for _, c := range ost.Commands {
		op, err := NewOptions(c)
		if err != nil {
			return nil, err
		}
		commands = append(commands, op)
	}

	co.Commands = commands

	return &co, nil
}

func (op *Options) hasCommands() bool {
	return len(op.Commands) > 0
}

// Parse tries to parse the input arguments
func (op *Options) parse(args []string) (*Options, error) {
	if err := op.FlagSet.Parse(args); err != nil {
		return op, err
	}

	if op.ParseFunc != nil {
		op.Extra = map[string]interface{}{}

		if err := op.ParseFunc(op, args); err != nil {
			return op, err
		}
	}

	if !op.hasCommands() {
		return op, nil
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) < 1 {
		err := &missingCommandError{}
		return op, err
	}

	var command string
	var commandOptions *Options
	for _, s := range op.Commands {
		if s.Name == commandArgs[0] {
			command = s.Name
			commandOptions = s
			break
		}
	}

	if command == "" {
		err := &UnknownCommandError{Command: commandArgs[0]}
		return op, err
	}

	op.Command = command
	op.CommandOptions = commandOptions

	return commandOptions.parse(commandArgs[1:])
}

func (op *Options) Parse(args []string) error {
	var helpRequested bool
	for _, a := range args {
		if a == "-h" || a == "--help" {
			helpRequested = true
		}
	}

	options, err := op.parse(args)
	if helpRequested {
		PrintHelp(options, flag.ErrHelp)
		return err
	}

	if err != nil {
		PrintHelp(options, err)
	}

	return err
}

// Values marshals the parsed arguments and it's values
func (op *Options) Values(deep bool) OptionsValues {
	m := OptionsValues{
		"Name":        op.Name,
		"Commands":    OptionsValues{},
		"Options":     OptionsValues{},
		"CommandName": op.Name,
	}

	values := OptionsValues{}
	for _, o := range op.Options {
		values[o.Name] = op.Vars[o.Name]
	}
	m["Options"] = values

	if op.Extra != nil {
		mo := m["Options"].(OptionsValues)
		for k, v := range op.Extra {
			mo[k] = v
		}

		m["Options"] = mo
	}

	if deep {
		if op.Command == "" {
			return m
		}

		m["Commands"] = op.CommandOptions.Values(true)
		m["CommandName"] = fmt.Sprintf("%s.%s", op.Name, m["Commands"].(OptionsValues)["CommandName"].(string))
	}

	return m
}

// OptionTemplate is the template for one flag option
type OptionTemplate struct {
	Name         string
	DefaultValue interface{}
	Help         string
	ValueType    interface{}
}

// OptionsTemplate is the template for Options
type OptionsTemplate struct {
	Name        string
	Usage       string
	Help        string
	Description string
	IsGroup     bool

	Options   []OptionTemplate
	Commands  []OptionsTemplate
	ParseFunc func(*Options, []string) error
}
