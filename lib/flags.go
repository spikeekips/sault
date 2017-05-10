package sault

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	log "github.com/Sirupsen/logrus"
)

type OptionsValues map[string]interface{}
type ErrInvalidCommand struct {
	s string
}

func (e *ErrInvalidCommand) Error() string {
	return e.s
}

type ErrMissingCommand struct {
	s string
}

func (e *ErrMissingCommand) Error() string {
	return "command is missing"
}

func PrintHelp(options *Options, err error) {
	tmpl, _ := template.New("t").Funcs(CommonTempalteFMap).Parse(`
Usage: {{.command }} {{.usage | escape }}
{{ if ne .description "" }}
{{ .line }}
{{ .description | escape}}
{{ .line }} {{ end }}{{.globalFlags | escape }}{{.commands | escape}}
`)

	commandsTmpl, _ := template.New("t").Funcs(CommonTempalteFMap).Parse(`
There are serveral commands:
{{.commands | escape}}
`)

	var errorString string
	if err == flag.ErrHelp {
		errorString = ""
		err = nil
	} else {
		switch err.(type) {
		case *ErrMissingCommand, *ErrInvalidCommand:
			errorString = fmt.Sprintf("%v", err)
			err = nil
		default:
			errorString = fmt.Sprintf("%v", err)
		}
	}

	val := reflect.ValueOf(options).Elem()
	command := val.FieldByName("Name").Interface().(string)
	usage := val.FieldByName("Usage").Interface().(string)
	flagSet := val.FieldByName("FlagSet").Interface().(*flag.FlagSet)

	var bw *bytes.Buffer

	var commandsHelps string
	if err == nil && options.HasCommands() {
		bw = bytes.NewBuffer([]byte{})
		var ch []string

		var maxLen int
		for _, c := range options.Commands {
			if maxLen < len(c.Name) {
				maxLen = len(c.Name)
			}
		}

		format := fmt.Sprintf("   %%%ds    %%s", maxLen)
		for _, c := range options.Commands {
			var l string
			if c.IsGroup {
				l = fmt.Sprintf("\n%s", c.Help)
			} else {
				l = fmt.Sprintf(format, c.Name, c.Help)
			}
			ch = append(ch, l)
		}
		commandsTmpl.Execute(
			bw,
			map[string]interface{}{
				"commands": strings.Join(ch, "\n"),
			},
		)

		commandsHelps = bw.String()
	}

	var globalFlags string
	globalFlagsDefaults := GetDefaults(flagSet)
	if strings.TrimSpace(globalFlagsDefaults) == "" {
		globalFlags = ""
	} else {
		globalFlags = fmt.Sprintf(`
global flags:
%s
`,
			strings.TrimRight(globalFlagsDefaults, " \n"),
		)
	}

	bw = bytes.NewBuffer([]byte{})
	tmpl.Execute(
		bw,
		map[string]interface{}{
			"command":     command,
			"usage":       usage,
			"description": options.Description,
			"globalFlags": globalFlags,
			"commands":    commandsHelps,
			"line":        strings.Repeat("-", int(CurrentTermSize.Col)),
		},
	)

	if errorString != "" {
		log.Errorf(errorString)
	}

	fmt.Fprintf(
		os.Stdout,
		strings.TrimRight(strings.TrimLeft(bw.String(), " \n"), "\n")+"\n\n",
	)
}

func GetDefaults(flagSet *flag.FlagSet) string {
	bw := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(bw)
	flagSet.PrintDefaults()

	return bw.String()
}

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

func NewOptions(ost OptionsTemplate) (*Options, error) {
	var options []OptionTemplate

	co := Options{Name: ost.Name}

	for _, option := range ost.Options {
		options = append(options, option)
	}

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

func (op *Options) HasCommands() bool {
	return len(op.Commands) > 0
}

func (op *Options) Parse(args []string) error {
	if err := op.FlagSet.Parse(args); err != nil {
		PrintHelp(op, err)
		return err
	}

	if op.ParseFunc != nil {
		if err := op.ParseFunc(op, args); err != nil {
			PrintHelp(op, err)
			return err
		}
	}

	if !op.HasCommands() {
		return nil
	}

	commandArgs := op.FlagSet.Args()
	if len(commandArgs) < 1 {
		err := &ErrMissingCommand{}
		PrintHelp(op, err)
		return err
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
		err := &ErrInvalidCommand{fmt.Sprintf("invalid command, `%s`", commandArgs[0])}
		PrintHelp(op, err)

		return err
	}

	op.Command = command
	op.CommandOptions = commandOptions

	return commandOptions.Parse(commandArgs[1:])
}

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
		for k, v := range op.Extra {
			m[k] = v
		}
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

type OptionTemplate struct {
	Name         string
	DefaultValue interface{}
	Help         string
	ValueType    interface{}
}

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