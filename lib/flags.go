package sault

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	log "github.com/Sirupsen/logrus"
)

var CommandsFlags []Flags

func init() {
	CommandsFlags = []Flags{
		&FlagsGroupFlags{Description: "commands for sault server"},
		&ServerFlags{
			Name:        "server",
			Description: "run sault server",
			Usage:       "server [flags]",
		},

		/*
			&FlagsGroupFlags{Description: "commands for control sault server"},
			&UserFlags{
				Name:        "user",
				Description: "manage user",
				Usage:       "user [flags]",
			},
		*/
	}
}

func SetFlagSetFromFlags(flags Flags) *flag.FlagSet {
	val := reflect.ValueOf(flags).Elem()

	fs := flag.NewFlagSet(val.FieldByName("Name").String(), flag.ContinueOnError)
	fs.SetOutput(ioutil.Discard)

	val.FieldByName("FlagSet").Set(reflect.ValueOf(fs))

	typ := val.Type()

	for i, n := 0, val.NumField(); i < n; i++ {
		fld := typ.Field(i)

		if _, ok := fld.Tag.Lookup("flag"); !ok {
			continue
		}

		name := MakeFirstLowerCase(fld.Name)
		var defValue interface{}
		if v, ok := fld.Tag.Lookup("default"); ok {
			defValues := []interface{}{""}
			if err := json.Unmarshal([]byte(v), &defValues); err != nil {
				log.Errorf("failed to parse default flag value for %s: %v", name, err)
				defValues = []interface{}{""}
			}
			defValue = defValues[0]
		}
		usage := fld.Tag.Get("help")

		p := val.Field(i).Addr().Interface()
		switch p := p.(type) {
		case *string:
			fs.StringVar(p, name, defValue.(string), usage)
		case *bool:
			fs.BoolVar(p, name, defValue.(bool), usage)
		case *int:
			fs.IntVar(p, name, int(defValue.(float64)), usage)
		case *float64:
			fs.Float64Var(p, name, defValue.(float64), usage)
		default:
			fs.Var(p.(flag.Value), name, usage)
		}
	}

	return fs
}

func printDefaults(flagSet *flag.FlagSet, usage string) string {
	bw := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(bw)
	flagSet.PrintDefaults()

	usageString := ""
	if usage != "" {
		usageString = fmt.Sprintf(
			"Usage: %s\n",
			usage,
		)
	}

	return fmt.Sprintf(
		"%s%s",
		usageString,
		bw.String(),
	)
}

func printUsage(defaults string, err error) {
	out := os.Stdout
	var errorString string
	if err != nil && len(err.Error()) > 1 {
		out = os.Stderr
		errorString = fmt.Sprintf("[error] %s\n", err.Error())
	}

	fmt.Fprintf(out, "%s%s", errorString, defaults)
}

func getHelp(format string, flags Flags) string {
	l := strings.Split(fmt.Sprintf("%s", reflect.TypeOf(flags)), ".")
	typeName := l[len(l)-1]

	val := reflect.ValueOf(flags).Elem()
	desc := val.FieldByName("Description")

	if typeName == "FlagsGroupFlags" {
		return fmt.Sprintf("\n%s", desc.String())
	}

	return fmt.Sprintf(
		format,
		val.FieldByName("Name").String(),
		desc.String(),
	)
}

func toMap(flags Flags, skipInernal bool) map[string]interface{} {
	if !skipInernal {
		method := reflect.ValueOf(flags).MethodByName("ToMap") //
		if method.IsValid() {
			rValues := method.Call([]reflect.Value{})
			rValue := rValues[0].Interface().(map[string]interface{})
			if rValue != nil {
				return rValue
			}
		}
	}

	m := map[string]interface{}{}

	val := reflect.ValueOf(flags).Elem()
	for i, n := 0, val.NumField(); i < n; i++ {
		fld := val.Type().Field(i)
		if _, ok := fld.Tag.Lookup("flag"); !ok {
			continue
		}
		p := val.Field(i).Interface()
		m[fld.Name] = p
	}

	return m
}

func NewGlobalFlags(name string) *GlobalFlags {
	gf := &GlobalFlags{Name: name}
	SetFlagSetFromFlags(gf)

	return gf
}

type Flags interface {
	Parse(args []string) error
}

// psuedo Flags for grouping commands
type FlagsGroupFlags struct {
	Description string
}

func (f *FlagsGroupFlags) Parse(args []string) error { return nil }

type FlagLogFormat string

func (l *FlagLogFormat) String() string {
	return string(*l)
}

func (l *FlagLogFormat) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogFormat(DefaultLogFormat)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range AvailableLogFormats {
		if f == nv {
			*l = FlagLogFormat(nv)
			return nil
		}
	}

	return errors.New("")
}

type FlagLogLevel string

func (l *FlagLogLevel) String() string {
	return string(*l)
}

func (l *FlagLogLevel) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogLevel(DefaultLogLevel)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range AvailableLogLevel {
		if f == nv {
			*l = FlagLogLevel(nv)
			return nil
		}
	}

	return errors.New("")
}

type FlagLogOutput string

func (l *FlagLogOutput) String() string {
	return string(*l)
}

func (l *FlagLogOutput) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogOutput(DefaultLogOutput)
		return nil
	}

	nv := strings.ToLower(value)
	_, err := ParseLogOutput(value, "")
	if err == nil {
		*l = FlagLogOutput(nv)
		return nil
	}

	return errors.New("")
}

var DefaultLogFormat = "text"
var DefaultLogLevel = "info"
var DefaultLogOutput = "stdout"

type GlobalFlags struct {
	Name        string
	Usage       string
	Description string
	FlagSet     *flag.FlagSet

	commandName  string
	commandFlags Flags

	LogFormat FlagLogFormat `flag:"" help:"log format: [text json] (default \"text\")"`
	LogLevel  FlagLogLevel  `flag:"" help:"log level: [debug info warn error fatal quiet] (default \"info\")"`
	LogOutput FlagLogOutput `flag:"" help:"log output: [stdout stderr <file name>] (default \"stdout\")"`
}

func (f *GlobalFlags) parse(args []string) (Flags, error) {
	if len(args) < 1 {
		return f, errors.New("")
	}
	err := f.FlagSet.Parse(args)
	if err != nil {
		return f, err
	}

	if err := f.Parse(args); err != nil {
		return f, err
	}

	commandArgs := f.FlagSet.Args()
	if len(commandArgs) < 1 {
		return f, errors.New("command is missing")
	}

	var command string
	var flags Flags
	for _, c := range CommandsFlags {
		v := reflect.ValueOf(c).Elem().FieldByName("Name")
		if v.String() == commandArgs[0] {
			command = v.String()
			flags = c
			break
		}
	}

	if command == "" {
		return f, fmt.Errorf("unknown command, `%s`", commandArgs[0])
	}

	f.commandName = command
	f.commandFlags = flags

	SetFlagSetFromFlags(flags)

	rValues := reflect.ValueOf(flags).Elem().FieldByName("FlagSet").MethodByName("Parse").Call([]reflect.Value{
		reflect.ValueOf(commandArgs[1:]),
	})
	if rv, ok := rValues[0].Interface().(error); ok {
		return flags, rv
	}

	rValues = reflect.ValueOf(flags).MethodByName("Parse").Call([]reflect.Value{
		reflect.ValueOf(commandArgs[1:]),
	})
	if rv, ok := rValues[0].Interface().(error); ok {
		return flags, rv
	}

	return f, nil
}

func (f *GlobalFlags) Parse(args []string) error {
	if f.LogFormat == "" {
		f.LogFormat = FlagLogFormat(DefaultLogFormat)
	}
	if f.LogLevel == "" {
		f.LogLevel = FlagLogLevel(DefaultLogLevel)
	}
	if f.LogOutput == "" {
		f.LogOutput = FlagLogOutput(DefaultLogOutput)
	}

	return nil
}

func (f *GlobalFlags) ParseAll() error {
	fs, err := f.parse(os.Args[1:])

	if err == nil {
		return nil
	}

	if f == fs {
		printUsage(f.GetFullUsage(), err)
		return errors.New("")
	}

	val := reflect.ValueOf(fs).Elem()
	flagSet := val.FieldByName("FlagSet").Interface().(*flag.FlagSet)
	usage := val.FieldByName("Usage").String()
	printUsage(printDefaults(flagSet, usage), err)

	return errors.New("")
}

func (f *GlobalFlags) GetFullUsage() string {
	tmpl, _ := template.New("t").Parse(`
Usage: {{.program}} [global flags] command [flags]

global flags:
{{.globalFlags}}

There are serveral sault commands:
{{.commandsFlags}}

`)

	globalUsage := printDefaults(f.FlagSet, "")

	commandsDescription := []string{}

	var maxLength int
	for _, c := range CommandsFlags {
		name := reflect.ValueOf(c).Elem().FieldByName("Name")
		if !name.IsValid() {
			continue
		}
		if l := len(name.String()); l > maxLength {
			maxLength = l
		}
	}

	format := fmt.Sprintf(
		"   %s   %%s",
		fmt.Sprintf("%%-%ds", maxLength),
	)
	for _, c := range CommandsFlags {
		commandsDescription = append(
			commandsDescription,
			getHelp(format, c),
		)
	}

	bw := bytes.NewBuffer([]byte{})
	tmpl.Execute(
		bw,
		map[string]interface{}{
			"program":       f.Name,
			"globalFlags":   template.HTML(strings.TrimRight(globalUsage, " \n")),
			"commandsFlags": template.HTML(strings.Join(commandsDescription, "\n")),
		},
	)

	return strings.TrimLeft(bw.String(), " \n")
}

type ParsedFlags map[string]map[string]interface{}

func (f *GlobalFlags) ToMapAll() ParsedFlags {
	globalFlags := toMap(f, false)
	globalFlags["command"] = f.commandName
	return ParsedFlags(map[string]map[string]interface{}{
		"global":  globalFlags,
		"command": toMap(f.commandFlags, false),
	})
}

func (f *GlobalFlags) ToJSONAll() ([]byte, error) {
	return json.MarshalIndent(f.ToMapAll(), "", "  ")
}
