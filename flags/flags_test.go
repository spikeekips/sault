package saultflags

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/spikeekips/sault/common"
)

func TestNewFlags(t *testing.T) {
	{
		// NewFlags renders FlagsTemplate and it's field values
		mainFlags := &FlagsTemplate{
			Name:  saultcommon.MakeRandomString(),
			Flags: []FlagTemplate{},
		}

		flags := NewFlags(mainFlags, nil)
		if flags.Name != mainFlags.Name {
			t.Errorf("flags.Name != mainFlags.Name; '%s' != '%s'", flags.Name, mainFlags.Name)
		}
		if flags.Help != mainFlags.Help {
			t.Errorf("flags.Help != mainFlags.Help; '%s' != '%s'", flags.Help, mainFlags.Help)
		}
		if flags.Usage != mainFlags.Usage {
			t.Errorf("flags.Usage != mainFlags.Usage; '%s' != '%s'", flags.Usage, mainFlags.Usage)
		}
	}

	{
		// default flag types
		flagValues := map[string][]interface{}{
			"FString":  []interface{}{"not bad", "so good"}, // default value, arguments value
			"FInt":     []interface{}{10, 20},
			"FFloat64": []interface{}{0.0, 1.64},
		}

		args := []string{}
		flagTemplates := []FlagTemplate{}
		for name, value := range flagValues {
			flagTemplates = append(
				flagTemplates,
				FlagTemplate{Name: name, Value: value[0]},
			)
			args = append(args, "-"+strings.ToLower(name), fmt.Sprintf("%v", value[1]))
		}
		flagTemplates = append(
			flagTemplates,
			FlagTemplate{
				Name:  "FBool",
				Value: false,
			},
		)
		args = append(args, "-fbool")

		mainFlags := &FlagsTemplate{
			Name:  saultcommon.MakeRandomString(),
			Flags: flagTemplates,
		}

		var flags *Flags
		var err error
		flags = NewFlags(mainFlags, nil)
		if err != nil {
			t.Error(err)
		}

		err = flags.Parse(args)
		if err != nil {
			t.Error(err)
		}

		for name, value := range flagValues {
			if parsedValue, ok := flags.Values[name]; !ok {
				t.Errorf("flag '%s' was not parsed", name)
			} else if parsedValue != value[1] {
				t.Errorf("flag '%s', parsedValue != value; '%v' != '%v'", name, parsedValue, value[1])
			}
		}
		if parsedValue, ok := flags.Values["FBool"]; !ok {
			t.Errorf("flag 'FBool' was not parsed")
		} else if parsedValue != true {
			t.Errorf("flag 'FBool', parsedValue != value; '%v' != true", parsedValue)
		}
	}
}

type lowercaseFlag string

func (l *lowercaseFlag) Set(s string) error {
	*l = lowercaseFlag(strings.ToLower(s))
	return nil
}

func (l *lowercaseFlag) Get() interface{} {
	return string(*l)
}

func (l *lowercaseFlag) String() string {
	return string(*l)
}

var defaultLowercaseFlag = lowercaseFlag("")

func TestCustomFlag(t *testing.T) {
	flagsTemplate := &FlagsTemplate{
		Name: saultcommon.MakeRandomString(),
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "Lower",
				Value: &defaultLowercaseFlag,
			},
		},
	}

	flags := NewFlags(flagsTemplate, nil)

	origValue := "MAKE-ME-LOWER"
	expectedValue := strings.ToLower(origValue)
	err := flags.Parse([]string{"-lower", origValue})
	if err != nil {
		t.Error(err)
	}

	if parsedValue, ok := flags.Values["Lower"]; !ok {
		t.Errorf("custom flag 'Lower' was not parsed")
	} else if parsedValue.(lowercaseFlag) != lowercaseFlag(expectedValue) {
		t.Errorf("custom flag 'Lower', parsedValue != value; '%v(%T)' != '%v(%T)'",
			parsedValue, parsedValue, expectedValue, expectedValue,
		)
	}
}

func TestParseFlag(t *testing.T) {
	flagsTemplate := &FlagsTemplate{
		Name: saultcommon.MakeRandomString(),
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "Lower",
				Value: &defaultLowercaseFlag,
			},
		},
		ParseFunc: func(f *Flags, args []string) error {
			f.Values["Lower1"] = string(f.Values["Lower"].(lowercaseFlag)) + "1"
			return nil
		},
	}

	flags := NewFlags(flagsTemplate, nil)

	origValue := "MAKE-ME-LOWER"
	expectedValue := strings.ToLower(origValue)
	expectedValue1 := strings.ToLower(origValue) + "1"
	err := flags.Parse([]string{"-lower", origValue})
	if err != nil {
		t.Error(err)
	}

	{
		if parsedValue, ok := flags.Values["Lower"]; !ok {
			t.Errorf("custom flag 'Lower' was not parsed")
		} else if parsedValue.(lowercaseFlag) != lowercaseFlag(expectedValue) {
			t.Errorf("custom flag 'Lower', parsedValue != value; '%v(%T)' != '%v(%T)'",
				parsedValue, parsedValue, expectedValue, expectedValue,
			)
		}
	}

	{
		if parsedValue, ok := flags.Values["Lower1"]; !ok {
			t.Errorf("custom flag 'Lower' was not parsed")
		} else if parsedValue.(string) != expectedValue1 {
			t.Errorf("custom flag 'Lower', parsedValue != value; '%v(%T)' != '%v(%T)'",
				parsedValue, parsedValue, expectedValue1, expectedValue1,
			)
		}
	}
}

func TestFlagPrintHelp(t *testing.T) {
	mainFlags := &FlagsTemplate{
		Name: saultcommon.MakeRandomString(),
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "Name",
				Value: "default name",
			},
		},
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{
			"-name",
			"My Name",
		}
		if err := flags.Parse(args); err != nil {
			t.Error(err)
		}
	}

	{
		// '-help', first of flags
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{
			"-help",
			"-name",
			"My Name",
		}
		var err error
		if err = flags.Parse(args); err == nil {
			t.Error("'flag.ErrHelp' must be returned")
		}
		if err, _ := err.(*ErrorOccured); err.Err != flag.ErrHelp {
			t.Error("err must be flag.ErrHelp")
		}
	}

	{
		// '-help', end of flags
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{
			"-name",
			"My Name",
			"-help",
		}
		var err error
		if err = flags.Parse(args); err == nil {
			t.Error("'flag.ErrHelp' must be returned")
		}
		if err, _ := err.(*ErrorOccured); err.Err != flag.ErrHelp {
			t.Error("err must be flag.ErrHelp")
		}
	}

	{
		// '-help', in the middle of flags
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{
			"-name",
			"-help",
			"My Name",
		}
		if err := flags.Parse(args); err != nil {
			t.Error(err)
		}
	}
}

func TestFlagSubcommands(t *testing.T) {
	subCommand := &FlagsTemplate{
		Name: "Sub0",
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "SubName",
				Value: "sub name",
			},
		},
	}

	mainFlags := &FlagsTemplate{
		Name: saultcommon.MakeRandomString(),
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "Name",
				Value: "default name",
			},
		},
		Subcommands: []*FlagsTemplate{
			subCommand,
		},
	}

	flags := NewFlags(mainFlags, nil)

	args := []string{"-name", "killme", "sub0", "-subname", "ok good"}
	{
		err := flags.Parse(args)
		if err != nil {
			t.Error(err)
		}
	}

	if flags.Subcommand == nil {
		t.Errorf("subcommand must be parsed")
	}
	if flags.Subcommand.Name != subCommand.Name {
		t.Errorf("flags.Subcommand.Name != subCommand.Name; '%s' != '%s'", flags.Subcommand.Name, subCommand.Name)
	}

	if flags.Subcommand.Values["SubName"].(string) != args[4] {
		t.Errorf(
			`flags.Subcommand.Values["SubName"].(string) != args[4]; '%v' != '%v'`,
			flags.Subcommand.Values["SubName"].(string),
			args[4],
		)
	}
}

func TestFlagSubcommandsHelp(t *testing.T) {
	mainFlags := &FlagsTemplate{
		Name: saultcommon.MakeRandomString(),
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "Name",
				Value: "default name",
			},
		},
		Subcommands: []*FlagsTemplate{
			&FlagsTemplate{
				Name: "Sub0",
				Flags: []FlagTemplate{
					FlagTemplate{
						Name:  "SubName",
						Value: "sub name",
					},
				},
			},
		},
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{"-name", "killme", "-h", "sub0", "-subName", "ok good"}
		err := flags.Parse(args)
		if err == nil {
			t.Error("err must be flag.ErrHelp")
		}
		if flags.Subcommand != nil {
			t.Error("Zzing???? 'flags.Subcommand' must be nil")
		}
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{"-name", "killme", "-help", "sub0", "-subName", "ok good"}
		err := flags.Parse(args)
		if err == nil {
			t.Error("err must be flag.ErrHelp")
		}
		if flags.Subcommand != nil {
			t.Error("Zzing???? 'flags.Subcommand' must be nil")
		}
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{"-name", "killme", "sub0", "-subName", "ok good", "--help"}
		err := flags.Parse(args)
		if err == nil {
			t.Error("err must be flag.ErrHelp")
		}
		if flags.Subcommand != nil {
			t.Error("Zzing???? 'flags.Subcommand' must be nil")
		}
	}
}

func TestFlagPrintHelpMessage(t *testing.T) {
	mainFlags := &FlagsTemplate{
		Name:        "cName",
		Usage:       "[flags]",
		Description: `this is description`,
		Flags: []FlagTemplate{
			FlagTemplate{Name: "Name", Value: "default name"},
			FlagTemplate{Name: "Blood", Value: "default blood type"},
		},
	}

	{
		var b bytes.Buffer
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(&b) // mute help output
		args := []string{"--help"}
		flags.Parse(args)

		if len(b.String()) < 1 {
			t.Errorf("help must be printed")
		}
	}
}

func TestFlagSubcommandsNames(t *testing.T) {
	subCommand1 := &FlagsTemplate{
		Name: "Sub00",
	}

	subCommand0 := &FlagsTemplate{
		Name:        "Sub0",
		Subcommands: []*FlagsTemplate{subCommand1},
	}

	mainFlags := &FlagsTemplate{
		Name:        "main",
		Subcommands: []*FlagsTemplate{subCommand0},
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard)

		args := []string{"sub0"}
		err := flags.Parse(args)
		if err, ok := err.(*ErrorOccured); !ok {
			if _, ok = err.Err.(*MissingCommand); !ok {
				t.Errorf("'MissingCommand' must be occured, %T", err)
			}
		}
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard)

		args := []string{"sub0", "sub00"}
		err := flags.Parse(args)
		if err != nil {
			log.Error(err)
		}

		expectedCommands := []string{"main", "Sub0", "Sub00"}
		var commands []string
		for _, f := range flags.GetSubcommands() {
			commands = append(commands, f.Name)
		}

		for i := 0; i < len(expectedCommands); i++ {
			if commands[i] != expectedCommands[i] {
				t.Errorf("commands[i] != expectedCommands[i]; '%s' != '%s'", commands[i], expectedCommands[i])
			}
		}
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard)

		args := []string{"sub0", "sub00"}
		err := flags.Parse(args)
		if err != nil {
			log.Error(err)
		}

		expectedCommands := []string{"main", "Sub0", "Sub00"}
		subcommands := flags.GetSubcommands()
		commands := subcommands[len(subcommands)-1].GetParentCommands()
		for i := 0; i < len(expectedCommands); i++ {
			if commands[i].Name != expectedCommands[i] {
				t.Errorf("commands[i].Name != expectedCommands[i]; '%s' != '%s'", commands[i].Name, expectedCommands[i])
			}
		}

	}
}

func TestParseFlagArgs(t *testing.T) {
	ft := &FlagsTemplate{
		Name: saultcommon.MakeRandomString(),
		Flags: []FlagTemplate{
			FlagTemplate{
				Name:  "lower",
				Value: "l",
			},
			FlagTemplate{
				Name:  "upper",
				Value: "u",
			},
		},
	}

	{
		args := []string{
			"findme",
			"-lower", "L",
			"-upper", "U",
		}

		fs := NewFlags(ft, nil)
		err := fs.Parse(args)
		if err != nil {
			t.Error(err)
		}

		if fs.Values["lower"].(string) != "l" || fs.Values["upper"].(string) != "u" {
			t.Errorf("flag parsed.")
		}

		if len(fs.Args()) == 3 {
			t.Errorf("flag parsed.")
		}
	}

	{
		args := []string{
			"-lower", "L",
			"-upper", "U",
			"findme",
		}

		fs := NewFlags(ft, nil)
		err := fs.Parse(args)
		if err != nil {
			t.Error(err)
		}

		if fs.Values["lower"].(string) != "L" || fs.Values["upper"].(string) != "U" {
			t.Errorf("flag not parsed.")
		}

		if len(fs.Args()) != 1 || fs.Args()[0] != "findme" {
			t.Errorf("flag not parsed.")
		}
	}

	{
		// positioned
		args := []string{
			"findme",
			"-lower", "L",
			"-upper", "U",
		}

		fs := NewFlags(ft, nil)
		err := fs.ParsePositioned(args)
		if err != nil {
			t.Error(err)
		}

		if fs.Values["lower"].(string) != "L" || fs.Values["upper"].(string) != "U" {
			t.Errorf("flag not parsed.")
		}

		if len(fs.Args()) == 3 {
			t.Errorf("flag not parsed.")
		}
	}

}
