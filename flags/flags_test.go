package saultflags

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/spikeekips/sault/common"
	"github.com/stretchr/testify/assert"
)

func TestNewFlags(t *testing.T) {
	{
		// NewFlags renders FlagsTemplate and it's field values
		mainFlags := &FlagsTemplate{
			Name:  saultcommon.MakeRandomString(),
			Flags: []FlagTemplate{},
		}

		flags := NewFlags(mainFlags, nil)
		assert.Equal(t, flags.Name, mainFlags.Name)
		assert.Equal(t, flags.Help, mainFlags.Help)
		assert.Equal(t, flags.Usage, mainFlags.Usage)
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

		assert.Nil(t, err)

		err = flags.Parse(args)
		assert.Nil(t, err)

		for name, value := range flagValues {
			parsedValue, ok := flags.Values[name]

			assert.True(t, ok)
			assert.Equal(t, value[1], parsedValue)
		}

		parsedValue, ok := flags.Values["FBool"]
		assert.True(t, ok)
		assert.Equal(t, true, parsedValue)
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

	assert.Nil(t, err)

	parsedValue, ok := flags.Values["Lower"]
	assert.True(t, ok)
	assert.Equal(t, lowercaseFlag(expectedValue), parsedValue.(lowercaseFlag))
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

	assert.Nil(t, err)

	{
		parsedValue, ok := flags.Values["Lower"]
		assert.True(t, ok)
		assert.Equal(t, lowercaseFlag(expectedValue), parsedValue.(lowercaseFlag))
	}

	{
		parsedValue, ok := flags.Values["Lower1"]
		assert.True(t, ok)
		assert.Equal(t, expectedValue1, parsedValue.(string))
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
		assert.Nil(t, flags.Parse(args))
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
		err = flags.Parse(args)
		assert.NotNil(t, err)
		assert.Error(t, &ErrorOccured{}, err)
		assert.Equal(t, err.(*ErrorOccured).Err, flag.ErrHelp)
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
		err = flags.Parse(args)
		assert.NotNil(t, err)
		assert.Error(t, &ErrorOccured{}, err)
		assert.Equal(t, err.(*ErrorOccured).Err, flag.ErrHelp)
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
		assert.Nil(t, flags.Parse(args))
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
		assert.Nil(t, flags.Parse(args))
	}

	assert.NotNil(t, flags.Subcommand)
	assert.Equal(t, subCommand.Name, flags.Subcommand.Name)
	assert.Equal(t, args[4], flags.Subcommand.Values["SubName"].(string))
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
		assert.NotNil(t, err)
		assert.Nil(t, flags.Subcommand)
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{"-name", "killme", "-help", "sub0", "-subName", "ok good"}
		err := flags.Parse(args)
		assert.NotNil(t, err)
		assert.Nil(t, flags.Subcommand)
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard) // mute help output
		args := []string{"-name", "killme", "sub0", "-subName", "ok good", "--help"}
		err := flags.Parse(args)
		assert.NotNil(t, err)
		assert.Nil(t, flags.Subcommand)
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

		assert.True(t, len(b.String()) > 0)
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
		assert.NotNil(t, err)
		assert.Error(t, &ErrorOccured{}, err)
		assert.Error(t, &MissingCommand{}, err.(*ErrorOccured).Err.(*MissingCommand))
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard)

		args := []string{"sub0", "sub00"}
		flags.Parse(args)

		expectedCommands := []string{"main", "Sub0", "Sub00"}
		var commands []string
		for _, f := range flags.GetSubcommands() {
			commands = append(commands, f.Name)
		}

		for i := 0; i < len(expectedCommands); i++ {
			assert.Equal(t, expectedCommands[i], commands[i])
		}
	}

	{
		flags := NewFlags(mainFlags, nil)
		flags.SetOutput(ioutil.Discard)

		args := []string{"sub0", "sub00"}
		flags.Parse(args)

		expectedCommands := []string{"main", "Sub0", "Sub00"}
		subcommands := flags.GetSubcommands()
		commands := subcommands[len(subcommands)-1].GetParentCommands()
		for i := 0; i < len(expectedCommands); i++ {
			assert.Equal(t, expectedCommands[i], commands[i].Name)
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
		fs.Parse(args)

		assert.Equal(t, "l", fs.Values["lower"].(string))
		assert.Equal(t, "u", fs.Values["upper"].(string))
		assert.Equal(t, 5, len(fs.Args()))
	}

	{
		args := []string{
			"-lower", "L",
			"-upper", "U",
			"findme",
		}

		fs := NewFlags(ft, nil)
		err := fs.Parse(args)
		assert.Nil(t, err)

		assert.Equal(t, "L", fs.Values["lower"].(string))
		assert.Equal(t, "U", fs.Values["upper"].(string))
		assert.Equal(t, 1, len(fs.Args()))
		assert.Equal(t, "findme", fs.Args()[0])
	}

	{
		// positioned
		args := []string{
			"findme",
			"-lower", "L",
			"-upper", "U",
		}

		fs := NewFlags(ft, nil)
		fs.IsPositioned = true
		err := fs.ParsePositioned(args)
		assert.Nil(t, err)

		assert.Equal(t, "L", fs.Values["lower"].(string))
		assert.Equal(t, "U", fs.Values["upper"].(string))
		assert.Equal(t, 1, len(fs.Args()))
	}
}
