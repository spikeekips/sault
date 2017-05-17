package sault

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/naoina/toml"
)

// Log is main logger
var Log = logrus.New()
var log = Log

// CommandOut is the message output for command
var CommandOut *commandOut

var defaultTOML toml.Config

type commandOut struct {
}

func NewCommandOut() *commandOut {
	return &commandOut{}
}

func (c *commandOut) Println(v ...interface{}) {
	fmt.Fprint(os.Stdout, v...)
}

func (c *commandOut) Printf(format string, v ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format = format + "\n"
	}

	fmt.Fprintf(os.Stdout, format, v...)
}

func (c *commandOut) Errorf(format string, v ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format = format + "\n"
	}

	fmt.Fprintf(
		os.Stderr,
		"%s: %s",
		colorFunc(color.FgRed)("error"),
		fmt.Sprintf(format, v...),
	)
}

func (c *commandOut) Error(err error) {
	c.Errorf("%s", err)
}

func init() {
	log.Level, _ = ParseLogLevel(DefaultLogLevel)
	log.Out = DefaultLogOutputValue
	log.Formatter = DefaultLogFormatter

	defaultTOML = toml.DefaultConfig
	defaultTOML.MissingField = func(typ reflect.Type, key string) error {
		log.Errorf("field corresponding to `%s' is not defined in %v; but skipped", key, typ)

		return nil
	}

	CommandOut = NewCommandOut()
}
