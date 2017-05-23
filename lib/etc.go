package sault

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/naoina/toml"
)

// default log format
var DefaultLogFormat = "text"

// default log level
var DefaultLogLevel = "quiet"

// default log output
var DefaultLogOutput = "stdout"

// default log output value
var DefaultLogOutputValue = os.Stdout

// DefaultLogFormatter has detailed time format
var DefaultLogFormatter = &logrus.TextFormatter{
	FullTimestamp: true,
	TimestampFormat:
	/* time.RFC3339 */
	"2006-01-02T15:04:05.000000-07:00", // with microseconds
}

var maxAuthTries int = 3
var authMethosTries []string
var sshDirectory = "~/.ssh"
var authorizedKeyFile = "~/.ssh/authorized_keys"
var defaultConfigDir = "./"
var availableLogFormats = [2]string{
	"json",
	"text",
}

var availableLogLevel = [6]string{
	"debug",
	"info",
	"warn",
	"error",
	"fatal",
	"quiet",
}

var availableRegistryType = [2]string{
	"toml",
	"consul",
}

var defaultServerName = "sault"
var defaultServerPort uint64 = 2222
var defaultServerBind string

type clientType uint8

const (
	saultClient clientType = iota + 1
	nativeSSHClient
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

func (c *commandOut) Warnf(format string, v ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format = format + "\n"
	}

	fmt.Fprintf(
		os.Stdout,
		"%s: %s",
		colorFunc(color.FgYellow)("warning"),
		strings.TrimLeft(fmt.Sprintf(format, v...), " \n"),
	)
}

type activeFilter int

const (
	_                            = iota
	activeFilterAll activeFilter = 1 << (10 * iota)
	activeFilterActive
	activeFilterDeactivated
)

const envSSHAuthSock = "SSH_AUTH_SOCK"

func init() {
	authMethosTries = []string{
		"publicKey",
	}
	for i := 0; i < maxAuthTries; i++ {
		authMethosTries = append(authMethosTries, "password")
	}

	defaultConfigDir, _ = filepath.Abs(filepath.Clean(defaultConfigDir))

	defaultServerBind = fmt.Sprintf(":%d", defaultServerPort)

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
