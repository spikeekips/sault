package saultcommon

import (
	"io"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/Sirupsen/logrus"
	"github.com/naoina/toml"
)

var log *logrus.Logger

var termSize *TermSize

var DefaultTOML toml.Config
var terminalStateFD = 0

func init() {
	log = logrus.New()

	SetupLog(logrus.ErrorLevel, os.Stdout, nil)

	termSize = &TermSize{}
	syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(termSize)))

	DefaultTOML = toml.DefaultConfig
	DefaultTOML.MissingField = func(typ reflect.Type, key string) error {
		log.Warnf("field corresponding to `%s' is not defined in %v; but skipped", key, typ)

		return nil
	}

	// terminal.ReadPassword was hanged after interruped with 'control-c'
	oldState, _ := terminal.GetState(terminalStateFD)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			syscall.Syscall6(
				syscall.SYS_IOCTL,
				uintptr(terminalStateFD),
				syscall.TIOCSETA,
				uintptr(unsafe.Pointer(oldState)),
				0,
				0,
				0,
			)
			os.Exit(1)
		}
	}()
}

func SetupLog(level logrus.Level, out io.Writer, formatter logrus.Formatter) {
	log.Level = level

	if formatter == nil {
		formatter = &logrus.TextFormatter{
			DisableTimestamp: true,
		}
	}
	log.Formatter = formatter
	log.Out = out
}
