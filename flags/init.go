package saultflags

import (
	"io"
	"os"

	"github.com/Sirupsen/logrus"
)

var log *logrus.Logger

func init() {
	log = logrus.New()

	SetupLog(logrus.ErrorLevel, os.Stdout, nil)
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
