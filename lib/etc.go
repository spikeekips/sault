package sault

import (
	"os"

	"github.com/Sirupsen/logrus"
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
