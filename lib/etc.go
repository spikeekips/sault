package sault

import (
	"github.com/Sirupsen/logrus"
)

// DefaultLogFormatter has detailed time format
var DefaultLogFormatter = &logrus.TextFormatter{
	FullTimestamp: true,
	TimestampFormat:
	/* time.RFC3339 */
	"2006-01-02T15:04:05.000000-07:00", // with microseconds
}
