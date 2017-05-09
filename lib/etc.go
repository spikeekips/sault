package sault

import (
	log "github.com/Sirupsen/logrus"
)

var DefaultLogFormatter = &log.TextFormatter{
	FullTimestamp: true,
	TimestampFormat:
	/* time.RFC3339 */
	"2006-01-02T15:04:05.000000-07:00", // with microseconds
}
