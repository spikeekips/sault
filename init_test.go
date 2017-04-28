package sault

import (
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
)

func init() {
	log.SetOutput(ioutil.Discard) // disable logging
}
