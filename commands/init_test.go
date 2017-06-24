package saultcommands

import "io/ioutil"

func init() {
	log.Out = ioutil.Discard // disable logging
}
