package sault

import (
	"reflect"

	"github.com/Sirupsen/logrus"
	"github.com/naoina/toml"
)

// Log is main logger
var Log = logrus.New()
var log = Log
var defaultTOML toml.Config

func init() {
	defaultTOML = toml.DefaultConfig
	defaultTOML.MissingField = func(typ reflect.Type, key string) error {
		log.Errorf("field corresponding to `%s' is not defined in %v; but skipped", key, typ)

		return nil
	}
}
