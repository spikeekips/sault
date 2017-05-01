package sault

import (
	"flag"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
)

type FlagConfigDirs []string

func (f *FlagConfigDirs) String() string {
	return "configs"
}

func (f *FlagConfigDirs) Set(v string) error {
	*f = append(*f, v)
	return nil
}

type ServerFlags struct {
	Name        string
	Usage       string
	Description string
	FlagSet     *flag.FlagSet

	ConfigDir FlagConfigDirs `flag:"" help:"This directory contains the configuration files (default: \"./\")"`
	Extra     map[string]interface{}
}

func (f *ServerFlags) Parse(args []string) error {
	p := []string(f.ConfigDir)
	if len(p) < 1 {
		f.ConfigDir = append(f.ConfigDir, "./")
	}

	f.Extra = map[string]interface{}{}

	// log config files
	var err error
	var configFiles []string
	var baseDirectory string
	for _, configDir := range []string(f.ConfigDir) {
		log.Debugf("trying to get config files from `%s`", configDir)

		isTolerated, d := ParseTolerateFilePath(configDir)
		d, err = filepath.Abs(d)
		if err != nil {
			log.Errorf("failed to traverse the config directory, `%s`", configDir)
			continue
		}

		files, err := filepath.Glob(BaseJoin(d, "*.conf"))
		if err != nil {
			msg := "failed to load config files from `%s`: %v"
			if isTolerated {
				log.Errorf(msg, configDir, err)
			} else {
				log.Fatalf(msg, configDir, err)
			}
		}

		// prevent to load hidden files.
		files = StringFilter(
			files,
			func(s string) bool {
				return string([]rune(filepath.Base(s))[0]) != "."
			},
		)
		configFiles = append(configFiles, files...)

		// last config directory will be `baseDirectory`
		baseDirectory = d
	}

	f.Extra["BaseDirectory"] = baseDirectory
	f.Extra["Configs"] = configFiles

	return nil
	//return errors.New("findme")
}

func (f *ServerFlags) ToMap() map[string]interface{} {
	m := toMap(f, true)

	for k, v := range f.Extra {
		m[k] = v
	}

	return m
}

/*
type UserFlags struct {
	Name        string
	Usage       string
	Description string
	FlagSet     *flag.FlagSet

	BB string `flag:"" help:"this is bb" default:"bb"`
	BC int    `flag:"" help:"this is bc" default:"200"`
}

func (f *UserFlags) Parse(args []string) error {
	return nil
}
*/
