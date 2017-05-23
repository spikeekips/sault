package sault

import (
	"fmt"
	"io/ioutil"
	"os"
)

type configTOMLRegistry struct {
	Path string
}

func (c configTOMLRegistry) GetType() string {
	return "toml"
}

func (c configTOMLRegistry) Validate(globalConfig *Config) (err error) {
	path := BaseJoin(globalConfig.baseDirectory, c.Path)

	var fi os.FileInfo
	if fi, err = os.Stat(path); os.IsNotExist(err) {
		return
	}

	if fi.Mode() != registryFileMode {
		err = fmt.Errorf("registry file must have the perm, %04o", registryFileMode)
		return
	}

	globalConfig.Registry.Source.Toml.Path = path
	err = nil
	return
}

type tomlRegistry struct {
	Path string
	Data *registryData
}

func newTOMLRegistry(config configTOMLRegistry, initialize bool) (
	r *tomlRegistry,
	err error,
) {
	r = &tomlRegistry{Path: config.Path}

	if initialize {
		var f *os.File
		f, err = os.OpenFile(config.Path, os.O_RDWR|os.O_CREATE, registryFileMode)
		if err != nil {
			return
		}
		f.Close()
		return
	}

	var fi os.FileInfo
	if fi, err = os.Stat(config.Path); os.IsNotExist(err) {
		return
	} else if fi.Mode() != registryFileMode {
		err = fmt.Errorf("registry file must have the perm, %04o", registryFileMode)
		return
	}

	f, err := os.Open(config.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return r, nil
}

func (r *tomlRegistry) Bytes() ([]byte, error) {
	return ioutil.ReadFile(r.Path)
}

func (r *tomlRegistry) Save(content []byte) error {
	os.Remove(r.Path)
	err := ioutil.WriteFile(r.Path, content, registryFileMode)
	if err != nil {
		return err
	}

	return nil
}

func (r *tomlRegistry) GetType() string {
	return "toml"
}
