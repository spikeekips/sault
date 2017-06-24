package saultregistry

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spikeekips/sault/common"
)

var RegistryFileMode os.FileMode = 0600
var RegistryFileExt = ".reg"

type TomlConfigRegistry struct {
	Type string // must be 'toml'
	Path string
}

func newTomlConfigRegistry(b []byte, config map[string]interface{}) (t *TomlConfigRegistry, err error) {
	t = &TomlConfigRegistry{}
	if err = saultcommon.DefaultTOML.NewDecoder(bytes.NewBuffer(b)).Decode(t); err != nil {
		return
	}
	if len(strings.TrimSpace(t.Path)) < 1 {
		err = fmt.Errorf("path is empty")
		return
	}

	t.Path = saultcommon.BaseJoin(config["BaseDirectory"].(string), t.Path)

	return
}

func (t TomlConfigRegistry) GetType() string {
	return "toml"
}

func (t TomlConfigRegistry) Bytes() (b []byte, err error) {
	b, err = ioutil.ReadFile(t.Path)
	if err != nil {
		return
	}

	return
}

func (t TomlConfigRegistry) Save(p []byte) (err error) {
	os.Remove(t.Path)
	err = ioutil.WriteFile(t.Path, p, RegistryFileMode)

	return
}

func (t TomlConfigRegistry) Validate() (err error) {
	if ext := filepath.Ext(t.Path); ext != RegistryFileExt {
		if len(ext) < 1 {
			err = fmt.Errorf("has empty extension")
		} else {
			err = fmt.Errorf("has wrong extension, %s", ext)
		}

		err = &os.PathError{
			Op:   "registry file",
			Path: t.Path,
			Err:  err,
		}
		return
	}

	var fi os.FileInfo
	if fi, err = os.Stat(t.Path); err != nil {
		if pathError, ok := err.(*os.PathError); ok {
			pathError.Op = "registry file"
			return pathError
		}
		return err
	}
	if fi.IsDir() {
		err = &os.PathError{
			Op:   "registry file",
			Path: t.Path,
			Err:  fmt.Errorf("is not file."),
		}
		return
	}
	if fi.Mode() != RegistryFileMode {
		err = &os.PathError{
			Op:   "registry file",
			Path: t.Path,
			Err:  fmt.Errorf("has wrong permission, %o; it must be %o", fi.Mode(), RegistryFileMode),
		}
		return
	}

	return nil
}
