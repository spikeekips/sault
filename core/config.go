package sault

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/naoina/toml"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

// Config contains configurations
type Config struct {
	Server   configServer
	Registry configRegistry

	baseDirectory string
}

// NewConfig makes config
func NewConfig() *Config {
	c := &Config{}

	// set default
	c.Server.Bind = defaultServerBind
	c.Server.SaultServerName = DefaultSaultServerName
	c.Server.HostKey = DefaultHostKey
	c.Server.ClientKey = DefaultClientKey

	registryFile := fmt.Sprintf("./sault%s", saultregistry.RegistryFileExt)
	c.Registry.Source = []interface{}{
		map[string]interface{}{"type": "toml", "path": registryFile},
	}

	return c
}

type configServer struct {
	// Bind, sault server bind address, '<hostname or ip>:<port>'
	Bind string

	SaultServerName string

	// HostKey is the ssh host key path
	HostKey       string
	hostKeySigner saultssh.Signer

	// ClientKey is the ssh client key path
	ClientKey       string
	clientKey       []byte
	clientKeySigner saultssh.Signer
}

type configRegistry struct {
	Source   []interface{}
	source   []saultregistry.RegistrySource
	registry *saultregistry.Registry
}

func (c configRegistry) GetSources() []saultregistry.RegistrySource {
	return c.source
}

// LoadConfigs loads configs
func LoadConfigs(envDirs []string) (config *Config, err error) {
	if len(envDirs) < 1 {
		err = fmt.Errorf("envDirs is empty")
		return
	}

	config = NewConfig()

	var configFiles []string
	for _, d := range envDirs {
		var fi os.FileInfo
		if fi, err = os.Stat(d); os.IsNotExist(err) {
			log.Debugf("env directory, '%s' does not exists; skipped", d)
			continue
		} else if !fi.IsDir() {
			log.Debugf("env directory, '%s' is not directory; skipped", d)
			continue
		}

		var files []string
		files, err = filepath.Glob(fmt.Sprintf("%s/*%s", d, ConfigFileExt))
		if err != nil {
			log.Debugf(
				"no '%s' found in envDirs, %v", ConfigFileExt, d)
			continue
		}
		for _, f := range files {
			if strings.HasPrefix(filepath.Base(f), ".") {
				continue
			}

			configFile := saultcommon.BaseJoin(d, f)
			if fi, err = os.Stat(configFile); os.IsNotExist(err) {
				log.Debugf("config file, '%s' does not exists; skipped", configFile)
				continue
			}
			configFiles = append(configFiles, configFile)
		}
	}

	if len(configFiles) < 1 {
		err = fmt.Errorf(
			"no '%s' found in envDirs, %v", ConfigFileExt, envDirs)
		return
	}

	for _, configFile := range configFiles {
		log.Debugf("trying to load config file, '%s'", configFile)
		config, err = loadConfigFromFile(configFile, config)
		if err != nil {
			err = fmt.Errorf("configFile, '%s' has problem: %v", err)
			return
		}
	}

	config.baseDirectory, _ = filepath.Abs(filepath.Dir(filepath.Clean(
		configFiles[len(configFiles)-1],
	)))

	return
}

func loadConfigFromFile(configFile string, config *Config) (*Config, error) {
	f, err := os.Open(configFile)
	if err != nil {
		return config, err
	}

	if err = saultcommon.DefaultTOML.NewDecoder(f).Decode(config); err != nil {
		return config, err
	}

	return config, nil
}

// GetBaseDirectory returns base directory
func (c *Config) GetBaseDirectory() string {
	return c.baseDirectory
}

// SetBaseDirectory set the base directory
func (c *Config) SetBaseDirectory(p string) {
	c.baseDirectory = p
}

// Bytes makes the config to []byte
func (c *Config) Bytes() []byte {
	var b bytes.Buffer
	toml.NewEncoder(&b).Encode(c)
	return b.Bytes()
}

// GetHostKeySigner returns signer of host key
func (c configServer) GetHostKeySigner() saultssh.Signer {
	return c.hostKeySigner
}

// GetClientKeySigner returns signer of internal client key
func (c configServer) GetClientKeySigner() saultssh.Signer {
	return c.clientKeySigner
}

// GetClientKey returns []byte of client key
func (c configServer) GetClientKey() []byte {
	return c.clientKey
}

// Validate validates config
func (c *Config) Validate() (err error) {
	funcs := [](func() error){
		c.validateServerBind,
		c.validateServerSaultServerName,
		c.validateServerHostKey,
		c.validateServerClientKey,
		c.validateRegistry,
	}

	for _, f := range funcs {
		if err = f(); err != nil {
			return
		}
	}

	return nil
}

func (c *Config) validateServerBind() (err error) {
	if len(c.Server.Bind) < 1 {
		c.Server.Bind = defaultServerBind
		return
	}

	_, _, err = saultcommon.SplitHostPort(c.Server.Bind, DefaultServerPort)
	if err != nil {
		return
	}

	return nil
}

func (c *Config) validateServerSaultServerName() (err error) {
	c.Server.SaultServerName = strings.TrimSpace(c.Server.SaultServerName)

	if len(c.Server.SaultServerName) < 1 {
		c.Server.SaultServerName = DefaultSaultServerName
		return
	}

	return
}

func (c *Config) validateServerHostKey() (err error) {
	if len(c.Server.HostKey) < 1 {
		c.Server.HostKey = saultcommon.BaseJoin(c.baseDirectory, DefaultHostKey)
	}

	s, err := ioutil.ReadFile(saultcommon.BaseJoin(c.baseDirectory, c.Server.HostKey))
	if err != nil {
		return fmt.Errorf("host_key, '%s' does not exist: %v", c.Server.HostKey, err)
	}

	c.Server.hostKeySigner, err = saultcommon.GetSignerFromPrivateKey(s)
	if err != nil {
		err = fmt.Errorf("invalid host_key, '%s': %v", c.Server.HostKey, err)
		return
	}

	return
}

func (c *Config) validateServerClientKey() (err error) {
	if len(c.Server.ClientKey) < 1 {
		c.Server.ClientKey = saultcommon.BaseJoin(c.baseDirectory, DefaultClientKey)
	}

	s, err := ioutil.ReadFile(saultcommon.BaseJoin(c.baseDirectory, c.Server.ClientKey))
	if err != nil {
		return fmt.Errorf("client_key, '%s' does not exist: %v", c.Server.ClientKey, err)
	}

	c.Server.clientKey = s

	c.Server.clientKeySigner, err = saultcommon.GetSignerFromPrivateKey(s)
	if err != nil {
		err = fmt.Errorf("invalid client_key, '%s': %v", c.Server.ClientKey, err)
		return
	}

	return
}

func (c *Config) validateRegistry() (err error) {
	if len(c.Registry.Source) < 1 {
		return fmt.Errorf("empty registry")
	}

	c.Registry.source = []saultregistry.RegistrySource{}

	for _, s := range c.Registry.Source {
		var cs saultregistry.RegistrySource
		cs, err = saultregistry.LoadRegistrySourceFromConfig(
			s.(map[string]interface{}),
			map[string]interface{}{
				"BaseDirectory": c.GetBaseDirectory(),
			},
		)
		if err != nil {
			return
		}
		if err = cs.Validate(); err != nil {
			return
		}
		c.Registry.source = append(c.Registry.source, cs)
	}

	return
}
