package sault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spikeekips/sault/ssh"

	"github.com/naoina/toml"
)

var availableLogFormats = [2]string{
	"json",
	"text",
}

var availableLogLevel = [6]string{
	"debug",
	"info",
	"warn",
	"error",
	"fatal",
	"quiet",
}

var availableRegistryType = [1]string{
	"toml",
}

var defaultServerName = "sault"
var defaultServerPort = 2222
var defaultServerBind string

func init() {
	defaultServerBind = fmt.Sprintf(":%d", defaultServerPort)
}

type configServer struct {
	Bind                  string
	HostKeyPath           string
	hostKeySigner         saultSsh.Signer
	GlobalClientKeyPath   string
	globalClientKeySigner saultSsh.Signer
	ServerName            string
	AllowUserCanUpdate    bool
}

type configLog struct {
	Format string
	Level  string
	Output string // filepath, `stdout`(default), `stderr`
}

type configSourceRegistry interface {
	GetType() string
}

type configRegistry struct {
	Type   string
	Source struct {
		File configTOMLRegistry
	}
}

func (c configRegistry) GetSource() (configSourceRegistry, error) {
	switch t := c.Type; t {
	case "toml":
		return c.Source.File, nil
	default:
		return nil, fmt.Errorf("invalid source type, `%s`", t)
	}
}

type configTOMLRegistry struct {
	Path string
}

func (c configTOMLRegistry) GetType() string {
	return "toml"
}

// Config contains all available configurations
type Config struct {
	Server        configServer
	Log           configLog
	Registry      configRegistry
	baseDirectory string
}

func loadConfig(args map[string]interface{}) (*Config, error) {
	config := newConfig()
	config.baseDirectory, _ = filepath.Abs("./")
	config.setDefault()

	var configFile string
	for _, configFile = range args["Configs"].([]string) {
		b, _ := ioutil.ReadFile(configFile)
		log.Debugf(`config file, '%s' read:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`,
			configFile,
			strings.TrimSpace(string(b)),
		)

		if _, err := loadConfigFromFile(configFile, config); err != nil {
			return nil, err
		}
	}

	config.baseDirectory, _ = filepath.Abs(args["BaseDirectory"].(string))

	if logFormat, ok := args["LogFormat"]; ok && logFormat.(string) != "" {
		config.Log.Format = logFormat.(string)
	}
	if logLevel, ok := args["LogLevel"]; ok && logLevel.(string) != "" {
		config.Log.Level = logLevel.(string)
	}
	if logOutput, ok := args["LogOutput"]; ok && logOutput.(string) != "" {
		config.Log.Output = args["LogOutput"].(string)
	}

	config.fillEmpty()

	log.Debugf(`loaded config:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, strings.TrimSpace(config.String()))

	return config, nil
}

func (c *Config) setDefault() {
	c.Server.Bind = defaultServerBind
	c.Server.ServerName = defaultServerName
	c.Server.AllowUserCanUpdate = true

	c.Log.Level = defaultLogLevel
	c.Log.Output = defaultLogOutput
	c.Log.Format = defaultLogFormat
}

func (c *Config) fillEmpty() {
	if c.Server.Bind == "" {
		c.Server.Bind = defaultServerBind
	}
	if c.Server.ServerName == "" {
		c.Server.ServerName = defaultServerName
	}
	if c.Server.HostKeyPath == "" {
		c.Server.HostKeyPath = BaseJoin(c.baseDirectory, "./host.key")
	}
	if c.Server.GlobalClientKeyPath == "" {
		c.Server.GlobalClientKeyPath = BaseJoin(c.baseDirectory, "./client.key")
	}

	if c.Log.Level == "" {
		c.Log.Level = defaultLogLevel
	}
	if c.Log.Output == "" {
		c.Log.Output = defaultLogOutput
	}
	if c.Log.Format == "" {
		c.Log.Format = defaultLogFormat
	}

	if c.Registry.Type == "toml" && c.Registry.Source.File.Path == "" {
		c.Registry.Source.File.Path = BaseJoin(c.baseDirectory, "./registry.toml")
	}
}

func newConfig() *Config {
	config := Config{
		Registry: configRegistry{
			Type: "toml",
		},
	}

	return &config
}

func newDefaultConfig(basePath string) *Config {
	config := newConfig()
	config.baseDirectory = basePath
	config.setDefault()
	config.fillEmpty()

	return config
}

func loadConfigFromFile(filePath string, config *Config) (*Config, error) {
	if config == nil {
		config = &Config{}
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	if err := toml.NewDecoder(f).Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) validate() error {
	if err := c.validateHostKey(); err != nil {
		return err
	}
	if err := c.validateGlobalClientKeyPath(); err != nil {
		return err
	}
	if err := c.validateLogFormat(); err != nil {
		return err
	}
	if err := c.validateLogLevel(); err != nil {
		return err
	}
	if err := c.validateRegistry(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateLogFormat() error {
	for _, f := range availableLogFormats {
		if f == c.Log.Format {
			return nil
		}
	}

	return fmt.Errorf("invalid log format, `%s`", c.Log.Format)
}

func (c *Config) validateLogLevel() error {
	for _, f := range availableLogLevel {
		if f == c.Log.Level {
			return nil
		}
	}

	return fmt.Errorf("invalid log level, `%s`", c.Log.Level)
}

func (c *Config) validateHostKey() error {
	if c.Server.HostKeyPath == "" {
		return fmt.Errorf("`Server.HostKeyPath` is missing")
	}
	signer, err := GetPrivateKeySigner(c.Server.HostKeyPath)
	if err != nil {
		return err
	}

	c.Server.hostKeySigner = signer

	return nil
}

func (c *Config) validateGlobalClientKeyPath() error {
	if c.Server.GlobalClientKeyPath == "" {
		return fmt.Errorf("`Server.GlobalClientKeyPath` is missing")
	}
	signer, err := GetPrivateKeySigner(c.Server.GlobalClientKeyPath)
	if err != nil {
		return err
	}

	c.Server.globalClientKeySigner = signer

	return nil
}

func (c *Config) validateRegistry() error {
	found := false
	for _, f := range availableRegistryType {
		if f == c.Registry.Type {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("invalid registry type, `%s`", c.Registry.Type)
	}

	if c.Registry.Type != "toml" {
		return nil
	}
	config := c.Registry.Source.File
	if config.Path == "" {
		return fmt.Errorf("registry file, `%s` is missing", config.Path)
	}

	if fi, err := os.Stat(config.Path); os.IsNotExist(err) {
		return err
	} else if fmt.Sprintf("%04o", fi.Mode()) != "0600" {
		return fmt.Errorf("registry file must have the perm, 0600")
	}

	return nil
}

func (c *Config) String() string {
	bw := bytes.NewBuffer([]byte{})
	toml.NewEncoder(bw).Encode(c)

	return strings.TrimSpace(bw.String())
}

// ToJSON exports configuration to json string
func (c *Config) ToJSON() string {
	jsoned, _ := json.MarshalIndent(c, "", "  ")
	return string(jsoned)
}

// Save saves configuration to file as TOML format
func (c *Config) Save(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	f.Write([]byte(c.String()))

	return nil
}
