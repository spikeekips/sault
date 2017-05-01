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

	log "github.com/Sirupsen/logrus"
	"github.com/naoina/toml"
)

var AvailableLogFormats = [2]string{
	"json",
	"text",
}

var AvailableLogLevel = []string{
	"debug",
	"info",
	"warn",
	"error",
	"fatal",
	"quiet",
}

var availableRegistryType = []string{
	"file",
}

type ConfigServer struct {
	Bind                  string
	HostKeyPath           string
	hostKeySigner         ssh.Signer
	GlobalClientKeyPath   string
	globalClientKeySigner ssh.Signer
}

type ConfigLog struct {
	Format string
	Level  string
	Output string // filepath, `stdout`(default), `stderr`
}

type ConfigSourceRegistry interface {
	GetType() string
}

type ConfigRegistry struct {
	Type   string
	Source struct {
		File ConfigFileRegistry
	}
}

func (c ConfigRegistry) GetSource() (ConfigSourceRegistry, error) {
	switch t := c.Type; t {
	case "file":
		return c.Source.File, nil
	default:
		return nil, fmt.Errorf("invalid source type, `%s`", t)
	}
}

type ConfigFileRegistry struct {
	Path string
}

func (c ConfigFileRegistry) GetType() string {
	return "file"
}

type Config struct {
	Server        ConfigServer
	Log           ConfigLog
	Registry      ConfigRegistry
	baseDirectory string
}

func LoadConfig(args map[string]interface{}) (*Config, error) {
	config := NewConfig()

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

		if _, err := LoadConfigFromFile(configFile, config); err != nil {
			return nil, err
		}
		bw := bytes.NewBuffer([]byte{})
		toml.NewEncoder(bw).Encode(config)
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

	config.setDefault()

	log.Debugf(`loaded config:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`, strings.TrimSpace(config.String()))

	return config, nil
}

func (c *Config) setDefault() {
	if c.Server.Bind == "" {
		c.Server.Bind = ":2222"
	}
	if c.Server.HostKeyPath == "" {
		c.Server.HostKeyPath = BaseJoin(c.baseDirectory, "./host.key")
	}

	if c.Server.GlobalClientKeyPath == "" {
		c.Server.GlobalClientKeyPath = BaseJoin(c.baseDirectory, "./client.key")
	}

	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Output == "" {
		c.Log.Output = "stdout"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}

	if c.Registry.Type == "file" && c.Registry.Source.File.Path == "" {
		c.Registry.Source.File.Path = BaseJoin(c.baseDirectory, "./registry.toml")
	}
}

func NewConfig() *Config {
	config := Config{
		Registry: ConfigRegistry{
			Type: "file",
		},
	}

	return &config
}

func LoadConfigFromFile(filePath string, config *Config) (*Config, error) {
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

func (c *Config) Validate() error {
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
	for _, f := range AvailableLogFormats {
		if f == c.Log.Format {
			return nil
		}
	}

	return fmt.Errorf("invalid log format, `%s`", c.Log.Format)
}

func (c *Config) validateLogLevel() error {
	for _, f := range AvailableLogLevel {
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

	if c.Registry.Type != "file" {
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

func (c *Config) ToJSON() string {
	jsonedConfig, _ := json.MarshalIndent(c, "", "  ")
	return string(jsonedConfig)
}
