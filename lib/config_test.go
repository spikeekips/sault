package sault

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var BaseDirectory = "/tmp/"

func TestLoadConfigFile(t *testing.T) {
	configTOML := `
[server]
host_key_path = "./host.key"
global_client_key_path = "./client.key"
	`
	configFile, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(configFile.Name())

	configFile.Write([]byte(configTOML))

	config, err := loadConfig(map[string]interface{}{
		"BaseDirectory": BaseDirectory,
		"Configs":       []string{configFile.Name()},
	})
	if err != nil {
		t.Error(err)
	}

	// load it again
	newConfigFile, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(newConfigFile.Name())

	newConfigFile.Write([]byte(config.String()))

	newConfig, err := loadConfig(map[string]interface{}{
		"BaseDirectory": BaseDirectory,
		"Configs":       []string{newConfigFile.Name()},
	})
	if err != nil {
		t.Error(err)
	}
	if newConfig.Server.HostKeyPath != config.Server.HostKeyPath {
		t.Errorf("newConfig.Server.HostKeyPath != config.Server.HostKeyPath: `%s` != `%s`", newConfig.Server.HostKeyPath, config.Server.HostKeyPath)
	}
	if newConfig.Server.GlobalClientKeyPath != config.Server.GlobalClientKeyPath {
		t.Errorf("newConfig.Server.GlobalClientKeyPath != config.Server.GlobalClientKeyPath: `%s` != `%s`", newConfig.Server.GlobalClientKeyPath, config.Server.GlobalClientKeyPath)
	}
}

func TestLoadMultipleConfigFile(t *testing.T) {
	configTOML0 := `
[server]
host_key_path = "./host0.key"
global_client_key_path = "./client0.key"
	`
	lastHostKeyPath := "./host1.key"
	lastGlobalClientKeyPath := "./client1.key"

	templateConfigTOML1, _ := template.New("t").Parse(`
[server]
host_key_path = "{{.lastHostKeyPath}}"
global_client_key_path = "{{.lastGlobalClientKeyPath}}"
	`)
	bw := bytes.NewBuffer([]byte{})
	templateConfigTOML1.Execute(bw, map[string]interface{}{
		"lastHostKeyPath":         lastHostKeyPath,
		"lastGlobalClientKeyPath": lastGlobalClientKeyPath,
	})

	configFile0, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(configFile0.Name())
	configFile0.Write([]byte(configTOML0))

	configFile1, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(configFile1.Name())
	configFile1.Write([]byte(bw.String()))

	config, err := loadConfig(map[string]interface{}{
		"BaseDirectory": BaseDirectory,
		"Configs": []string{
			configFile0.Name(),
			configFile1.Name(),
		},
	})
	if err != nil {
		t.Error(err)
	}

	if config.Server.HostKeyPath != lastHostKeyPath {
		t.Errorf("config.Server.HostKeyPath != lastHostKeyPath: `%s` != `%s`", config.Server.HostKeyPath, lastHostKeyPath)
	}
	if config.Server.GlobalClientKeyPath != lastGlobalClientKeyPath {
		t.Errorf("config.Server.GlobalClientKeyPath != lastGlobalClientKeyPath: `%s` != `%s`", config.Server.GlobalClientKeyPath, lastGlobalClientKeyPath)
	}
}

func TestConfigToJSON(t *testing.T) {
	configTOML := `
[server]
host_key_path = "./host.key"
global_client_key_path = "./client.key"
	`
	configFile, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(configFile.Name())

	configFile.Write([]byte(configTOML))

	config, _ := loadConfig(map[string]interface{}{
		"BaseDirectory": BaseDirectory,
		"Configs":       []string{configFile.Name()},
	})

	bw := bytes.NewBuffer([]byte{})
	templateConfigJSON, _ := template.New("t").Parse(`
{
  "Server": {
    "Bind": ":2222",
    "HostKeyPath": "./host.key",
    "GlobalClientKeyPath": "./client.key",
    "ServerName": "sault",
    "AllowUserCanUpdate": true
  },
  "Log": {
    "Format": "text",
    "Level": "error",
    "Output": "stdout"
  },
  "Registry": {
    "Type": "toml",
    "Source": {
      "File": {
        "Path": "{{.BaseDirectory}}registry.toml"
      }
    }
  }
}
	`)
	templateConfigJSON.Execute(bw, map[string]interface{}{
		"BaseDirectory": BaseDirectory,
	})

	configJSON := strings.TrimSpace(bw.String())
	if config.ToJSON() != configJSON {
		t.Errorf("config.ToJSON() != strings.TrimSpace(configJSON): `%s` != `%s`", config.ToJSON(), configJSON)
	}
}
