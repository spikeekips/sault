package sault

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var BaseDirectory = "/tmp/"

func makeTestKeys() (string, string) {
	hostKey, _ := ioutil.TempFile("/tmp/", "sault-test")
	hostKey.Write([]byte(generatePrivateKey()))
	hostKey.Close()
	clientKey, _ := ioutil.TempFile("/tmp/", "sault-test")
	clientKey.Write([]byte(generatePrivateKey()))
	clientKey.Close()

	return hostKey.Name(), clientKey.Name()
}

func TestLoadConfigFile(t *testing.T) {
	hostKey, clientKey := makeTestKeys()
	defer os.Remove(hostKey)
	defer os.Remove(clientKey)

	configTOML := fmt.Sprintf(`
[server]
host_key_path = "%s"
global_client_key_path = "%s"
	`, hostKey, clientKey,
	)

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
		t.Errorf("newConfig.Server.HostKeyPath != config.Server.HostKeyPath: '%s' != '%s'", newConfig.Server.HostKeyPath, config.Server.HostKeyPath)
	}
	if newConfig.Server.GlobalClientKeyPath != config.Server.GlobalClientKeyPath {
		t.Errorf("newConfig.Server.GlobalClientKeyPath != config.Server.GlobalClientKeyPath: '%s' != '%s'", newConfig.Server.GlobalClientKeyPath, config.Server.GlobalClientKeyPath)
	}
}

func TestLoadMultipleConfigFile(t *testing.T) {
	configTOML0 := `
[server]
host_key_path = "./host0.key"
global_client_key_path = "./client0.key"
	`

	lastHostKeyPath, lastGlobalClientKeyPath := makeTestKeys()
	defer os.Remove(lastHostKeyPath)
	defer os.Remove(lastGlobalClientKeyPath)

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
		t.Errorf("config.Server.HostKeyPath != lastHostKeyPath: '%s' != '%s'", config.Server.HostKeyPath, lastHostKeyPath)
	}
	if config.Server.GlobalClientKeyPath != lastGlobalClientKeyPath {
		t.Errorf("config.Server.GlobalClientKeyPath != lastGlobalClientKeyPath: '%s' != '%s'", config.Server.GlobalClientKeyPath, lastGlobalClientKeyPath)
	}
}

func TestConfigToJSON(t *testing.T) {
	hostKey, clientKey := makeTestKeys()
	defer os.Remove(hostKey)
	defer os.Remove(clientKey)

	configTOML := fmt.Sprintf(`
[server]
host_key_path = "%s"
global_client_key_path = "%s"
	`, hostKey, clientKey)
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
    "Bind": "{{ .ServerBind }}",
    "HostKeyPath": "{{ .hostKey }}",
    "GlobalClientKeyPath": "{{ .clientKey }}",
    "ServerName": "sault",
    "AllowUserCanUpdate": true
  },
  "Log": {
    "Format": "text",
    "Level": "quiet",
    "Output": "stdout"
  },
  "Registry": {
    "Type": "toml",
    "Source": {
      "Toml": {
        "Path": "{{.BaseDirectory}}registry.toml"
      }
    }
  }
}
	`)
	templateConfigJSON.Execute(bw, map[string]interface{}{
		"ServerBind":    defaultServerBind,
		"BaseDirectory": BaseDirectory,
		"hostKey":       hostKey,
		"clientKey":     clientKey,
	})

	configJSON := strings.TrimSpace(bw.String())
	if config.ToJSON() != configJSON {
		t.Errorf("config.ToJSON() != strings.TrimSpace(configJSON): '%s' != '%s'", config.ToJSON(), configJSON)
	}
}
