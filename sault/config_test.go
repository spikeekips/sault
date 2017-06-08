package sault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
)

func TestBasicConfig(t *testing.T) {
	env, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env)

	bind := "192.168.99.101:22"
	host_key := "./host.key"
	client_key := "./client.key"

	configBody, _ := saultcommon.SimpleTemplating(`
[server]
bind = "{{ .bind }}"
host_key = "{{ .host_key }}"
client_key = "{{ .client_key }}"
	`,
		map[string]interface{}{
			"bind":       bind,
			"host_key":   host_key,
			"client_key": client_key,
		},
	)
	ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

	config, err := LoadConfigs([]string{env})
	if err != nil {
		t.Error(err)
	}

	if config.Server.Bind != bind {
		t.Errorf("config.Server.Bind != bind: '%s' != '%s'", config.Server.Bind, bind)
	}
	if config.Server.HostKey != host_key {
		t.Errorf("config.Server.HostKey != host_key: '%s' != '%s'", config.Server.HostKey, host_key)
	}
	if config.Server.ClientKey != client_key {
		t.Errorf("config.Server.ClientKey != client_key: '%s' != '%s'", config.Server.ClientKey, client_key)
	}
}

func TestConfigEmptyEnvs(t *testing.T) {
	{
		_, err := LoadConfigs([]string{})
		if err == nil {
			t.Errorf("error must be occured with empty envs")
		}
	}

	{
		var envs []string
		for i := 0; i < 3; i++ {
			env, _ := ioutil.TempDir("/tmp/", "sault-test")
			defer os.RemoveAll(env)

			envs = append(envs, env)
		}

		_, err := LoadConfigs(envs)
		if err == nil {
			t.Errorf("error must be occured with empty envs")
		}
	}
}

func TestConfigBaseDirectory(t *testing.T) {
	var envs []string

	for i := 0; i < 3; i++ {
		env, _ := ioutil.TempDir("/tmp/", "sault-test")
		defer os.RemoveAll(env)

		envs = append(envs, env)

		configBody := `
[server]
bind = "hostname"
host_key = "host.key"
client_key = "client.key"
		`
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)
	}

	config, err := LoadConfigs(envs)
	if err != nil {
		t.Error(err)
	}
	if config.baseDirectory != envs[len(envs)-1] {
		t.Errorf("config.baseDirectory != envs[len(envs) -1]; '%s' != '%s'", config.baseDirectory, envs[len(envs)-1])
	}
}

func TestConfigOverriding(t *testing.T) {
	env0, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env0)

	configBody0 := `
[server]
bind = "hostname0"
host_key = "host.key0"
client_key = "client.key0"
		`
	ioutil.WriteFile(saultcommon.BaseJoin(env0, "sault.conf"), []byte(configBody0), 0600)

	env1, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env1)

	configBody1 := `
[server]
bind = "hostname1"
host_key = "host.key1"
client_key = "client.key1"
		`
	ioutil.WriteFile(saultcommon.BaseJoin(env1, "sault.conf"), []byte(configBody1), 0600)

	{
		config, err := LoadConfigs([]string{env0, env1})
		if err != nil {
			t.Error(err)
		}

		if config.Server.Bind != "hostname1" {
			t.Errorf("config.Server.Bind != 'hostname1'; '%s'", config.Server.Bind)
		}
		if config.Server.HostKey != "host.key1" {
			t.Errorf("config.Server.HostKey != 'host.key1'; '%s'", config.Server.HostKey)
		}
		if config.Server.ClientKey != "client.key1" {
			t.Errorf("config.Server.ClientKey != 'client.key1'; '%s'", config.Server.ClientKey)
		}
	}
}

func TestConfigAddNewValue(t *testing.T) {
	env0, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env0)

	configBody0 := `
[server]
bind = "hostname0"
host_key = "host.key0"
		`
	ioutil.WriteFile(saultcommon.BaseJoin(env0, "sault.conf"), []byte(configBody0), 0600)

	env1, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env1)

	configBody1 := `
[server]
client_key = "client.key1"
		`
	ioutil.WriteFile(saultcommon.BaseJoin(env1, "sault.conf"), []byte(configBody1), 0600)

	{
		config, err := LoadConfigs([]string{env0, env1})
		if err != nil {
			t.Error(err)
		}

		if config.Server.Bind != "hostname0" {
			t.Errorf("config.Server.Bind != 'hostname0'; '%s'", config.Server.Bind)
		}
		if config.Server.HostKey != "host.key0" {
			t.Errorf("config.Server.HostKey != 'host.key0'; '%s'", config.Server.HostKey)
		}
		if config.Server.ClientKey != "client.key1" {
			t.Errorf("config.Server.ClientKey != 'client.key1'; '%s'", config.Server.ClientKey)
		}
	}
}

func TestConfigValidateBind(t *testing.T) {
	env, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env)

	{
		// with valid bind
		configBody := `
[server]
bind = "192.168.99.101:22"
	`
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.validateServerBind(); err != nil {
			t.Error(err)
		}
	}

	{
		// with valid bind
		configBody := `
[server]
bind = ":22"
	`
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.validateServerBind(); err != nil {
			t.Error(err)
		}
	}
}

func TestConfigValidateHostKey(t *testing.T) {
	env, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env)

	validHostKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx0yz3QRFewa8zuVkwsAZyC9UCnEfkCZJ6d2r8moGLraCkZpo
lrWi1R8EiY0+lA//ypMx1onMY6vrF2vCfZwzGPJWxug1NlBUIA/ucpY7Jo0bH0U/
bA6Mkv8TQxhzPcssx0Z9Gal1TKJ0VjmMLUw96R/5DRe1mvgUnD7TJFuvmHOSCQFg
Zv5NpTgT/VHXKpZ9URbXwmfIwcrr2qknJAkZEZOTob9e9Qj17xWkfRC59pHkE7yo
2F/F6DHMoDBJqcJORTUUeTLDgs0dvAGY8W/F4kM8GwTCuGxb4W7T/SO6RvOHgN8Q
Pak6vOR33uLhJOMcFeTyHAOvkP76LZ8nj0l82wIDAQABAoIBAEcM7UJp92s4p68K
0LUtTwOy+78NPTdirw8U2+v8KGAW6M2HwqmX74kTGcb/98NJQOOzPh1B2v/dll4v
KJMnUIAgRRd8SRwn3xXfGB75t/SycWzgfw/C0BLHpNJSsSLigAA6/PZdF1hOwjLL
KVIs0BWANIWaYj/xGUfqjdN0bFFooSPOxDE63ruclY/87tviGKhqV0SlEw691TYv
mr/a0n7DwWmif7sva1aWtldTbPahrrtyrsXJJz9ED+nqayRKvUmvYdnEEUqSkC9T
2x+YHduURea46dpWU6cqSDPY7KwZOxcc/aIjfm0OeKJ5zfkj8Ni95wru+BXXn+ER
42P4W8ECgYEA5APk+kLc8++uUy0/KGLn/96KP4VU0ePcRHqNbcbVUPr6TcCsHyjN
Oyn7AY/xccK+6yaV6JxM2KYBAVEdQQYLkXAOq9BvYpIUpU9zkwSQNeAD15iF3kqN
zhn7LPxXP4P+cFbjUi1ge0cqW5wiioT3CCiEhcXR0wA2u9kuK6xKULkCgYEA38KU
tQgiZxflV0/vogRfgX72qYSZCavTszV0YMsbH9vM8cIAhQcakV/LeQEWpQ059BfH
1raePrr9CstNLpvZFODutViJZ4eI4v5IZbIbrcV6gCHpWC/7aiyhMlpqNhJaYtnz
zSZnrzGQf718tOkYGnM9zSTSgJr0GLe8id6SqDMCgYEAv5d2I8NjHaXb+RAf7bON
9bXsvIswRl0MjI3doMxeGfmJsSOgfV4vdPNFcn6dBlX5TmXRuO78s15poc2ioyyN
M9vQuBYgQdc1eeJU3sgK1PoywEns0mga13+FSruOJFSoy4R25moyk+Osd+WuMG6h
lD1XfYBHWuDnHNjUruXKXCECgYA0amhbX+RvMfHPWjJQSaX1t8AgRadz1IRq3oK8
idd4xwxjNYbZoqhelYocdlzPnSGORGPTsEOxfiv4c1dJK8jWUzqX0H2feuheBCMB
b498TV481bTLq7HBVWMNYJCwyevSbCvoSq7PI1UuFz03Q8MZrxUzEQUeiy3S/Hd1
9GV2cQKBgQCPoBUoGh2RgvdKyfV+8hnXRcfgf5EEeBwN77xm4gyTIh2/1AYXMrEz
mcDVxXw9zpsWq/Xxs84OoArVL2mZj6wSnDyGjHCBpQiWRlFJ/j0soGmgLb3cZxGa
+Msh98PiCWJ/aDaQrUak1Y1z4OtJZR7OgC+kaXanm7RtKPL3bS+bdA==
-----END RSA PRIVATE KEY-----`

	{
		// with valid host key
		hostKeyFile, _ := ioutil.TempFile(env, "")
		hostKeyFile.Write([]byte(validHostKey))
		hostKeyFile.Close()

		configBody, _ := saultcommon.SimpleTemplating(`
[server]
host_key = "{{ . }}"
			`,
			hostKeyFile.Name(),
		)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.validateServerHostKey(); err != nil {
			t.Error(err)
		}
	}

	{
		// with invalid host key
		hostKeyFile, _ := ioutil.TempFile(env, "")
		hostKeyFile.Write([]byte(validHostKey[100:]))
		hostKeyFile.Close()

		configBody, _ := saultcommon.SimpleTemplating(`
[server]
host_key = "{{ . }}"
			`,
			hostKeyFile.Name(),
		)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.validateServerHostKey(); err == nil {
			t.Errorf("error must be occured with empty envs")
		}
	}
}

func TestConfigValidateClientKey(t *testing.T) {
	env, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env)

	validClientKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx0yz3QRFewa8zuVkwsAZyC9UCnEfkCZJ6d2r8moGLraCkZpo
lrWi1R8EiY0+lA//ypMx1onMY6vrF2vCfZwzGPJWxug1NlBUIA/ucpY7Jo0bH0U/
bA6Mkv8TQxhzPcssx0Z9Gal1TKJ0VjmMLUw96R/5DRe1mvgUnD7TJFuvmHOSCQFg
Zv5NpTgT/VHXKpZ9URbXwmfIwcrr2qknJAkZEZOTob9e9Qj17xWkfRC59pHkE7yo
2F/F6DHMoDBJqcJORTUUeTLDgs0dvAGY8W/F4kM8GwTCuGxb4W7T/SO6RvOHgN8Q
Pak6vOR33uLhJOMcFeTyHAOvkP76LZ8nj0l82wIDAQABAoIBAEcM7UJp92s4p68K
0LUtTwOy+78NPTdirw8U2+v8KGAW6M2HwqmX74kTGcb/98NJQOOzPh1B2v/dll4v
KJMnUIAgRRd8SRwn3xXfGB75t/SycWzgfw/C0BLHpNJSsSLigAA6/PZdF1hOwjLL
KVIs0BWANIWaYj/xGUfqjdN0bFFooSPOxDE63ruclY/87tviGKhqV0SlEw691TYv
mr/a0n7DwWmif7sva1aWtldTbPahrrtyrsXJJz9ED+nqayRKvUmvYdnEEUqSkC9T
2x+YHduURea46dpWU6cqSDPY7KwZOxcc/aIjfm0OeKJ5zfkj8Ni95wru+BXXn+ER
42P4W8ECgYEA5APk+kLc8++uUy0/KGLn/96KP4VU0ePcRHqNbcbVUPr6TcCsHyjN
Oyn7AY/xccK+6yaV6JxM2KYBAVEdQQYLkXAOq9BvYpIUpU9zkwSQNeAD15iF3kqN
zhn7LPxXP4P+cFbjUi1ge0cqW5wiioT3CCiEhcXR0wA2u9kuK6xKULkCgYEA38KU
tQgiZxflV0/vogRfgX72qYSZCavTszV0YMsbH9vM8cIAhQcakV/LeQEWpQ059BfH
1raePrr9CstNLpvZFODutViJZ4eI4v5IZbIbrcV6gCHpWC/7aiyhMlpqNhJaYtnz
zSZnrzGQf718tOkYGnM9zSTSgJr0GLe8id6SqDMCgYEAv5d2I8NjHaXb+RAf7bON
9bXsvIswRl0MjI3doMxeGfmJsSOgfV4vdPNFcn6dBlX5TmXRuO78s15poc2ioyyN
M9vQuBYgQdc1eeJU3sgK1PoywEns0mga13+FSruOJFSoy4R25moyk+Osd+WuMG6h
lD1XfYBHWuDnHNjUruXKXCECgYA0amhbX+RvMfHPWjJQSaX1t8AgRadz1IRq3oK8
idd4xwxjNYbZoqhelYocdlzPnSGORGPTsEOxfiv4c1dJK8jWUzqX0H2feuheBCMB
b498TV481bTLq7HBVWMNYJCwyevSbCvoSq7PI1UuFz03Q8MZrxUzEQUeiy3S/Hd1
9GV2cQKBgQCPoBUoGh2RgvdKyfV+8hnXRcfgf5EEeBwN77xm4gyTIh2/1AYXMrEz
mcDVxXw9zpsWq/Xxs84OoArVL2mZj6wSnDyGjHCBpQiWRlFJ/j0soGmgLb3cZxGa
+Msh98PiCWJ/aDaQrUak1Y1z4OtJZR7OgC+kaXanm7RtKPL3bS+bdA==
-----END RSA PRIVATE KEY-----`

	{
		// with valid host key
		clientKeyFile, _ := ioutil.TempFile(env, "")
		clientKeyFile.Write([]byte(validClientKey))
		clientKeyFile.Close()

		configBody, _ := saultcommon.SimpleTemplating(`
[server]
client_key = "{{ . }}"
			`,
			clientKeyFile.Name(),
		)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.validateServerClientKey(); err != nil {
			t.Error(err)
		}
	}

	{
		// with invalid host key
		clientKeyFile, _ := ioutil.TempFile(env, "")
		clientKeyFile.Write([]byte(validClientKey[100:]))
		clientKeyFile.Close()

		configBody, _ := saultcommon.SimpleTemplating(`
[server]
client_key = "{{ . }}"
			`,
			clientKeyFile.Name(),
		)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.validateServerClientKey(); err == nil {
			t.Errorf("error must be occured with empty envs")
		}
	}
}

func TestConfigValidate(t *testing.T) {
	env, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env)

	validKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx0yz3QRFewa8zuVkwsAZyC9UCnEfkCZJ6d2r8moGLraCkZpo
lrWi1R8EiY0+lA//ypMx1onMY6vrF2vCfZwzGPJWxug1NlBUIA/ucpY7Jo0bH0U/
bA6Mkv8TQxhzPcssx0Z9Gal1TKJ0VjmMLUw96R/5DRe1mvgUnD7TJFuvmHOSCQFg
Zv5NpTgT/VHXKpZ9URbXwmfIwcrr2qknJAkZEZOTob9e9Qj17xWkfRC59pHkE7yo
2F/F6DHMoDBJqcJORTUUeTLDgs0dvAGY8W/F4kM8GwTCuGxb4W7T/SO6RvOHgN8Q
Pak6vOR33uLhJOMcFeTyHAOvkP76LZ8nj0l82wIDAQABAoIBAEcM7UJp92s4p68K
0LUtTwOy+78NPTdirw8U2+v8KGAW6M2HwqmX74kTGcb/98NJQOOzPh1B2v/dll4v
KJMnUIAgRRd8SRwn3xXfGB75t/SycWzgfw/C0BLHpNJSsSLigAA6/PZdF1hOwjLL
KVIs0BWANIWaYj/xGUfqjdN0bFFooSPOxDE63ruclY/87tviGKhqV0SlEw691TYv
mr/a0n7DwWmif7sva1aWtldTbPahrrtyrsXJJz9ED+nqayRKvUmvYdnEEUqSkC9T
2x+YHduURea46dpWU6cqSDPY7KwZOxcc/aIjfm0OeKJ5zfkj8Ni95wru+BXXn+ER
42P4W8ECgYEA5APk+kLc8++uUy0/KGLn/96KP4VU0ePcRHqNbcbVUPr6TcCsHyjN
Oyn7AY/xccK+6yaV6JxM2KYBAVEdQQYLkXAOq9BvYpIUpU9zkwSQNeAD15iF3kqN
zhn7LPxXP4P+cFbjUi1ge0cqW5wiioT3CCiEhcXR0wA2u9kuK6xKULkCgYEA38KU
tQgiZxflV0/vogRfgX72qYSZCavTszV0YMsbH9vM8cIAhQcakV/LeQEWpQ059BfH
1raePrr9CstNLpvZFODutViJZ4eI4v5IZbIbrcV6gCHpWC/7aiyhMlpqNhJaYtnz
zSZnrzGQf718tOkYGnM9zSTSgJr0GLe8id6SqDMCgYEAv5d2I8NjHaXb+RAf7bON
9bXsvIswRl0MjI3doMxeGfmJsSOgfV4vdPNFcn6dBlX5TmXRuO78s15poc2ioyyN
M9vQuBYgQdc1eeJU3sgK1PoywEns0mga13+FSruOJFSoy4R25moyk+Osd+WuMG6h
lD1XfYBHWuDnHNjUruXKXCECgYA0amhbX+RvMfHPWjJQSaX1t8AgRadz1IRq3oK8
idd4xwxjNYbZoqhelYocdlzPnSGORGPTsEOxfiv4c1dJK8jWUzqX0H2feuheBCMB
b498TV481bTLq7HBVWMNYJCwyevSbCvoSq7PI1UuFz03Q8MZrxUzEQUeiy3S/Hd1
9GV2cQKBgQCPoBUoGh2RgvdKyfV+8hnXRcfgf5EEeBwN77xm4gyTIh2/1AYXMrEz
mcDVxXw9zpsWq/Xxs84OoArVL2mZj6wSnDyGjHCBpQiWRlFJ/j0soGmgLb3cZxGa
+Msh98PiCWJ/aDaQrUak1Y1z4OtJZR7OgC+kaXanm7RtKPL3bS+bdA==
-----END RSA PRIVATE KEY-----`

	{
		// with valid config
		clientKeyFile, _ := ioutil.TempFile(env, "")
		clientKeyFile.Write([]byte(validKey))
		clientKeyFile.Close()

		configBody, _ := saultcommon.SimpleTemplating(`
[server]
bind = ":2223"
host_key = "{{ . }}"
client_key = "{{ . }}"

[[registry.source]]
path = "./sample.reg"
type = "toml"
			`,
			clientKeyFile.Name(),
		)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sample.reg"), []byte{}, 0600)

		config, _ := LoadConfigs([]string{env})
		if err := config.Validate(); err != nil {
			t.Error(err)
		}
	}
}

func TestConfigBytes(t *testing.T) {
	var envs []string

	for i := 0; i < 3; i++ {
		env, _ := ioutil.TempDir("/tmp/", "sault-test")
		defer os.RemoveAll(env)

		envs = append(envs, env)

		configBody := fmt.Sprintf(`
[server]
bind = "hostname%d"
host_key = "host.key%d"
client_key = "client.key%d"
		`, i, i, i)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)
	}

	config, _ := LoadConfigs(envs)
	if len(config.Bytes()) == 0 {
		fmt.Errorf("Bytes() must not be empty")
	}
}

func TestConfigRegistry(t *testing.T) {
	env, _ := ioutil.TempDir("/tmp/", "sault-test")
	defer os.RemoveAll(env)

	validKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx0yz3QRFewa8zuVkwsAZyC9UCnEfkCZJ6d2r8moGLraCkZpo
lrWi1R8EiY0+lA//ypMx1onMY6vrF2vCfZwzGPJWxug1NlBUIA/ucpY7Jo0bH0U/
bA6Mkv8TQxhzPcssx0Z9Gal1TKJ0VjmMLUw96R/5DRe1mvgUnD7TJFuvmHOSCQFg
Zv5NpTgT/VHXKpZ9URbXwmfIwcrr2qknJAkZEZOTob9e9Qj17xWkfRC59pHkE7yo
2F/F6DHMoDBJqcJORTUUeTLDgs0dvAGY8W/F4kM8GwTCuGxb4W7T/SO6RvOHgN8Q
Pak6vOR33uLhJOMcFeTyHAOvkP76LZ8nj0l82wIDAQABAoIBAEcM7UJp92s4p68K
0LUtTwOy+78NPTdirw8U2+v8KGAW6M2HwqmX74kTGcb/98NJQOOzPh1B2v/dll4v
KJMnUIAgRRd8SRwn3xXfGB75t/SycWzgfw/C0BLHpNJSsSLigAA6/PZdF1hOwjLL
KVIs0BWANIWaYj/xGUfqjdN0bFFooSPOxDE63ruclY/87tviGKhqV0SlEw691TYv
mr/a0n7DwWmif7sva1aWtldTbPahrrtyrsXJJz9ED+nqayRKvUmvYdnEEUqSkC9T
2x+YHduURea46dpWU6cqSDPY7KwZOxcc/aIjfm0OeKJ5zfkj8Ni95wru+BXXn+ER
42P4W8ECgYEA5APk+kLc8++uUy0/KGLn/96KP4VU0ePcRHqNbcbVUPr6TcCsHyjN
Oyn7AY/xccK+6yaV6JxM2KYBAVEdQQYLkXAOq9BvYpIUpU9zkwSQNeAD15iF3kqN
zhn7LPxXP4P+cFbjUi1ge0cqW5wiioT3CCiEhcXR0wA2u9kuK6xKULkCgYEA38KU
tQgiZxflV0/vogRfgX72qYSZCavTszV0YMsbH9vM8cIAhQcakV/LeQEWpQ059BfH
1raePrr9CstNLpvZFODutViJZ4eI4v5IZbIbrcV6gCHpWC/7aiyhMlpqNhJaYtnz
zSZnrzGQf718tOkYGnM9zSTSgJr0GLe8id6SqDMCgYEAv5d2I8NjHaXb+RAf7bON
9bXsvIswRl0MjI3doMxeGfmJsSOgfV4vdPNFcn6dBlX5TmXRuO78s15poc2ioyyN
M9vQuBYgQdc1eeJU3sgK1PoywEns0mga13+FSruOJFSoy4R25moyk+Osd+WuMG6h
lD1XfYBHWuDnHNjUruXKXCECgYA0amhbX+RvMfHPWjJQSaX1t8AgRadz1IRq3oK8
idd4xwxjNYbZoqhelYocdlzPnSGORGPTsEOxfiv4c1dJK8jWUzqX0H2feuheBCMB
b498TV481bTLq7HBVWMNYJCwyevSbCvoSq7PI1UuFz03Q8MZrxUzEQUeiy3S/Hd1
9GV2cQKBgQCPoBUoGh2RgvdKyfV+8hnXRcfgf5EEeBwN77xm4gyTIh2/1AYXMrEz
mcDVxXw9zpsWq/Xxs84OoArVL2mZj6wSnDyGjHCBpQiWRlFJ/j0soGmgLb3cZxGa
+Msh98PiCWJ/aDaQrUak1Y1z4OtJZR7OgC+kaXanm7RtKPL3bS+bdA==
-----END RSA PRIVATE KEY-----`

	tmpRegistryFile, _ := ioutil.TempFile(env, "sault-test")
	os.Remove(tmpRegistryFile.Name())

	registryFile := saultcommon.BaseJoin(
		env,
		fmt.Sprintf("%s%s", filepath.Base(tmpRegistryFile.Name()), saultregistry.RegistryFileExt),
	)
	ioutil.WriteFile(
		registryFile,
		[]byte{},
		saultregistry.RegistryFileMode,
	)

	var config *Config
	{
		// with valid config
		clientKeyFile, _ := ioutil.TempFile(env, "")
		clientKeyFile.Write([]byte(validKey))
		clientKeyFile.Close()

		configBody, _ := saultcommon.SimpleTemplating(`
[server]
bind = ":2223"
host_key = "{{ .key }}"
client_key = "{{ .key }}"

[[registry.source]]
path = "{{ .registry }}"
type = "toml"
			`,
			map[string]interface{}{
				"key":      clientKeyFile.Name(),
				"registry": registryFile,
			},
		)
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)
		config, _ = LoadConfigs([]string{env})
	}

	ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), config.Bytes(), 0600)

	config, _ = LoadConfigs([]string{env})

	{
		err := config.Validate()
		if err != nil {
			t.Error(err)
		}
	}

	{
		cr := config.Registry.GetSources()
		tomlcr := cr[0].(*saultregistry.TomlConfigRegistry)
		if tomlcr.Path != registryFile {
			t.Errorf("tomlcr.Path != registryFile; '%s' != '%s'", tomlcr.Path, registryFile)
		}
	}

	{
		registry := saultregistry.NewRegistry()
		rs, err := saultregistry.LoadRegistrySourceFromConfig(
			config.Registry.Source[0].(map[string]interface{}),
			map[string]interface{}{
				"BaseDirectory": config.GetBaseDirectory(),
			},
		)
		if err != nil {
			t.Error(err)
		}
		err = registry.AddSource(rs)
		if err != nil {
			t.Error(err)
		}
	}
}
