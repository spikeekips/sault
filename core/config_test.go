package sault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type BasicConfigTestSuite struct {
	suite.Suite

	env string

	bind      string
	hostKey   string
	clientKey string
}

func (suite *BasicConfigTestSuite) SetupTest() {
	// create sault env
	env, _ := ioutil.TempDir("/tmp/", "sault-test")

	suite.bind = "192.168.99.101:22"
	suite.hostKey = "./host.key"
	suite.clientKey = "./client.key"

	configBody, _ := saultcommon.SimpleTemplating(`
[server]
bind = "{{ .bind }}"
host_key = "{{ .host_key }}"
client_key = "{{ .client_key }}"
	`,
		map[string]interface{}{
			"bind":       suite.bind,
			"host_key":   suite.hostKey,
			"client_key": suite.clientKey,
		},
	)
	ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

	suite.env = env
}

func (suite *BasicConfigTestSuite) TearDownTest() {
	os.RemoveAll(suite.env)
}

func (suite *BasicConfigTestSuite) TestLoadConfigs() {
	_, err := LoadConfigs([]string{suite.env})

	suite.Nil(err)
}

func (suite *BasicConfigTestSuite) TestCheckValues() {
	config, _ := LoadConfigs([]string{suite.env})

	suite.Equal(suite.bind, config.Server.Bind)
	suite.Equal(suite.hostKey, config.Server.HostKey)
	suite.Equal(suite.clientKey, config.Server.ClientKey)
}

func TestConfig(t *testing.T) {
	suite.Run(t, new(BasicConfigTestSuite))
}

func TestConfigEmptyEnvs(t *testing.T) {
	{
		_, err := LoadConfigs([]string{})
		assert.NotNil(t, err)
	}

	{
		var envs []string
		for i := 0; i < 3; i++ {
			env, _ := ioutil.TempDir("/tmp/", "sault-test")
			defer os.RemoveAll(env)

			envs = append(envs, env)
		}

		_, err := LoadConfigs(envs)
		assert.NotNil(t, err)
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
	assert.Nil(t, err)
	assert.Equal(t, envs[len(envs)-1], config.baseDirectory)
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

		assert.Nil(t, err)

		assert.Equal(t, "hostname1", config.Server.Bind)
		assert.Equal(t, "host.key1", config.Server.HostKey)
		assert.Equal(t, "client.key1", config.Server.ClientKey)
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
		assert.Nil(t, err)

		assert.Equal(t, "hostname0", config.Server.Bind)
		assert.Equal(t, "host.key0", config.Server.HostKey)
		assert.Equal(t, "client.key1", config.Server.ClientKey)
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
		assert.Nil(t, config.validateServerBind())
	}

	{
		// with valid bind
		configBody := `
[server]
bind = ":22"
	`
		ioutil.WriteFile(saultcommon.BaseJoin(env, "sault.conf"), []byte(configBody), 0600)

		config, _ := LoadConfigs([]string{env})
		assert.Nil(t, config.validateServerBind())
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
		assert.Nil(t, config.validateServerHostKey())
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
		assert.NotNil(t, config.validateServerHostKey())
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
		// with valid client key
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
		assert.Nil(t, config.validateServerClientKey())
	}

	{
		// with invalid client key
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
		assert.NotNil(t, config.validateServerClientKey())
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
		assert.Nil(t, config.Validate())
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
	assert.NotEqual(t, len(config.Bytes()), 0)
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

	assert.Nil(t, config.Validate())

	{
		cr := config.Registry.GetSources()
		tomlcr := cr[0].(*saultregistry.TomlConfigRegistry)
		assert.Equal(t, registryFile, tomlcr.Path)
	}

	{
		registry := saultregistry.NewRegistry()
		rs, err := saultregistry.LoadRegistrySourceFromConfig(
			config.Registry.Source[0].(map[string]interface{}),
			map[string]interface{}{
				"BaseDirectory": config.GetBaseDirectory(),
			},
		)

		assert.Nil(t, err)
		err = registry.AddSource(rs)
		assert.Nil(t, err)
	}
}
