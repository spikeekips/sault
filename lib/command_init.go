package sault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var initOptionsTemplate = OptionsTemplate{
	Name:  "init",
	Help:  "init sault",
	Usage: "[flags] <admin user name> <publicKeyFile>",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:         "ConfigDir",
			Help:         "directory for sault files",
			DefaultValue: "",
		},
	},
	ParseFunc:   parseInitOptions,
	Description: descriptionInit,
}

var gettingStartedTemplate = `
Kom igång~

Successfully new admin added:
{{ .line }}
{{ .userAdded | escape }}
{{ .line }}

If sault was successfully initialized without error, start to run sault server:
{{ "$ sault server" | magenta }}

You can check the simple help message in every commands with '{{ "-h" | yellow }}' flag like:
{{ "$ sault server -h" | magenta }}
{{ "$ sault init -h" | magenta }}

and visit the sault project page, https://github.com/spikeekips/sault .

Lycka till~
`

func parseInitOptions(op *Options, args []string) error {
	commandArgs := op.FlagSet.Args()
	if len(commandArgs) != 2 {
		return fmt.Errorf("wrong usage")
	}

	{
		configDir := *op.Vars["ConfigDir"].(*string)
		if configDir == "" {
			configDir = defaultConfigDir
		} else {
			configDir, _ = filepath.Abs(filepath.Clean(configDir))
		}

		op.Extra["ConfigDir"] = configDir
	}

	adminName, publicKeyFile := commandArgs[0], commandArgs[1]
	{
		if !CheckUserName(adminName) {
			return fmt.Errorf("invalid adminName, '%s'", adminName)
		}

		op.Extra["AdminName"] = adminName
	}

	{
		publicKeyString, err := ioutil.ReadFile(publicKeyFile)
		if err != nil {
			return err
		}
		if _, err := ParsePublicKeyFromString(string(publicKeyString)); err != nil {
			return err
		}

		op.Extra["PublicKeyString"] = string(publicKeyString)
	}

	return nil
}

func checkConfigDir(directory string) (created bool, err error) {
	// directory exists or not
	var fi os.FileInfo
	if fi, err = os.Stat(directory); err != nil {
		if !os.IsNotExist(err) {
			return
		}

		if err = os.MkdirAll(directory, 0700); err != nil {
			err = nil
			return
		}
		err = nil
		created = true

		return
	}

	if !fi.IsDir() {
		err = fmt.Errorf("'%s' is not directory", directory)
		return
	}

	return
}

func createDefaultFiles(config *Config, configDir string) error {
	{
		path := BaseJoin(configDir, "./sault.conf")
		if err := config.Save(path); err != nil {
			return fmt.Errorf("failed to create default sault conf, '%s': %v", path, err)
		}

		log.Debugf("sault config file, '%v', created", path)
	}

	{
		privateKey, err := CreateRSAPrivateKey(2048)
		if err != nil {
			return err
		}

		pem, err := EncodePrivateKey(privateKey)
		if err != nil {
			return err
		}

		hostKeyFile := BaseJoin(configDir, "./host.key")
		f, err := os.OpenFile(hostKeyFile, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("failed to create host key, '%s': %v", hostKeyFile, err)
		}
		f.Write(pem)
		f.Close()

		log.Debugf("the host key for sault server, '%v', created", hostKeyFile)
	}
	{
		var clientKeyFile, clientPubFile string
		privateKey, err := CreateRSAPrivateKey(2048)
		if err != nil {
			return err
		}

		{
			pem, err := EncodePrivateKey(privateKey)
			if err != nil {
				return err
			}

			clientKeyFile = BaseJoin(configDir, "./client.key")
			f, err := os.OpenFile(clientKeyFile, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				return fmt.Errorf("failed to create client key, '%s': %v", clientKeyFile, err)
			}
			f.Write(pem)
			f.Close()
		}

		{
			clientPubFile = BaseJoin(configDir, "./client.pub")
			f, err := os.OpenFile(clientPubFile, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				return fmt.Errorf("failed to create client public key, '%s': %v", clientPubFile, err)
			}

			enc, err := EncodePublicKey(&privateKey.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to generate client public key from it's private key: %v", err)
			}

			f.Write(enc)
			f.Close()
		}

		log.Debugf("the client keys for target hosts, '%s', '%s', created", clientKeyFile, clientPubFile)
	}

	return nil
}

func addAdmin(registry *Registry, adminName, publicKeyString string) (UserRegistryData, error) {
	// add new admin with publicKey
	if _, err := registry.AddUser(adminName, publicKeyString); err != nil {
		return UserRegistryData{}, fmt.Errorf("failed to create admin: %v", err)
	}
	if err := registry.SetAdmin(adminName, true); err != nil {
		return UserRegistryData{}, fmt.Errorf("failed to create admin: %v", err)
	}

	if err := registry.Sync(); err != nil {
		return UserRegistryData{}, fmt.Errorf("failed to save registry: %v", err)
	}

	userData, err := registry.GetUserByUserName(adminName)
	if err != nil {
		return UserRegistryData{}, fmt.Errorf("failed to create admin: %v", err)
	}

	log.Debugf("new admin, %s was created", adminName)

	return userData, nil
}

func runInit(options OptionsValues, globalOptions OptionsValues) (err error) {
	log.Info("första gången...")

	// check whether ConfigDir is sault env or not
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	configDir := ov["ConfigDir"].(string)
	var created bool
	{
		if created, err = checkConfigDir(configDir); err != nil {
			log.Errorf("invalid ConfigDir: %v", err)
			return
		}

		if !created {
			var files []os.FileInfo
			files, err = ioutil.ReadDir(configDir)
			if err != nil {
				log.Errorf("invalid ConfigDir: %v", err)
				return
			}
			if len(files) > 1 {
				log.Errorf("ConfigDir, '%s' must be empty", configDir)
				return
			}
		}
	}

	if created {
		log.Debugf("sault config directory, '%s', created", configDir)
	} else {
		log.Debugf("sault config directory, '%s', found", configDir)
	}

	config := newDefaultConfig(configDir)

	if created {
		if err = createDefaultFiles(config, configDir); err != nil {
			log.Error(err)
			return
		}
	}

	var registry *Registry
	registry, err = getRegistryFromConfig(config, true)
	if err != nil {
		log.Error(err)

		return
	}

	adminName := ov["AdminName"].(string)
	publicKeyString := ov["PublicKeyString"].(string)

	var userData UserRegistryData
	userData, err = addAdmin(registry, adminName, publicKeyString)
	if err != nil {
		log.Error(err)
		return
	}
	userResponseData := newUserResponseData(registry, userData)

	log.Info("kom igång~")

	var gettingStarted string
	gettingStarted, err = ExecuteCommonTemplate(
		gettingStartedTemplate,
		map[string]interface{}{
			"userAdded": printUser(userResponseData),
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	CommandOut.Println(strings.TrimSpace(gettingStarted) + "\n")

	return
}
