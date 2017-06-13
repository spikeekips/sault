package saultcommands

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var ServerInitFlagsTemplate *saultflags.FlagsTemplate
var currentDirectory string
var currentUser *user.User

func init() {
	currentDirectory, _ = filepath.Abs("./")
	currentUser, _ = user.Current()

	description, _ := saultcommon.SimpleTemplating(`{{ "server init" | yellow }} initialize the sault server environment

After initializing sault server,

* the necessary environment files will be created
 - host.key, client.key: private key files 
 - sault.reg: registry file, it contains the user and hosts information
* the admin user will be also registered, the admin user can control the sault server in remote,
* the ssh service in this server will be automatically added to registry, and this host can be connected like:
 {{ "$ ssh -p" | magenta }} {{ .port | magenta }} {{ .account | magenta }}{{ "+" | magenta }}{{ .hostID | magenta }}{{ "@<hostname or ip>" | magenta }}
		`,
		map[string]interface{}{
			"port":    fmt.Sprintf("%d", sault.DefaultServerPort),
			"account": currentUser.Username,
			"hostID":  sault.DefaultSaultHostID,
		},
	)

	ServerInitFlagsTemplate = &saultflags.FlagsTemplate{
		ID:           "server init",
		Name:         "init",
		Help:         "initialize sault server environment",
		Usage:        "<admin user's publicKey file> [flags]",
		Description:  description,
		IsPositioned: true,
		Flags: []saultflags.FlagTemplate{
			saultflags.FlagTemplate{
				Name:  "Env",
				Help:  "This sault environment directory",
				Value: "./",
			},
			saultflags.FlagTemplate{
				Name:  "SkipThisHost",
				Help:  "skip to add the ssh service of this server to registry",
				Value: false,
			},
		},
		ParseFunc: parseServerInitCommandFlags,
	}

	sault.Commands[ServerInitFlagsTemplate.ID] = &ServerInitCommand{}
}

func parseServerInitCommandFlags(f *saultflags.Flags, args []string) (err error) {
	commandArgs := f.Args()
	if len(commandArgs) < 1 {
		err = fmt.Errorf("<admin user's publicKey file> must be given")
		return
	}

	publicKeyFile := commandArgs[0]

	var b []byte
	b, err = ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return
	}
	_, err = saultcommon.ParsePublicKey(b)
	if err != nil {
		return
	}
	f.Values["PublicKey"] = b

	envDir := f.Values["Env"].(string)
	if len(envDir) < 1 {
		f.Values["Env"] = currentDirectory
	}

	var fi os.FileInfo
	if fi, err = os.Stat(envDir); err == nil {
		if !fi.IsDir() {
			return &os.PathError{Op: "env", Path: envDir, Err: fmt.Errorf("is not directory")}
		}
	}

	return nil
}

type ServerInitCommand struct{}

func (c *ServerInitCommand) Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) (err error) {
	envDir := thisFlags.Values["Env"].(string)
	log.Debugf("initializing sault environment at %s", envDir)

	var created bool
	if _, err = os.Stat(envDir); err == nil {
		log.Debugf("env direcotry, '%s' found", envDir)
	} else {
		if !os.IsNotExist(err) {
			return
		}
		if err = os.MkdirAll(envDir, 0700); err != nil {
			log.Errorf("env direcotry, '%s' does not exist, but failed to create: %v", envDir, err)
			return
		}
		log.Debugf("env direcotry, '%s' does not exist, created", envDir)
		created = true
	}

	if !created { // check sault configuration files and
		var files []string
		files, err = filepath.Glob(fmt.Sprintf("%s/*%s", envDir, sault.ConfigFileExt))
		files = saultcommon.StringFilter(files, func(s string) bool {
			return !strings.HasPrefix(s, ".")
		})
		if err == nil && len(files) > 0 {
			log.Debugf("sault configuration files found: %v", files)
			err = fmt.Errorf("sault configuration files found, %s. clean up the directory first", files)
			return
		}
		log.Debugf("check whether sault conf files exist or not")

		files, err = filepath.Glob(fmt.Sprintf("%s/*%s", envDir, saultregistry.RegistryFileExt))
		files = saultcommon.StringFilter(files, func(s string) bool {
			return !strings.HasPrefix(s, ".")
		})
		if err == nil && len(files) > 0 {
			log.Debugf("sault registry files found: %v", files)
			err = fmt.Errorf("sault registry files found, %s. clean up the directory first", files)
			return
		}
		log.Debugf("check whether sault registry files exist or not")
	}

	config := sault.NewConfig()
	config.SetBaseDirectory(envDir)

	registryFile := fmt.Sprintf("./sault%s", saultregistry.RegistryFileExt)

	{
		// HostKey
		hostKey, _ := saultcommon.CreateRSAPrivateKey(2048)
		hostKeyFile := saultcommon.BaseJoin(envDir, sault.DefaultHostKey)

		b, _ := saultcommon.EncodePrivateKey(hostKey)
		if err = ioutil.WriteFile(hostKeyFile, b, 0600); err != nil {
			return
		}
		log.Debugf("HostKey was created, %s", hostKeyFile)
	}
	{
		// ClientKey
		clientKey, _ := saultcommon.CreateRSAPrivateKey(2048)
		clientKeyFile := saultcommon.BaseJoin(envDir, sault.DefaultClientKey)

		b, _ := saultcommon.EncodePrivateKey(clientKey)
		if err = ioutil.WriteFile(clientKeyFile, b, 0600); err != nil {
			return
		}
		log.Debugf("ClientKey was created, %s", clientKeyFile)
	}

	{
		// sault.reg
		if err = ioutil.WriteFile(saultcommon.BaseJoin(envDir, registryFile), []byte{}, saultregistry.RegistryFileMode); err != nil {
			return
		}
	}

	if err = config.Validate(); err != nil {
		return
	}

	log.Debugf(`dumped config:
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------`,
		string(config.Bytes()),
	)

	log.Debugf("admin user will be registered thru registry")

	publicKey := thisFlags.Values["PublicKey"].([]byte)
	log.Debugf("the user.ID for admin will be 'admin' by default and the publicKey will be given, '%s'", publicKey)

	cr := config.Registry.GetSources()
	registry := saultregistry.NewRegistry()
	if err = registry.AddSource(cr...); err != nil {
		return
	}
	if err = registry.Load(); err != nil {
		return
	}

	{
		var user saultregistry.UserRegistry
		user, err = registry.AddUser("admin", publicKey)
		if err != nil {
			return
		}
		user.IsAdmin = true
		user, err = registry.UpdateUser("admin", user)
	}

	{
		var user saultregistry.UserRegistry
		user, err = registry.GetUser("admin", nil, saultregistry.UserFilterNone)
		if err != nil || !user.IsAdmin {
			return err
		}
	}
	log.Debugf("admin user was registered thru registry")

	if !thisFlags.Values["SkipThisHost"].(bool) {
		hostName := "127.0.0.1"
		port := uint64(22)
		localAddress := fmt.Sprintf("%s:%d", hostName, port)
		found := checkSSHService(localAddress)
		if !found {
			log.Debugf("ssh service, '%s' not found", localAddress)
		} else {
			log.Debugf("ssh service, '%s' found", localAddress)
			currentUser, _ := user.Current()

			var host saultregistry.HostRegistry
			host, err = registry.AddHost(sault.DefaultSaultHostID, hostName, port, []string{currentUser.Username})
			if err != nil {
				log.Debugf("tried to register local ssh service, '%s', but failed: %v", localAddress, err)
				return
			}
			log.Debugf("local ssh service, '%s' registered: %s", localAddress, host)
		}
	}

	configFile := saultcommon.BaseJoin(config.GetBaseDirectory(), fmt.Sprintf("sault%s", sault.ConfigFileExt))
	log.Debugf("config will be saved at %s", configFile)

	if err = ioutil.WriteFile(configFile, config.Bytes(), 0600); err != nil {
		return
	}

	log.Debug("registry file will be saved")
	if err = registry.Save(); err != nil {
		return
	}

	log.Infof("sault environment was created at %s", envDir)

	return nil
}

func (c *ServerInitCommand) Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *sault.Config) error {
	return nil
}

func checkSSHService(address string) bool {
	clog := log.WithFields(logrus.Fields{
		"type":    "checkSSHService",
		"address": address,
	})

	{
		conn, err := net.DialTimeout("tcp", address, time.Second*2)
		conn.Close()
		if err != nil {
			clog.Debugf("port is dead")
			return false
		}

		clog.Debugf("port is live")
	}

	client := saultcommon.NewSSHClient("killme", address)
	client.AddAuthMethod(saultssh.Password(""))
	client.SetTimeout(time.Second * 2)

	err := client.Connect()
	client.Close()

	if err == nil {
		clog.Debugf("got nil error, interesting~")
		return true
	}

	if !strings.HasPrefix(err.Error(), "ssh: handshake failed: ") {
		clog.Debug(err)
		return false
	}
	errString := strings.TrimSpace(strings.TrimPrefix(err.Error(), "ssh: handshake failed: "))

	if errString == "EOF" { // not ssh service
		clog.Debug(err)
		return false
	}

	clog.Debugf("found ssh service")
	return true
}
