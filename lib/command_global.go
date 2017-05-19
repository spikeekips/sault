package sault

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ScaleFT/sshkeys"
	"github.com/spikeekips/sault/ssh"
)

// GlobalOptionsTemplate has global flags
var globalOptionsTemplate = OptionsTemplate{
	Name:  os.Args[0],
	Usage: "[flags] command",
	Description: `
==================================================
{{ " sault" | cyan }}: The authentication proxy for SSH servers
==================================================

"sault" acts like the reverse proxy, so the native openssh client and server work transparently.

To deploy the sault in your system, follow these steps.
1. In the server side, download and install sault.
  Get the latest pre-built binary at https://github.com/spikeekips/sault/releases , and extract it in $PATH.
2. Create sault default directory, like {{ "~/.sault" | yellow }}:
  {{ "$ mkdir ~./sault" | magenta }}
3. Initialize sault environment:
  {{ "$ cd ~./sault" | magenta }}
  {{ "$ sault init admin ~/.ssh/admin.pub" | magenta }}
4. Run sault server:
  {{ "$ cd ~./sault" | magenta }}
  {{ "$ sault server run" | magenta }}
5. Add users and ssh hosts like this:
  {{ "$ sault user add spikeekips ~/.ssh/id_rsa.pub" | magenta }}
  The "spikeekips" is the name for sault, it is not ssh user account name.
  {{ "$ sault host add president-server ubuntu@192.168.99.110:22" | magenta }}
  You added the, "president-server", it will be used host name to connect to "ubuntu@192.168.99.110:22".
  {{ "$ sault user link spikeekips president-server" | magenta }}
  This will allow to access "spikeekips" to "president-server" with the "ubuntu" user account.
6. Connect with your ssh client to ssh server
  {{ "$ ssh spikeekips ubuntu@president-server" | magenta }}

For more information, check out the helps with {{ "$ sault <command> -h" | magenta }}, or visit https://github.com/spikeekips/sault .
	`,
	Options: []OptionTemplate{
		OptionTemplate{
			Name:      "LogFormat",
			Help:      fmt.Sprintf("log format %s", availableLogFormats),
			ValueType: &struct{ Type FlagLogFormat }{FlagLogFormat("")},
		},
		OptionTemplate{
			Name:      "LogLevel",
			Help:      fmt.Sprintf("log level %s", availableLogLevel),
			ValueType: &struct{ Type FlagLogLevel }{FlagLogLevel("")},
		},
		OptionTemplate{
			Name:      "LogOutput",
			Help:      "log output [stdout stderr <filename>]",
			ValueType: &struct{ Type FlagLogOutput }{FlagLogOutput("")},
		},
		OptionTemplate{
			Name: "At",
			Help: "sault server, sault@<sault server[:port]>",
			ValueType: &struct{ Type flagSaultServer }{
				flagSaultServer(fmt.Sprintf("sault@localhost:%d", defaultServerPort)),
			},
		},
		OptionTemplate{
			Name:      "Key",
			Help:      "private key to connect sault server.",
			ValueType: &struct{ Type flagPrivateKey }{flagPrivateKey{}},
		},
	},
	ParseFunc:     parseGlobalOptions,
	ParseFuncInit: parseGlobalOptionsInit,
}

// FlagLogFormat set the log format
type FlagLogFormat string

func (l *FlagLogFormat) String() string {
	return string(*l)
}

// Set value
func (l *FlagLogFormat) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogFormat(DefaultLogFormat)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range availableLogFormats {
		if f == nv {
			*l = FlagLogFormat(nv)
			return nil
		}
	}

	return errors.New("")
}

// FlagLogLevel set the log level
type FlagLogLevel string

func (l *FlagLogLevel) String() string {
	return string(*l)
}

// Set value
func (l *FlagLogLevel) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogLevel(DefaultLogLevel)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range availableLogLevel {
		if f == nv {
			*l = FlagLogLevel(nv)
			return nil
		}
	}

	return errors.New("")
}

// FlagLogOutput set the output for logging
type FlagLogOutput string

func (l *FlagLogOutput) String() string {
	return string(*l)
}

// Set value
func (l *FlagLogOutput) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogOutput(DefaultLogOutput)
		return nil
	}

	nv := strings.ToLower(value)
	_, err := ParseLogOutput(value, "")
	if err == nil {
		*l = FlagLogOutput(nv)
		return nil
	}

	return errors.New("")
}

type flagSaultServer string

func (f *flagSaultServer) String() string {
	return string(*f)
}

func (f *flagSaultServer) Set(v string) error {
	_, _, err := ParseHostAccount(v)
	if err != nil {
		return err
	}

	*f = flagSaultServer(v)

	return nil
}

type flagPrivateKey struct {
	Path   string
	Signer saultSsh.Signer
}

func (f *flagPrivateKey) String() string {
	return f.Path
}

func (f *flagPrivateKey) Set(v string) error {
	checkSSHAgent()

	keyFile := filepath.Clean(v)

	var signer saultSsh.Signer
	{
		var err error
		var tmpPublicKey saultSsh.PublicKey
		tmpPublicKey, err = loadPublicKeyFromPrivateKeyFile(keyFile)
		if err == nil {
			signer, err = findSignerInSSHAgent(tmpPublicKey)
			if err != nil {
				log.Error(err)
			}
		}
	}

	if signer == nil {
		var err error
		signer, err = loadPrivateKeySigner(keyFile)
		if err != nil {
			log.Error(err)
		}
	}

	if signer == nil {
		return fmt.Errorf("failed to load private key from '%s'", keyFile)
	}

	*f = flagPrivateKey{Path: keyFile, Signer: signer}

	return nil
}

func parseGlobalOptionsInit(op *Options, args []string) error {
	return nil
}

func parseGlobalOptions(op *Options, args []string) error {
	values := op.Values(false)["Options"].(OptionsValues)

	{
		saultServer := string(*values["At"].(*flagSaultServer))
		serverName, fullHostName, err := ParseHostAccount(saultServer)
		if err != nil {
			return err
		}
		hostName, port, err := SplitHostPort(fullHostName, defaultServerPort)
		if err != nil {
			return err
		}

		op.Extra["SaultServerName"] = serverName
		op.Extra["SaultServerHostName"] = hostName
		op.Extra["SaultServerAddress"] = fmt.Sprintf("%s:%d", hostName, port)
	}

	{
		key := values["Key"].(*flagPrivateKey)
		op.Extra["Signer"] = key.Signer
	}

	return nil
}

func loadPrivateKeySigner(privateKeyFile string) (signer saultSsh.Signer, err error) {
	b, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return
	}

	// if private key does not have passphrase,
	{
		signer, err = GetPrivateKeySignerFromString(string(b))
		if err == nil {
			return
		}

		err = nil
	}

	// read passphrase, try to decrypt private key
	CommandOut.Printf("Enter passphrase for key '%s'", privateKeyFile)
	var maxTries = 3
	var tries int
	for {
		if tries > (maxTries - 1) {
			break
		}

		var passphrase string
		passphrase, err = ReadPassword(maxAuthTries)
		if err != nil {
			log.Error(err)
			return
		}
		fmt.Fprint(os.Stdout, "")

		if len(passphrase) < 1 {
			err = errors.New("cancel passphrase authentication")
			log.Error(err)
			return
		}

		var key interface{}
		key, err = sshkeys.ParseEncryptedRawPrivateKey(b, []byte(passphrase))
		if err == nil {
			signer, err = saultSsh.NewSignerFromKey(key)
			if err == nil {
				break
			} else {
				log.Error(err)
			}
		}
		tries++
		CommandOut.Errorf("failed to parse private key, will try again: %v", err)
	}

	if signer == nil {
		return
	}

	err = nil
	log.Debugf("successfully load client private key, '%s'", privateKeyFile)

	return
}
