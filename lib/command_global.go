package sault

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/ScaleFT/sshkeys"
	"github.com/spikeekips/sault/ssh"
	"github.com/spikeekips/sault/ssh/agent"
)

// GlobalOptionsTemplate has global flags
var globalOptionsTemplate = OptionsTemplate{
	Name:  os.Args[0],
	Usage: "[flags] command",
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
	ParseFunc: parseGlobalOptions,
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
	Path      string
	PublicKey saultSsh.PublicKey
}

func (f *flagPrivateKey) String() string {
	return f.Path
}

func (f *flagPrivateKey) Set(v string) error {
	keyFile := filepath.Clean(v)

	var clientPublicKey saultSsh.PublicKey

	publicKey, err := loadPublicKeyFromPrivateKeyFile(keyFile)
	authorizedKey := GetAuthorizedKey(publicKey)
	if err == nil {
		agent, err := getSshAgent()
		if err != nil {
			return err
		}

		list, err := agent.Signers()
		if err != nil {
			return err
		}

		for _, l := range list {
			if GetAuthorizedKey(l.PublicKey()) == authorizedKey {
				clientPublicKey = publicKey
				break
			}
		}
	}

	if clientPublicKey == nil {
		b, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return err
		}

		signer, err := GetPrivateKeySignerFromString(string(b))
		if err != nil {
			clientPublicKey = signer.PublicKey()
		} else {
			CommandOut.Printf("Enter passphrase for key '%s'", keyFile)
			var sg ssh.Signer
			var maxTries = 3
			var tries int
			for {
				if tries > (maxTries - 1) {
					break
				}

				var password string
				password, err = ReadPassword(maxAuthTries)
				if err != nil {
					log.Error(err)
					return err
				}
				fmt.Fprint(os.Stdout, "")

				if len(password) < 1 {
					err = errors.New("cancel password authentication")
					log.Error(err)
					return err
				}

				sg, err = sshkeys.ParseEncryptedPrivateKey(b, []byte(password))
				if err == nil {
					break
				}
				tries++

				CommandOut.Errorf("failed to parse private key, will try again: %v", err)
			}

			if sg == nil {
				return errors.New("failed to parse the encrypted private key")
			}

			clientPublicKey, err = ParsePublicKeyFromString(string(ssh.MarshalAuthorizedKey(sg.PublicKey())))
			if err != nil {
				return errors.New("failed to parse the encrypted private key: %v")
			}
			log.Debugf("successfully load client private key, '%s'", keyFile)
		}
	}

	*f = flagPrivateKey{Path: keyFile, PublicKey: clientPublicKey}

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
		op.Extra["ClientPublicKey"] = key.PublicKey
	}

	return nil
}

func loadPublicKey(privateKeyFile string) (publicKey saultSsh.PublicKey, err error) {
	privateKeyFile = filepath.Clean(privateKeyFile)

	var tmpPublicKey saultSsh.PublicKey
	tmpPublicKey, err = loadPublicKeyFromPrivateKeyFile(privateKeyFile)
	if err == nil {
		// digg in ssh-agent
		authorizedKey := GetAuthorizedKey(tmpPublicKey)
		var agent sshAgent.Agent
		agent, err = getSshAgent()
		if err != nil {
			return
		}

		var list []saultSsh.Signer
		list, err = agent.Signers()
		if err != nil {
			return
		}

		for _, l := range list {
			if GetAuthorizedKey(l.PublicKey()) == authorizedKey {
				publicKey = tmpPublicKey
				break
			}
		}
		if publicKey != nil {
			return
		}
	}

	b, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return
	}

	// if private key does not have passphrase,
	{
		var signer saultSsh.Signer
		signer, err = GetPrivateKeySignerFromString(string(b))
		if err != nil {
			publicKey = signer.PublicKey()
			return
		}
	}

	// read password, try to decrypt private key
	CommandOut.Printf("Enter passphrase for key '%s'", privateKeyFile)
	var maxTries = 3
	var tries int
	for {
		if tries > (maxTries - 1) {
			break
		}

		var password string
		password, err = ReadPassword(maxAuthTries)
		if err != nil {
			log.Error(err)
			return
		}
		fmt.Fprint(os.Stdout, "")

		if len(password) < 1 {
			err = errors.New("cancel password authentication")
			log.Error(err)
			return
		}

		var signer ssh.Signer
		signer, err = sshkeys.ParseEncryptedPrivateKey(b, []byte(password))
		if err == nil {
			// convert ssh.PublicKey to saultSsh.PublicKey
			publicKey, err = ParsePublicKeyFromString(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			if err != nil {
				err = errors.New("failed to parse the encrypted private key: %v")
				return
			}
			break
		}
		tries++

		CommandOut.Errorf("failed to parse private key, will try again: %v", err)
	}

	log.Debugf("successfully load client private key, '%s'", privateKeyFile)

	return
}
