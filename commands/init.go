package saultcommands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/saultssh"
)

var log *logrus.Logger

var sshDirectory = "~/.ssh"
var authorizedKeyFile = "~/.ssh/authorized_keys"

func init() {
	log = logrus.New()
	SetupLog(logrus.ErrorLevel, os.Stdout, nil)
}

// SetupLog will set up the logging
func SetupLog(level logrus.Level, out io.Writer, formatter logrus.Formatter) {
	log.Level = level

	if formatter == nil {
		formatter = saultcommon.GetDefaultLogrusFormatter()
	}
	log.Formatter = formatter
	log.Out = out
}

func sshAgentAuthMethod(signer saultssh.Signer) ([]saultssh.AuthMethod, error) {
	var signerCallback func() ([]saultssh.Signer, error)
	if signer != nil {
		signerCallback = func() ([]saultssh.Signer, error) {
			return []saultssh.Signer{signer}, nil
		}
	} else {
		agent, err := saultcommon.GetSSHAgent()
		if err != nil {
			return nil, err
		}
		signerCallback = agent.Signers
	}

	return []saultssh.AuthMethod{
		saultssh.PublicKeysCallback(signerCallback),
	}, nil
}

func connectSaultServer(serverName, address string, signer saultssh.Signer) (*saultssh.Client, error) {
	authMethods, err := sshAgentAuthMethod(signer)
	if err != nil {
		return nil, err
	}

	clientConfig := &saultssh.ClientConfig{
		User:            serverName,
		Auth:            authMethods,
		HostKeyCallback: saultssh.InsecureIgnoreHostKey(),
	}

	log.Debugf("trying to connect to sault server, '%s'", address)

	connection, err := saultssh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, saultcommon.NewCommandError(
			saultcommon.CommandErrorAuthFailed,
			fmt.Sprintf("failed to connect sault server, '%s': %v", address, err),
		)
	}

	log.Debugf("connection established, %s@%s", serverName, address)

	return connection, nil
}

func responseMsgFromJSON(b []byte, data interface{}) (*saultcommon.ResponseMsg, error) {
	var rm saultcommon.ResponseMsg
	err := json.Unmarshal(b, &rm)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return &rm, nil
	}

	jsoned, err := json.Marshal(rm.Data)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(jsoned, data)
	rm.Data = data

	return &rm, nil
}

func runCommand(
	mainFlags *saultflags.Flags,
	command string,
	data interface{},
	out interface{},
) (response *saultcommon.ResponseMsg, err error) {
	saultServer := mainFlags.Values["Sault"].(saultcommon.FlagSaultServer)
	identity := mainFlags.Values["Identity"].(saultcommon.FlagPrivateKey).Signer

	var connection *saultssh.Client
	connection, err = connectSaultServer(saultServer.SaultServerName, saultServer.Address, identity)
	if err != nil {
		return
	}
	defer connection.Close()

	var msg *saultcommon.CommandMsg
	msg, err = saultcommon.NewCommandMsg(command, data)
	if err != nil {
		return
	}

	var output []byte

	session, err := connection.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	// marshal command
	log.Debugf("run command: %v", msg)
	output, err = session.Output(string(saultssh.Marshal(msg)))
	if err != nil {
		if exitError, ok := err.(*saultssh.ExitError); ok {
			err = fmt.Errorf("ExitError: %v", exitError)
			return
		}
		return
	}

	response, err = responseMsgFromJSON(output, out)
	if err != nil {
		return
	}

	if err == nil && response.Err != nil {
		err = response.Err
		return
	}

	return
}
