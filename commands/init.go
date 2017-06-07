package saultcommands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/sssh"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	SetupLog(logrus.ErrorLevel, os.Stdout, nil)
}

func SetupLog(level logrus.Level, out io.Writer, formatter logrus.Formatter) {
	log.Level = level

	if formatter == nil {
		formatter = &logrus.TextFormatter{
			DisableTimestamp: true,
		}
	}
	log.Formatter = formatter
	log.Out = out
}

func sshAgentAuthMethod(signer sssh.Signer) ([]sssh.AuthMethod, error) {
	var signerCallback func() ([]sssh.Signer, error)
	if signer != nil {
		signerCallback = func() ([]sssh.Signer, error) {
			return []sssh.Signer{signer}, nil
		}
	} else {
		agent, err := saultcommon.GetSSHAgent()
		if err != nil {
			return nil, err
		}
		signerCallback = agent.Signers
	}

	return []sssh.AuthMethod{
		sssh.PublicKeysCallback(signerCallback),
	}, nil
}

func connectSaultServer(serverName, address string, signer sssh.Signer) (*sssh.Client, error) {
	authMethods, err := sshAgentAuthMethod(signer)
	if err != nil {
		return nil, err
	}

	clientConfig := &sssh.ClientConfig{
		User:            serverName,
		Auth:            authMethods,
		HostKeyCallback: sssh.InsecureIgnoreHostKey(),
	}

	log.Debugf("trying to connect to sault server, '%s'", address)

	connection, err := sssh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, saultcommon.NewCommandError(
			saultcommon.CommandErrorAuthFailed,
			fmt.Sprintf("failed to connect sault server, '%s': %v", address, err),
		)
	}

	log.Debugf("connection established, %s@%s", serverName, address)

	return connection, nil
}

func responseMsgFromJson(b []byte, data interface{}) (*saultcommon.ResponseMsg, error) {
	var rm saultcommon.ResponseMsg
	err := json.Unmarshal(b, &rm)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return &rm, nil
	}

	if jsoned, err := json.Marshal(rm.Data); err != nil {
		return nil, err
	} else {
		json.Unmarshal(jsoned, data)
		rm.Data = data
	}

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

	var connection *sssh.Client
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
	output, err = session.Output(string(sssh.Marshal(msg)))
	if err != nil {
		if exitError, ok := err.(*sssh.ExitError); ok {
			err = fmt.Errorf("ExitError: %v", exitError)
			return
		}
		return
	}

	response, err = responseMsgFromJson(output, out)
	if err != nil {
		return
	}

	if err == nil && response.Err != nil {
		err = response.Err
		return
	}

	return
}
