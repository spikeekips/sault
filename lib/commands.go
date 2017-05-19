package sault

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var commandForNotAdmin map[string]bool
var serverOptionsTemplate OptionsTemplate
var userOptionsTemplate OptionsTemplate
var hostOptionsTemplate OptionsTemplate

// GlobalOptionsTemplate has global flags
var GlobalOptionsTemplate OptionsTemplate

// RequestCommands has command to rquest to sault server
var RequestCommands map[string]func(OptionsValues, OptionsValues) error
var responseCommands map[string]func(*proxyConnection, saultSsh.Channel, commandMsg) (uint32, error)

func init() {
	serverOptionsTemplate = OptionsTemplate{
		Name:  "server",
		Help:  "sault server",
		Usage: "[flags] command",
		Commands: []OptionsTemplate{
			serverRunOptionsTemplate,
			showConfigOptionsTemplate,
			showClientKeysOptionsTemplate,
		},
	}

	userOptionsTemplate = OptionsTemplate{
		Name:  "user",
		Help:  "manage users",
		Usage: "[flags] command",
		Commands: []OptionsTemplate{
			userGetOptionsTemplate,
			userAddOptionsTemplate,
			userRemoveOptionsTemplate,
			userUpdateOptionsTemplate,
			userActiveOptionsTemplate,
			userAdminOptionsTemplate,
			linkOptionsTemplate,
		},
	}

	hostOptionsTemplate = OptionsTemplate{
		Name:  "host",
		Help:  "manage hosts",
		Usage: "[flags] command",
		Commands: []OptionsTemplate{
			hostGetOptionsTemplate,
			hostAddOptionsTemplate,
			hostRemoveOptionsTemplate,
			hostUpdateOptionsTemplate,
			hostActiveOptionsTemplate,
			hostAliveOptionsTemplate,
		},
	}

	globalOptionsTemplate.Commands = append(globalOptionsTemplate.Commands,
		[]OptionsTemplate{
			initOptionsTemplate,
			serverOptionsTemplate,
			userOptionsTemplate,
			hostOptionsTemplate,
			whoAmIOptionsTemplate,
		}...,
	)
	GlobalOptionsTemplate = globalOptionsTemplate

	RequestCommands = map[string]func(OptionsValues, OptionsValues) error{
		"init":              runInit,
		"server.run":        runServer,
		"server.config":     requestShowConfig,
		"server.clientKeys": requestShowClientKeys,
		"user.get":          requestUserGet,
		"user.add":          requestUserAdd,
		"user.remove":       requestUserRemove,
		"user.active":       requestUserActive,
		"user.admin":        requestUserAdmin,
		"user.update":       requestUserUpdate,
		"host.get":          requestHostGet,
		"host.add":          requestHostAdd,
		"host.remove":       requestHostRemove,
		"host.update":       requestHostUpdate,
		"host.active":       requestHostActive,
		"host.alive":        requesthostAlive,
		"user.link":         requestLink,
		"whoami":            requestWhoAmI,
	}
	responseCommands = map[string]func(*proxyConnection, saultSsh.Channel, commandMsg) (uint32, error){
		"server.config":     responseShowConfig,
		"server.clientKeys": responseShowClientKeys,
		"user.get":          responseUserGet,
		"user.add":          responseUserAdd,
		"user.remove":       responseUserRemove,
		"user.active":       responseUserActive,
		"user.admin":        responseUserAdmin,
		"user.update":       responseUserUpdate,
		"user.link":         responseLink,
		"host.get":          responseHostGet,
		"host.add":          responseHostAdd,
		"host.remove":       responseHostRemove,
		"host.update":       responseHostUpdate,
		"host.active":       responseHostActive,
		"host.alive":        responsehostAlive,
		"whoami":            responseWhoAmI,
		"publicKey":         responseUpdatePublicKey,
	}

	// this is for commands thru native ssh client
	commandForNotAdmin = map[string]bool{
		"whoami":    true,
		"publicKey": true,
	}
}

func parseBaseCommandOptions(op *Options, args []string) error {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			PrintHelp(op, flag.ErrHelp)
			os.Exit(1)
		}
	}
	return nil
}

func handleCommandMsg(
	pc *proxyConnection,
	channel saultSsh.Channel,
	msg commandMsg,
) (exitStatus uint32) {
	var err error
	log.Debugf("command: `%s`", strings.TrimSpace(msg.Command))

	if !pc.userData.IsAdmin {
		if allowed, ok := commandForNotAdmin[msg.Command]; !ok || !allowed {
			err = fmt.Errorf("command, `%s`: permission denied", msg.Command)
			log.Error(err)

			response, _ := newResponseMsgWithError(err).ToJSON()
			channel.Write(response)
			return
		}
	}

	if handler, ok := responseCommands[msg.Command]; ok {
		exitStatus, err = handler(pc, channel, msg)
		log.Debugf("command=%s exitStatus=%v err=%v", msg.Command, exitStatus, err)
		if err != nil {
			log.Error(err)
			response, _ := newResponseMsgWithError(err).ToJSON()

			channel.Write(response)
		}
		return
	}

	err = fmt.Errorf("unknown msg: %v", msg.Command)
	log.Error(err)

	response, _ := newResponseMsgWithError(err).ToJSON()
	channel.Write(response)

	return
}

func sshAgentAuthMethod(clientPublicKey saultSsh.PublicKey) (saultSsh.AuthMethod, error) {
	agent, err := getSshAgent()
	if err != nil {
		return nil, err
	}

	var signerCallback func() ([]saultSsh.Signer, error)
	if clientPublicKey == nil {
		signerCallback = agent.Signers
	} else {
		authorizedKey := GetAuthorizedKey(clientPublicKey)

		signerCallback = func() ([]saultSsh.Signer, error) {
			list, err := agent.Signers()
			if err != nil {
				return nil, err
			}

			// filter
			var filtered []saultSsh.Signer
			for _, l := range list {
				if GetAuthorizedKey(l.PublicKey()) != authorizedKey {
					continue
				}

				log.Debugf("found the matched identity file, '%s'", l.PublicKey())
				filtered = append(filtered, l)
			}
			return filtered, nil
		}
	}

	return saultSsh.PublicKeysCallback(signerCallback), nil
}

func connectSaultServer(serverName, address string, clientPublicKey saultSsh.PublicKey) (*saultSsh.Client, error) {
	sshAgentAuth, err := sshAgentAuthMethod(clientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ssh agent: `%v`", err)
	}

	clientConfig := &saultSsh.ClientConfig{
		User:            serverName,
		Auth:            []saultSsh.AuthMethod{sshAgentAuth},
		HostKeyCallback: saultSsh.InsecureIgnoreHostKey(),
	}

	log.Debugf("trying to connect to sault server, `%s`", address)

	connection, err := saultSsh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect sault server, `%s`: %v", address, err)
	}

	log.Debug("connection established")

	return connection, nil
}

func runCommand(
	serverName,
	address string,
	clientPublicKey saultSsh.PublicKey,
	command string,
	data interface{},
	out interface{},
) (response *responseMsg, err error) {
	var connection *saultSsh.Client
	connection, err = connectSaultServer(serverName, address, clientPublicKey)
	if err != nil {
		return
	}
	defer connection.Close()

	var msg *commandMsg
	msg, err = newCommandMsg(command, data)
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
	output, err = session.Output(string(saultSsh.Marshal(msg)))
	if err != nil {
		if exitError, ok := err.(*saultSsh.ExitError); ok {
			err = fmt.Errorf("ExitError: %v", exitError)
			return
		}
		return
	}

	response, err = responseMsgFromJson(output, out)

	return
}
