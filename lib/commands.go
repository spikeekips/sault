package sault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"
	"github.com/spikeekips/sault/ssh/agent"
)

var commandForNotAdmin map[string]bool
var serverOptionsTemplate OptionsTemplate
var userOptionsTemplate OptionsTemplate
var hostOptionsTemplate OptionsTemplate

// RequestCommands has command to rquest to sault server
var RequestCommands map[string]func(OptionsValues, OptionsValues) (int, error)
var responseCommands map[string]func(*proxyConnection, saultSsh.Channel, commandMsg) (uint32, error)

// GlobalOptionsTemplate has global flags
var GlobalOptionsTemplate OptionsTemplate

var atOptionTemplate = OptionTemplate{
	Name: "At",
	Help: "sault server, sault@<sault server[:port]>",
	ValueType: &struct{ Type flagSaultServer }{
		flagSaultServer(fmt.Sprintf("sault@localhost:%d", defaultServerPort)),
	},
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

func parseBaseCommandOptions(op *Options, args []string) error {
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

	return nil
}

func toResponse(result interface{}, resultError error) []byte {
	if resultError != nil {
		return saultSsh.Marshal(
			responseMsg{Error: resultError.Error()},
		)
	}

	jsoned, err := json.Marshal(result)
	if err != nil {
		return saultSsh.Marshal(
			responseMsg{Error: err.Error()},
		)
	}

	return saultSsh.Marshal(
		responseMsg{Result: jsoned},
	)
}

func handleCommandMsg(
	pc *proxyConnection,
	channel saultSsh.Channel,
	msg commandMsg,
) (exitStatus uint32, err error) {
	exitStatus = 0

	log.Debugf("command: `%s`", strings.TrimSpace(msg.Command))

	if !pc.userData.IsAdmin {
		if allowed, ok := commandForNotAdmin[msg.Command]; !ok || !allowed {
			err = fmt.Errorf("command, `%s` not allowed for not admin user", msg.Command)
			exitStatus = 1

			return
		}
	}

	if handler, ok := responseCommands[msg.Command]; ok {
		exitStatus, err = handler(pc, channel, msg)
		if err != nil {
			log.Error(err)
		}
		return
	}

	err = fmt.Errorf("unknown msg: %v", msg.Command)
	//exitStatus = 1

	return
}

func defaultSshAgent() (saultSsh.AuthMethod, error) {
	sa, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}

	return saultSsh.PublicKeysCallback(sshAgent.NewClient(sa).Signers), nil
}

func makeConnectionForSaultServer(serverName, address string) (*saultSsh.Client, error) {
	sshAgentAuth, err := defaultSshAgent()
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

func RunCommand(serverName, address, command string, data interface{}, out interface{}) (exitStatus int, err error) {
	var connection *saultSsh.Client
	connection, err = makeConnectionForSaultServer(serverName, address)
	if err != nil {
		err = &RunCommandError{E: err}
		return
	}

	var msg *commandMsg
	msg, err = newCommandMsg(command, data)
	if err != nil {
		err = &RunCommandError{E: err}
		return
	}

	var output []byte

	session, err := connection.NewSession()
	if err != nil {
		err = &RunCommandError{E: fmt.Errorf("failed to create session: %s", err)}
		return
	}
	defer session.Close()

	// marshal command
	log.Debugf("run command: %v", msg)
	output, err = session.Output(string(saultSsh.Marshal(msg)))
	if err != nil {
		if exitError, ok := err.(*saultSsh.ExitError); ok {
			err = &RunCommandError{E: fmt.Errorf("got exitError: %v", exitError)}
			return
		}
		err = &RunCommandError{E: fmt.Errorf("command %v was failed: %v", err)}
		return
	}

	if err != nil {
		err = &RunCommandError{E: err}
		return
	}

	var rm responseMsg
	if err = saultSsh.Unmarshal(output, &rm); err != nil {
		err = &RunCommandError{E: err}
		return
	}

	if rm.Error != "" {
		err = &RunCommandError{RemoteError: errors.New(rm.Error)}
		return
	}

	if out == nil {
		return
	}

	if err = json.Unmarshal(rm.Result, out); err != nil {
		err = &RunCommandError{E: err}
		return
	}

	jsoned, _ := json.MarshalIndent(out, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	return
}

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
			userListOptionsTemplate,
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
			hostListOptionsTemplate,
			hostAddOptionsTemplate,
			hostRemoveOptionsTemplate,
			hostUpdateOptionsTemplate,
			hostActiveOptionsTemplate,
			hostAliveOptionsTemplate,
		},
	}

	GlobalOptionsTemplate = OptionsTemplate{
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
			atOptionTemplate,
		},
		Commands: []OptionsTemplate{
			initOptionsTemplate,
			serverOptionsTemplate,
			userOptionsTemplate,
			hostOptionsTemplate,
			whoAmIOptionsTemplate,
		},
		ParseFunc: parseGlobalOptions,
	}

	RequestCommands = map[string]func(OptionsValues, OptionsValues) (int, error){
		"init":              runInit,
		"server.run":        runServer,
		"server.config":     requestShowConfig,
		"server.clientKeys": requestShowClientKeys,
		"user.get":          requestUserGet,
		"user.list":         requestUserList,
		"user.add":          requestUserAdd,
		"user.remove":       requestUserRemove,
		"user.active":       requestUserActive,
		"user.admin":        requestUserAdmin,
		"user.update":       requestUserUpdate,
		"host.get":          requestHostGet,
		"host.list":         requestHostList,
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
		"user.list":         responseUserList,
		"user.add":          responseUserAdd,
		"user.remove":       responseUserRemove,
		"user.active":       responseUserActive,
		"user.admin":        responseUserAdmin,
		"user.update":       responseUserUpdate,
		"user.link":         responseLink,
		"host.get":          responseHostGet,
		"host.list":         responseHostList,
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
