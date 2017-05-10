package sault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
	"github.com/spikeekips/sault/ssh/agent"
)

var CommandForNotAdmin map[string]bool
var UserOptionsTemplate OptionsTemplate
var HostOptionsTemplate OptionsTemplate
var RequestCommands map[string]func(OptionsValues, OptionsValues) int
var ResponseCommands map[string]func(*proxyConnection, saultSsh.Channel, CommandMsg) (uint32, error)
var GlobalOptionsTemplate OptionsTemplate
var DefaultLogFormat = "text"
var DefaultLogLevel = "info"
var DefaultLogOutput = "stdout"
var AtOptionTemplate = OptionTemplate{
	Name:         "At",
	DefaultValue: "sault@localhost",
	Help:         "sault server, sault@<sault server>",
	ValueType:    &struct{ Type FlagSaultServer }{FlagSaultServer("sault@localhost")},
}

var POptionTemplate = OptionTemplate{
	Name:         "P",
	DefaultValue: DefaultServerPort,
	Help:         "sault server port",
}

type FlagLogFormat string

func (l *FlagLogFormat) String() string {
	return string(*l)
}

func (l *FlagLogFormat) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogFormat(DefaultLogFormat)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range AvailableLogFormats {
		if f == nv {
			*l = FlagLogFormat(nv)
			return nil
		}
	}

	return errors.New("")
}

type FlagLogLevel string

func (l *FlagLogLevel) String() string {
	return string(*l)
}

func (l *FlagLogLevel) Set(value string) error {
	if len(strings.TrimSpace(value)) < 1 {
		*l = FlagLogLevel(DefaultLogLevel)
		return nil
	}

	nv := strings.ToLower(value)
	for _, f := range AvailableLogLevel {
		if f == nv {
			*l = FlagLogLevel(nv)
			return nil
		}
	}

	return errors.New("")
}

type FlagLogOutput string

func (l *FlagLogOutput) String() string {
	return string(*l)
}

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

type FlagSaultServer string

func (f *FlagSaultServer) String() string {
	return string(*f)
}

func (f *FlagSaultServer) Set(v string) error {
	_, _, err := ParseHostAccount(v)
	if err != nil {
		return err
	}

	return nil
}

func ParseBaseCommandOptions(op *Options, args []string) error {
	values := op.Values(false)["Options"].(OptionsValues)

	op.Extra = map[string]interface{}{}

	{
		saultServer := string(*values["At"].(*FlagSaultServer))
		serverName, hostName, err := ParseHostAccount(saultServer)
		if err != nil {
			return err
		}
		port := int(*values["P"].(*int))

		op.Extra["SaultServerName"] = serverName
		op.Extra["SaultServerHostName"] = hostName
		op.Extra["SaultServerAddress"] = fmt.Sprintf("%s:%d", hostName, port)
	}

	return nil
}

func ToResponse(result interface{}, resultError error) []byte {
	if resultError != nil {
		return saultSsh.Marshal(
			ResponseMsg{Error: resultError.Error()},
		)
	}

	jsoned, err := json.Marshal(result)
	if err != nil {
		return saultSsh.Marshal(
			ResponseMsg{Error: err.Error()},
		)
	}

	return saultSsh.Marshal(
		ResponseMsg{Result: jsoned},
	)
}

func handleCommandMsg(
	pc *proxyConnection,
	channel saultSsh.Channel,
	msg CommandMsg,
) (exitStatus uint32, err error) {
	exitStatus = 0

	log.Debugf("command: `%s`", strings.TrimSpace(msg.Command))

	if !pc.userData.IsAdmin {
		if allowed, ok := CommandForNotAdmin[msg.Command]; !ok || !allowed {
			err = fmt.Errorf("command, `%s` not allowed for not admin user", msg.Command)
			exitStatus = 1

			return
		}
	}

	if handler, ok := ResponseCommands[msg.Command]; ok {
		exitStatus, err = handler(pc, channel, msg)
		if err != nil {
			log.Error(err)
		}
		return
	}

	err = fmt.Errorf("unknown msg: %v", msg.Command)
	exitStatus = 1

	return
}

func SSHAgent() (saultSsh.AuthMethod, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}

	return saultSsh.PublicKeysCallback(saultSshAgent.NewClient(sshAgent).Signers), nil
}

func makeConnectionForSaultServer(serverName, address string) (*saultSsh.Client, error) {
	sshAgentAuth, err := SSHAgent()
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

func runCommand(connection *saultSsh.Client, msg *CommandMsg) (output []byte, exitStatus int, err error) {
	session, err := connection.NewSession()
	if err != nil {
		err = fmt.Errorf("failed to create session: %s", err)
		return
	}
	defer session.Close()

	// marshal command
	output, err = session.Output(string(saultSsh.Marshal(msg)))
	if err != nil {
		if exitError, ok := err.(*saultSsh.ExitError); ok {
			exitStatus = exitError.Waitmsg.ExitStatus()
			err = fmt.Errorf("got exitError: %v", exitError)
			return
		}
		err = fmt.Errorf("command %v was failed: %v", err)
		return
	}

	return
}

func init() {
	UserOptionsTemplate = OptionsTemplate{
		Name:  "user",
		Help:  "manage user",
		Usage: "[flags] command",
		Commands: []OptionsTemplate{
			UserGetOptionsTemplate,
			UserListOptionsTemplate,
			UserAddOptionsTemplate,
			UserRemoveOptionsTemplate,
			UserUpdateOptionsTemplate,
			UserActiveOptionsTemplate,
			UserAdminOptionsTemplate,
		},
	}

	HostListOptionsTemplate = OptionsTemplate{
		Name:      "list",
		Help:      "get hosts",
		Usage:     "[flags]",
		Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
		ParseFunc: ParseHostListOptions,
	}
	HostOptionsTemplate = OptionsTemplate{
		Name:  "host",
		Help:  "manage host",
		Usage: "[flags] command",
		Commands: []OptionsTemplate{
			HostGetOptionsTemplate,
			HostListOptionsTemplate,
			HostAddOptionsTemplate,
			HostRemoveOptionsTemplate,
			HostUpdateOptionsTemplate,
			HostActiveOptionsTemplate,
		},
	}

	GlobalOptionsTemplate = OptionsTemplate{
		Name:  os.Args[0],
		Usage: "[flags] command",
		Options: []OptionTemplate{
			OptionTemplate{
				Name:      "LogFormat",
				Help:      fmt.Sprintf("log format %s", AvailableLogFormats),
				ValueType: &struct{ Type FlagLogFormat }{FlagLogFormat(DefaultLogFormat)},
			},
			OptionTemplate{
				Name:      "LogLevel",
				Help:      fmt.Sprintf("log level %s", AvailableLogLevel),
				ValueType: &struct{ Type FlagLogLevel }{FlagLogLevel(DefaultLogLevel)},
			},
			OptionTemplate{
				Name:      "LogOutput",
				Help:      "log output [stdout stderr <filename>]",
				ValueType: &struct{ Type FlagLogOutput }{FlagLogOutput(DefaultLogOutput)},
			},
		},
		Commands: []OptionsTemplate{
			ServerOptionsTemplate,
			UserOptionsTemplate,
			HostOptionsTemplate,
			ConnectOptionsTemplate,
			WhoAmIOptionsTemplate,
		},
	}

	RequestCommands = map[string]func(OptionsValues, OptionsValues) int{
		"server":      RunServer,
		"user.get":    RequestUserGet,
		"user.list":   RequestUserList,
		"user.add":    RequestUserAdd,
		"user.remove": RequestUserRemove,
		"user.active": RequestUserActive,
		"user.admin":  RequestUserAdmin,
		"user.update": RequestUserUpdate,
		"host.get":    RequestHostGet,
		"host.list":   RequestHostList,
		"host.add":    RequestHostAdd,
		"host.remove": RequestHostRemove,
		"host.update": RequestHostUpdate,
		"host.active": RequestHostActive,
		"connect":     RequestConnect,
		"whoami":      RequestWhoAmI,
	}
	ResponseCommands = map[string]func(*proxyConnection, saultSsh.Channel, CommandMsg) (uint32, error){
		"user.get":    ResponseUserGet,
		"user.list":   ResponseUserList,
		"user.add":    ResponseUserAdd,
		"user.remove": ResponseUserRemove,
		"user.active": ResponseUserActive,
		"user.admin":  ResponseUserAdmin,
		"user.update": ResponseUserUpdate,
		"host.get":    ResponseHostGet,
		"host.list":   ResponseHostList,
		"host.add":    ResponseHostAdd,
		"host.remove": ResponseHostRemove,
		"host.update": ResponseHostUpdate,
		"host.active": ResponseHostActive,
		"connect":     ResponseConnect,
		"whoami":      ResponseWhoAmI,
		"publicKey":   ResponseUpdatePublicKey,
	}

	// this is for commands thru native ssh client
	CommandForNotAdmin = map[string]bool{
		"whoami":    true,
		"publicKey": true,
	}
}
