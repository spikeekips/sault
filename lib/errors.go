package sault

import (
	"encoding/json"
	"fmt"
)

// UnknownCommandError is error for unknown command
type UnknownCommandError struct {
	Command string
}

func (e *UnknownCommandError) Error() string {
	return fmt.Sprintf("unknown command, '%s'", e.Command)
}

type missingCommandError struct {
	s string
}

func (e *missingCommandError) Error() string {
	return "command is missing"
}

type commandErrorType uint
type commandError struct {
	Type    commandErrorType
	Message string
}

const (
	commandErrorNone commandErrorType = iota + 1
	commandErrorAuthFailed
	commandErrorInjectClientKey
)

func (e *commandError) Error() string {
	jsoned, _ := json.Marshal(e)
	return string(jsoned)
}

type InvalidHostName struct {
	name string
}

func (e *InvalidHostName) Error() string {
	return fmt.Sprintf(`invalid hostName, "%s": hostName must be "%s" and less than %d`, e.name, reHostName, maxLengthHostName)
}

type SSHAgentNotRunning struct {
	E error
}

func (e *SSHAgentNotRunning) Error() string {
	if e.E == nil {
		return `'ssh-agent' is not running`
	}

	return fmt.Sprintf("'ssh-agent' has some problem: %v", e.Error)
}

func (e *SSHAgentNotRunning) PrintWarning() {
	if e.E != nil {
		return
	}

	errString, _ := ExecuteCommonTemplate(`
{{ .err | escape }}
{{ "Without 'ssh-agent', you must enter the passphrase in every time you run sault. For details, see 'Using SSH Agent to Automate Login'(https://code.snipcademy.com/tutorials/linux-command-line/ssh-secure-shell-access/ssh-agent-add)." | yellow }}

`,
		map[string]interface{}{
			"err": e.Error(),
		},
	)

	CommandOut.Warnf(errString)
}
