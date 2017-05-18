package sault

import (
	"encoding/json"
	"fmt"
)

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
		return "'ssh-agent' is not running"
	}

	return fmt.Sprintf("'ssh-agent' has some problem: %v", e.Error)
}
