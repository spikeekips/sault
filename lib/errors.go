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
	commandErrorCommon commandErrorType = iota + 1
	commandErrorAuthFailed
	commandErrorInjectClientKey
)

func (e *commandError) Error() string {
	jsoned, _ := json.Marshal(e)
	return string(jsoned)
}

func newCommandError(t commandErrorType, err error) *commandError {
	return &commandError{
		Type:    t,
		Message: err.Error(),
	}
}

func parseCommandError(s string) (*commandError, error) {
	var ce commandError
	err := json.Unmarshal([]byte(s), &ce)
	if err != nil {
		return nil, err
	}

	return &ce, nil
}

type InvalidHostName struct {
	name string
}

func (e *InvalidHostName) Error() string {
	return fmt.Sprintf(`invalid hostName, "%s": hostName must be "%s" and less than %d`, e.name, reHostName, maxLengthHostName)
}
