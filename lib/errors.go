package sault

import (
	"encoding/json"
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
	return e.Message
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
