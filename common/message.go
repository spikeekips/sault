package saultcommon

import "encoding/json"

type CommandErrorType uint
type CommandError struct {
	Type    CommandErrorType
	Message string
}

const (
	CommandErrorNone CommandErrorType = iota + 1
	CommandErrorCommon
	CommandErrorAuthFailed
	CommandErrorInjectClientKey
	CommandErrorPermissionDenied
)

func (e *CommandError) Error() string {
	var m string
	switch e.Type {
	case CommandErrorAuthFailed:
		m = "authentication failed"
	default:
		m = e.Message
	}

	return m
}

func NewCommandError(errType CommandErrorType, message string) *CommandError {
	return &CommandError{
		Type:    errType,
		Message: message,
	}
}

type ResponseMsgError struct {
	ErrorType CommandErrorType
	Message   string
}

func (r *ResponseMsgError) IsError(errType CommandErrorType) bool {
	return r.ErrorType == errType
}

func (r *ResponseMsgError) Error() string {
	var m string

	switch r.ErrorType {
	case CommandErrorPermissionDenied:
		m = "permission denied"
	case CommandErrorAuthFailed:
		m = "authentication failed"
	case CommandErrorInjectClientKey:
		m = "failed to inject client key"
	default:
		m = r.Message
	}
	return m
}

type ResponseMsg struct {
	Data interface{}
	Err  *ResponseMsgError
}

func NewResponseMsg(result interface{}, errType CommandErrorType, e error) *ResponseMsg {
	var errString string
	if e != nil {
		errString = e.Error()
	}

	var err *ResponseMsgError
	if errType == CommandErrorNone {
		err = nil
	} else {
		err = &ResponseMsgError{ErrorType: errType, Message: errString}
	}

	return &ResponseMsg{
		Data: result,
		Err:  err,
	}
}

func (r *ResponseMsg) ToJSON() ([]byte, error) {
	jsoned, err := json.Marshal(r)
	if err != nil {
		return []byte{}, err
	}

	return jsoned, nil
}

type CommandMsg struct {
	Name string
	Data []byte
}

func NewCommandMsg(name string, data interface{}) (msg *CommandMsg, err error) {
	var marshaled []byte
	marshaled, err = json.Marshal(data)
	if err != nil {
		return
	}

	msg = &CommandMsg{
		Name: name,
		Data: marshaled,
	}
	return
}

func (msg *CommandMsg) GetData(out interface{}) (err error) {
	err = json.Unmarshal(msg.Data, out)
	return
}
