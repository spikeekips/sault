package sault

import (
	"encoding/json"
	"fmt"
)

var exitStatusNotAllowed uint32 = 254
var exitStatusSuccess uint32

type exitStatusMsg struct {
	Status uint32
}

type execMsg struct {
	Command string
}

type commandMsg struct {
	Command string
	Data    []byte
}

func newCommandMsg(command string, s interface{}) (*commandMsg, error) {
	jsoned, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	msg := commandMsg{Command: command, Data: jsoned}

	return &msg, nil
}

func (c commandMsg) String() string {
	l := len(c.Data)
	if l > 50 {
		l = 50
	}
	return fmt.Sprintf("{Command: %s Data: %s...}", c.Command, c.Data[:l])
}

type ResponseMsgError struct {
	ErrorType commandErrorType
	Message   string
}

func (r *ResponseMsgError) IsError(errType commandErrorType) bool {
	return r.ErrorType == errType
}

func (r *ResponseMsgError) Error() string {
	return r.Message
}

type responseMsg struct {
	Result interface{}
	Error  *ResponseMsgError
}

func newResponseMsg(result interface{}, errType commandErrorType, e error) *responseMsg {
	var errString string
	if e != nil {
		errString = e.Error()
	}

	var err *ResponseMsgError
	if errType == commandErrorNone {
		err = nil
	} else {
		err = &ResponseMsgError{ErrorType: errType, Message: errString}
	}

	return &responseMsg{
		Result: result,
		Error:  err,
	}
}

func newResponseMsgWithError(e error) *responseMsg {
	if err, ok := e.(*ResponseMsgError); ok {
		return &responseMsg{Error: err}
	}

	return &responseMsg{
		Error: &ResponseMsgError{ErrorType: commandErrorNone, Message: e.Error()},
	}
}

func (r *responseMsg) ToJSON() ([]byte, error) {
	jsoned, err := json.Marshal(r)
	if err != nil {
		return []byte{}, err
	}

	return jsoned, nil
}

func responseMsgFromJson(b []byte, result interface{}) (*responseMsg, error) {
	var rm responseMsg
	err := json.Unmarshal(b, &rm)
	if err != nil {
		return nil, err
	}

	if result == nil {
		return &rm, nil
	}

	if jsoned, err := json.Marshal(rm.Result); err != nil {
		return nil, err
	} else {
		json.Unmarshal(jsoned, result)
		rm.Result = result
	}

	return &rm, nil
}

type userAddRequestData struct {
	User      string
	PublicKey string
}

type userRemoveRequestData struct {
	Users []string
}

type userAdminRequestData struct {
	Users map[string]bool
}

type userActiveRequestData struct {
	Users map[string]bool
}

type userUpdateRequestData struct {
	User         string
	NewUserName  string
	NewPublicKey string
}

type userGetRequestData struct {
	Users     []string
	PublicKey string
	Filter    activeFilter
}

type hostGetRequestData struct {
	Hosts  []string
	Filter activeFilter
}

type hostAddRequestData struct {
	Host             string
	DefaultAccount   string
	Accounts         []string
	Address          string
	Port             uint64
	ClientPrivateKey string
	AuthMethod       string
	Password         string
	Force            bool
}

func (p hostAddRequestData) getFullAddress() string {
	port := p.Port
	if p.Port < 1 {
		port = 22
	}

	return fmt.Sprintf("%s:%d", p.Address, port)
}

type hostRemoveRequestData struct {
	Hosts []string
}

type hostUpdateRequestData struct {
	Host                string
	NewHostName         string
	NewDefaultAccount   string
	NewAccounts         []string
	NewAddress          string
	NewPort             uint64
	NewClientPrivateKey string
	Force               bool
}

type hostActiveRequestData struct {
	Hosts map[string]bool
}

type hostAliveRequestData struct {
	Hosts []string
}

type linkRequestData struct {
	User  string
	Links map[string]bool
}

type userResponseData struct {
	UserData UserRegistryData
	Linked   map[string][]string
}

func newUserResponseData(registry Registry, userData UserRegistryData) userResponseData {
	return userResponseData{
		UserData: userData,
		Linked:   registry.GetLinkedHosts(userData.User),
	}
}

type clientKeysResponseData struct {
	PrivateKey string
	PublicKey  string
}

type hostAliveResponseData struct {
	Host  string
	Uri   string
	Alive bool
	Error string
}

type serverConfigResponseData struct {
	Config string
}
