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

type responseMsg struct {
	Result []byte
	Error  string
}

type userAddRequestData struct {
	User      string
	PublicKey string
}

type userRemoveRequestData struct {
	User string
}

type userAdminRequestData struct {
	User     string
	SetAdmin bool
}

type userActiveRequestData struct {
	User   string
	Active bool
}

type userUpdateRequestData struct {
	User         string
	NewUserName  string
	NewPublicKey string
}

type userGetRequestData struct {
	User      string
	PublicKey string
}

type hostGetRequestData struct {
	Host string
}

type hostAddRequestData struct {
	Host             string
	DefaultAccount   string
	Accounts         []string
	Address          string
	Port             uint64
	ClientPrivateKey string
}

func (p hostAddRequestData) getFullAddress() string {
	port := p.Port
	if p.Port < 1 {
		port = 22
	}

	return fmt.Sprintf("%s:%d", p.Address, port)
}

type hostRemoveRequestData struct {
	Host string
}

type hostUpdateRequestData struct {
	Host                string
	NewHostName         string
	NewDefaultAccount   string
	NewAccounts         []string
	NewAddress          string
	NewPort             uint64
	NewClientPrivateKey string
}

type hostActiveRequestData struct {
	Host   string
	Active bool
}

type connectRequestData struct {
	Host          string
	User          string
	TargetAccount string
	Disconnect    bool
}

type userResponseData struct {
	UserData  UserRegistryData
	Connected map[string][]string
}

func newUserResponseData(registry Registry, userData UserRegistryData) userResponseData {
	return userResponseData{
		UserData:  userData,
		Connected: registry.GetConnectedHosts(userData.User),
	}
}

type clientKeysResponseData struct {
	PrivateKey string
	PublicKey  string
}
