package sault

import "encoding/json"

var exitStatusNotAllowed uint32 = 254
var exitStatusSuccess uint32 = 0

type exitStatusMsg struct {
	Status uint32
}

type ExecMsg struct {
	Command string
}

type CommandMsg struct {
	Command string
	Data    []byte
}

func NewCommandMsg(command string, s interface{}) (*CommandMsg, error) {
	jsoned, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	msg := CommandMsg{Command: command, Data: jsoned}

	return &msg, nil
}

type ResponseMsg struct {
	Result []byte
	Error  string
}

type UserAddRequestData struct {
	UserName  string
	PublicKey string
}

type UserRemoveRequestData struct {
	UserName string
}

type UserAdminRequestData struct {
	UserName string
	SetAdmin bool
}

type UserActiveRequestData struct {
	UserName string
	Active   bool
}

type UserUpdateRequestData struct {
	UserName     string
	NewUserName  string
	NewPublicKey string
}

type UserGetRequestData struct {
	UserName  string
	PublicKey string
}

type HostGetRequestData struct {
	Host string
}

type HostAddRequestData struct {
	Host             string
	DefaultAccount   string
	Accounts         []string
	Address          string
	Port             uint64
	ClientPrivateKey string
}

type HostRemoveRequestData struct {
	Host string
}

type HostUpdateRequestData struct {
	Host                string
	NewHostName         string
	NewDefaultAccount   string
	NewAccounts         []string
	NewAddress          string
	NewPort             uint64
	NewClientPrivateKey string
}

type ConnectRequestData struct {
	Host          string
	UserName      string
	TargetAccount string
	Disconnect    bool
}

type UserResponseData struct {
	UserData  UserRegistryData
	Connected map[string][]string
}

func NewUserResponseData(registry Registry, userData UserRegistryData) UserResponseData {
	return UserResponseData{
		UserData:  userData,
		Connected: registry.GetConnectedHosts(userData.User),
	}
}
