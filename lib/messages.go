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
	User      string
	PublicKey string
}

type UserRemoveRequestData struct {
	User string
}

type UserAdminRequestData struct {
	User     string
	SetAdmin bool
}

type UserActiveRequestData struct {
	User   string
	Active bool
}

type UserUpdateRequestData struct {
	User         string
	NewUserName  string
	NewPublicKey string
}

type UserGetRequestData struct {
	User      string
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

type HostActiveRequestData struct {
	Host   string
	Active bool
}

type ConnectRequestData struct {
	Host          string
	User          string
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
