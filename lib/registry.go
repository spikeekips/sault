package sault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spikeekips/sault/ssh"

	log "github.com/Sirupsen/logrus"
	"github.com/naoina/toml"
)

type UserRegistryData struct {
	User      string // must be unique
	PublicKey string

	parsedPublicKey ssh.PublicKey
}

func (u *UserRegistryData) GetPublicKey() ssh.PublicKey {
	if u.parsedPublicKey == nil {
		parsed, err := ParsePublicKeyFromString(u.PublicKey)
		if err != nil {
			return nil
		}
		u.parsedPublicKey = parsed
	}
	return u.parsedPublicKey
}

func (u *UserRegistryData) GetAuthorizedKey() string {
	if u.GetPublicKey() == nil {
		return ""
	}

	return GetAuthorizedKeyFromPublicKey(u.parsedPublicKey)
}

func (u UserRegistryData) String() string {
	return fmt.Sprintf("{%s %s}", u.User, "...")
}

type Base64ClientPrivateKey string

func (d *Base64ClientPrivateKey) UnmarshalText(data []byte) error {
	decodedClientPrivateKey, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	*d = Base64ClientPrivateKey(string(decodedClientPrivateKey))
	return nil
}

func (d Base64ClientPrivateKey) MarshalText() ([]byte, error) {
	encodedClientPrivateKey := base64.StdEncoding.EncodeToString([]byte(d))
	return []byte(encodedClientPrivateKey), nil
}

func (d Base64ClientPrivateKey) GetSigner() (ssh.Signer, error) {
	if string(d) == "" {
		return nil, nil
	}

	signer, err := GetPrivateKeySignerFromString(strings.TrimSpace(string(d)))
	if err != nil {
		log.Errorf("failed to load client private key: %v", err)
		return nil, err
	}

	return signer, nil
}

type HostRegistryData struct {
	Host             string // must be unique
	DefaultAccount   string
	Accounts         []string
	Address          string
	Port             int
	ClientPrivateKey Base64ClientPrivateKey
}

func (p HostRegistryData) String() string {
	return fmt.Sprintf("{%s %s %s %d %s}", p.Host, p.DefaultAccount, p.Address, p.Port, "...")
}

func (p HostRegistryData) GetPort() int {
	port := p.Port
	if p.Port < 1 {
		port = 22
	}

	return port
}

func (p HostRegistryData) GetFullAddress() string {
	return fmt.Sprintf("%s:%d", p.Address, p.GetPort())
}

type Registry interface {
	GetType() string
	String() string
	Save(w io.Writer) error
	Sync() error
	GetUserCount() int
	GetUserByUserName(userName string) (UserRegistryData, error)
	GetUserByPublicKey(publicKey ssh.PublicKey) (UserRegistryData, error)
	GetHostByHostName(hostName string) (HostRegistryData, error)
	GetConnectedByPublicKeyAndHostName(publicKey ssh.PublicKey, hostName, targetAccount string) (
		UserRegistryData,
		HostRegistryData,
		error,
	)
	AddUser(userName, publicKey string) (UserRegistryData, error)
	RemoveUser(userName string) error
	AddHost(
		hostName,
		defaultAccountName,
		address string,
		port int,
		clientPrivateKey string,
	) (HostRegistryData, error)
	GetHostCount() int
	RemoveHost(hostName string) error
	Connect(hostName, userName string, targetAccounts []string) error
	Disconnect(hostName, userName string, targetAccounts []string) error
	ConnectAll(hostName, userName string) error
	DisconnectAll(hostName, userName string) error
	IsConnectedAll(hostName, userName string) bool
	IsConnected(hostName, userName, targetAccount string) bool
}

func NewRegistry(sourceType string, config ConfigSourceRegistry) (Registry, error) {
	switch t := sourceType; t {
	case "file":
		return NewFileRegistry(config.(ConfigFileRegistry))
	default:
		return nil, fmt.Errorf("registry source type, `%s` not found", t)
	}
}

type FileConnectedUserRegistryData struct {
	Account []string
}

type FileRegistryDataSource struct {
	User      map[string]UserRegistryData
	Host      map[string]HostRegistryData
	Connected map[string]map[string]FileConnectedUserRegistryData
}

type FileRegistry struct {
	Path       string
	DataSource *FileRegistryDataSource
}

func (r *FileRegistry) marshal() *bytes.Buffer {
	b := bytes.NewBuffer([]byte{})
	toml.NewEncoder(b).Encode(r.DataSource)

	return b
}

func (r *FileRegistry) Bytes() []byte {
	return r.marshal().Bytes()
}

func (r *FileRegistry) String() string {
	return strings.TrimSpace(r.marshal().String())
}

func (r *FileRegistry) Sync() error {
	tomlFile, err := os.OpenFile(r.Path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer tomlFile.Close()

	toml.NewEncoder(tomlFile).Encode(r.DataSource)
	return nil
}

func (r *FileRegistry) Save(w io.Writer) error {
	toml.NewEncoder(w).Encode(r.DataSource)
	return nil
}

func NewFileRegistry(config ConfigFileRegistry) (*FileRegistry, error) {
	r := FileRegistry{Path: config.Path}

	// load toml file
	f, err := os.Open(config.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dataSource := &FileRegistryDataSource{
		User:      map[string]UserRegistryData{},
		Host:      map[string]HostRegistryData{},
		Connected: map[string]map[string]FileConnectedUserRegistryData{},
	}
	if err := toml.NewDecoder(f).Decode(dataSource); err != nil {
		return nil, err
	}
	r.DataSource = dataSource

	return &r, nil
}

func (r *FileRegistry) GetType() string {
	return "file"
}

func (r *FileRegistry) GetUserByPublicKeyString(publicKey string) (UserRegistryData, error) {
	parsedPublicKey, err := ParsePublicKeyFromString(publicKey)
	if err != nil {
		return UserRegistryData{}, fmt.Errorf("invalid publicKey `%s`: %v", publicKey, err)
	}

	return r.GetUserByPublicKey(parsedPublicKey)
}

func (r *FileRegistry) GetUserByPublicKey(publicKey ssh.PublicKey) (UserRegistryData, error) {
	authorizedKey := GetAuthorizedKeyFromPublicKey(publicKey)

	var matchedUserData *UserRegistryData
	for _, userData := range r.DataSource.User {
		userAuthorizedKey := userData.GetAuthorizedKey()
		if userAuthorizedKey == "" {
			log.Errorf("invalid publicKey for `%s`, %v: %v", userData.User, userData.PublicKey)
			continue
		}
		if userAuthorizedKey == authorizedKey {
			matchedUserData = &userData
			break
		}
	}
	if matchedUserData == nil {
		return UserRegistryData{}, fmt.Errorf("UserData not found")
	}

	return *matchedUserData, nil
}

func (r *FileRegistry) GetHostByHostName(hostName string) (HostRegistryData, error) {
	var matchedHostData *HostRegistryData
	for _, hostData := range r.DataSource.Host {
		if hostName == hostData.Host {
			matchedHostData = &hostData
			break
		}
	}
	if matchedHostData == nil {
		return HostRegistryData{}, fmt.Errorf("HostData not found")
	}

	return *matchedHostData, nil
}

func (r *FileRegistry) GetConnectedByPublicKeyAndHostName(publicKey ssh.PublicKey, hostName, targetAccount string) (
	UserRegistryData,
	HostRegistryData,
	error,
) {
	ud, err := r.GetUserByPublicKey(publicKey)
	if err != nil {
		return UserRegistryData{}, HostRegistryData{}, fmt.Errorf("UserData not found")
	}
	hd, err := r.GetHostByHostName(hostName)
	if err != nil {
		return UserRegistryData{}, HostRegistryData{}, fmt.Errorf("HostData not found")
	}

	// check they are connected
	_, ok := r.DataSource.Connected[hd.Host]
	if !ok {
		return UserRegistryData{}, HostRegistryData{}, fmt.Errorf("not connected")
	}
	uc, ok := r.DataSource.Connected[hd.Host][ud.User]
	if !ok {
		return UserRegistryData{}, HostRegistryData{}, fmt.Errorf("not connected")
	}
	if len(uc.Account) < 1 {
		return UserRegistryData{}, HostRegistryData{}, fmt.Errorf("not connected; no available account")
	}

	var found bool
	for _, a := range uc.Account {
		if a == "*" {
			found = true
			break
		} else if a == targetAccount {
			found = true
			break
		}
	}
	if !found {
		return UserRegistryData{}, HostRegistryData{}, fmt.Errorf("target account, `%s` not available", targetAccount)
	}

	return ud, hd, nil
}

func (r *FileRegistry) GetUserCount() int {
	return len(r.DataSource.User)
}

func (r *FileRegistry) GetUserByUserName(userName string) (UserRegistryData, error) {
	userData, ok := r.DataSource.User[userName]
	if !ok {
		return UserRegistryData{}, fmt.Errorf("UserData not found")
	}

	return userData, nil
}

func (r *FileRegistry) AddUser(userName, publicKey string) (UserRegistryData, error) {
	if _, err := r.GetUserByUserName(userName); err == nil {
		return UserRegistryData{}, fmt.Errorf("userName, `%s` already added", userName)
	}

	if _, err := ParsePublicKeyFromString(publicKey); err != nil {
		return UserRegistryData{}, fmt.Errorf("invalid public key: %v", err)
	}

	if _, err := r.GetUserByPublicKeyString(publicKey); err == nil {
		return UserRegistryData{}, fmt.Errorf("publicKey, `%s` already added", publicKey)
	}

	userData := UserRegistryData{
		User:      userName,
		PublicKey: strings.TrimSpace(publicKey),
	}
	r.DataSource.User[userName] = userData

	return userData, nil
}

func (r *FileRegistry) RemoveUser(userName string) error {
	_, ok := r.DataSource.User[userName]
	if !ok {
		return fmt.Errorf("userName, `%s`, not found")
	}

	delete(r.DataSource.User, userName)

	for hostName, users := range r.DataSource.Connected {
		if _, ok := users[userName]; !ok {
			continue
		}
		delete(r.DataSource.Connected[hostName], userName)
	}

	return nil
}

func (r *FileRegistry) AddHost(
	hostName,
	defaultAccountName,
	address string,
	port int,
	clientPrivateKey string,
) (HostRegistryData, error) {
	if clientPrivateKey != "" {
		if _, err := GetPrivateKeySignerFromString(clientPrivateKey); err != nil {
			return HostRegistryData{}, fmt.Errorf("invalid clientPrivateKey: %v", err)
		}
	}

	if _, err := r.GetHostByHostName(hostName); err == nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s` already added", hostName)
	}

	hostData := HostRegistryData{
		Host:           hostName,
		DefaultAccount: defaultAccountName,
		Address:        address,
		Port:           port,
		Accounts:       []string{defaultAccountName},
	}
	if clientPrivateKey != "" {
		hostData.ClientPrivateKey = Base64ClientPrivateKey(clientPrivateKey)
	}

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *FileRegistry) GetHostCount() int {
	return len(r.DataSource.Host)
}

func (r *FileRegistry) RemoveHost(hostName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found")
	}

	delete(r.DataSource.Host, hostName)

	if _, ok := r.DataSource.Connected[hostName]; ok {
		delete(r.DataSource.Connected, hostName)
	}

	return nil
}

func (r *FileRegistry) IsConnectedAll(hostName, userName string) bool {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return false
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		return false
	}
	uc, ok := r.DataSource.Connected[hostName][userName]
	if !ok {
		return false
	}

	for _, a := range uc.Account {
		if a == "*" {
			return true
		}
	}

	return false
}

func (r *FileRegistry) IsConnected(hostName, userName, targetAccount string) bool {
	if r.IsConnectedAll(hostName, userName) {
		return true
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return false
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		return false
	}
	uc, ok := r.DataSource.Connected[hostName][userName]
	if !ok {
		return false
	}

	for _, a := range uc.Account {
		if a == targetAccount {
			return true
		}
	}

	return false
}

func (r *FileRegistry) ConnectAll(hostName, userName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		r.DataSource.Connected[hostName] = map[string]FileConnectedUserRegistryData{}
	}
	r.DataSource.Connected[hostName][userName] = FileConnectedUserRegistryData{Account: []string{"*"}}

	return nil
}

func (r *FileRegistry) Connect(hostName, userName string, targetAccounts []string) error {
	if r.IsConnectedAll(hostName, userName) {
		return nil
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		r.DataSource.Connected[hostName] = map[string]FileConnectedUserRegistryData{}
	}
	uc, ok := r.DataSource.Connected[hostName][userName]
	if !ok {
		r.DataSource.Connected[hostName][userName] = FileConnectedUserRegistryData{Account: targetAccounts}
		return nil
	}

	var filtered []string
	filtered = append(filtered, uc.Account...)
	for _, a := range targetAccounts {
		var skip bool
		for _, t := range filtered {
			if a == t {
				skip = true
				break
			}
		}

		if skip {
			continue
		}
		filtered = append(filtered, a)
	}

	r.DataSource.Connected[hostName][userName] = FileConnectedUserRegistryData{Account: filtered}

	return nil
}
func (r *FileRegistry) Disconnect(hostName, userName string, targetAccounts []string) error {
	if r.IsConnectedAll(hostName, userName) {
		return nil
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		return nil
	}
	uc, ok := r.DataSource.Connected[hostName][userName]
	if !ok {
		return nil
	}

	var filtered []string
	for _, a := range uc.Account {
		var found bool
		for _, t := range targetAccounts {
			if a == t {
				found = true
				break
			}
		}

		if found {
			continue
		}
		filtered = append(filtered, a)
	}

	r.DataSource.Connected[hostName][userName] = FileConnectedUserRegistryData{Account: filtered}

	return nil
}

func (r *FileRegistry) DisconnectAll(hostName, userName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		return nil
	}
	delete(r.DataSource.Connected[hostName], userName)

	return nil
}
