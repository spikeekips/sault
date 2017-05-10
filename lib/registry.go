package sault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/spikeekips/sault/ssh"

	log "github.com/Sirupsen/logrus"
	"github.com/naoina/toml"
)

type ActiveFilter int

const (
	_                            = iota
	activeFilterAll ActiveFilter = 1 << (10 * iota)
	activeFilterActive
	activeFilterDeactivated
)

type UserRegistryData struct {
	User        string // must be unique
	PublicKey   string
	IsAdmin     bool
	Deactivated bool

	parsedPublicKey saultSsh.PublicKey
}

func (u *UserRegistryData) GetPublicKey() saultSsh.PublicKey {
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
	a := ""
	if u.IsAdmin {
		a = "*"
	}
	return fmt.Sprintf("{%s%s %s}", u.User, a, "...")
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

func (d Base64ClientPrivateKey) GetSigner() (saultSsh.Signer, error) {
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
	Port             uint64
	ClientPrivateKey Base64ClientPrivateKey
	Deactivated      bool
}

func (p HostRegistryData) String() string {
	return fmt.Sprintf("{%s %s %s %d %s}", p.Host, p.DefaultAccount, p.Address, p.Port, "...")
}

func (p HostRegistryData) GetPort() uint64 {
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

	AddUser(userName, publicKey string) (UserRegistryData, error)
	RemoveUser(userName string) error
	GetUserCount(f ActiveFilter) int
	GetUsers(f ActiveFilter) map[string]UserRegistryData
	GetUserByUserName(userName string) (UserRegistryData, error)
	GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error)
	GetActiveUserByUserName(userName string) (UserRegistryData, error)
	GetActiveUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error)
	SetAdmin(userName string, set bool) error
	IsUserActive(userName string) (bool, error)
	SetUserActive(userName string, active bool) error
	UpdateUserName(userName, newUserName string) (UserRegistryData, error)
	UpdateUserPublicKey(userName, publicKey string) (UserRegistryData, error)

	AddHost(
		hostName,
		defaultAccount,
		address string,
		port uint64,
		clientPrivateKey string,
		accounts []string,
	) (HostRegistryData, error)
	GetHostCount(f ActiveFilter) int
	GetHosts(f ActiveFilter) map[string]HostRegistryData
	GetHostByHostName(hostName string) (HostRegistryData, error)
	GetActiveHostByHostName(hostName string) (HostRegistryData, error)
	IsHostActive(hostName string) (bool, error)
	SetHostActive(hostName string, active bool) error
	RemoveHost(hostName string) error
	UpdateHostName(hostName, newHostName string) (HostRegistryData, error)
	UpdateHostDefaultAccount(hostName, defaultAccount string) (HostRegistryData, error)
	UpdateHostAccounts(hostName string, accounts []string) (HostRegistryData, error)
	UpdateHostAddress(hostName, address string) (HostRegistryData, error)
	UpdateHostPort(hostName string, port uint64) (HostRegistryData, error)
	UpdateHostClientPrivateKey(hostName, clientPrivateKey string) (HostRegistryData, error)

	Connect(hostName, userName string, targetAccounts []string) error
	Disconnect(hostName, userName string, targetAccounts []string) error
	ConnectAll(hostName, userName string) error
	DisconnectAll(hostName, userName string) error
	IsConnectedAll(hostName, userName string) bool
	IsConnected(hostName, userName, targetAccount string) bool
	GetConnectedHosts(userName string) map[string][]string
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
	os.Remove(r.Path)
	tomlFile, err := os.OpenFile(r.Path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer tomlFile.Close()

	return r.Save(tomlFile)
}

func (r *FileRegistry) Save(w io.Writer) error {
	return toml.NewEncoder(w).Encode(r.DataSource)
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

func (r *FileRegistry) GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error) {
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
		return UserRegistryData{}, fmt.Errorf("user with the publickey, not found")
	}

	return *matchedUserData, nil
}

func (r *FileRegistry) GetActiveUserByPublicKey(publicKey saultSsh.PublicKey) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByPublicKey(publicKey)
	if err != nil {
		return
	}

	if userData.Deactivated {
		err = fmt.Errorf("user, `%s`, deactivated", userData.User)
		return
	}

	return
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

func (r *FileRegistry) GetActiveHostByHostName(hostName string) (hostData HostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}
	if hostData.Deactivated {
		err = fmt.Errorf("host, `%s`, deactivated", hostData.Host)
		return
	}

	return
}

func (r *FileRegistry) IsHostActive(hostName string) (bool, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return false, err
	}

	return !hostData.Deactivated, nil
}

func (r *FileRegistry) SetHostActive(hostName string, active bool) error {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return err
	}

	if ok, _ := r.IsHostActive(hostName); ok == active {
		return nil
	}

	hostData.Deactivated = !active
	r.DataSource.Host[hostName] = hostData

	return nil
}

func (r *FileRegistry) GetHosts(f ActiveFilter) (hosts map[string]HostRegistryData) {
	if f == activeFilterAll {
		return r.DataSource.Host
	}

	hosts = map[string]HostRegistryData{}
	for _, h := range r.DataSource.Host {
		if f == activeFilterActive && h.Deactivated {
			continue
		}
		if f == activeFilterDeactivated && !h.Deactivated {
			continue
		}
		hosts[h.Host] = h
	}

	return
}

func (r *FileRegistry) GetUserCount(f ActiveFilter) (c int) {
	switch f {
	case activeFilterAll:
		c = len(r.DataSource.User)
		return
	default:
		for _, u := range r.DataSource.User {
			if u.Deactivated && f == activeFilterDeactivated {
				c++
			} else if !u.Deactivated && f == activeFilterActive {
				c++
			}
		}
	}

	return
}

func (r *FileRegistry) GetUsers(f ActiveFilter) (users map[string]UserRegistryData) {
	users = map[string]UserRegistryData{}

	switch f {
	case activeFilterAll:
		users = r.DataSource.User
		return
	default:
		for userName, u := range r.DataSource.User {
			if u.Deactivated && f == activeFilterDeactivated {
				users[userName] = u
			} else if !u.Deactivated && f == activeFilterActive {
				users[userName] = u
			}
		}
	}

	return
}

func (r *FileRegistry) GetUserByUserName(userName string) (UserRegistryData, error) {
	userData, ok := r.DataSource.User[userName]
	if !ok {
		return UserRegistryData{}, fmt.Errorf("user with userName, `%s`, not found", userName)
	}

	return userData, nil
}

func (r *FileRegistry) AddUser(userName, publicKey string) (UserRegistryData, error) {
	if !CheckUserName(userName) {
		return UserRegistryData{}, fmt.Errorf("invalid userName, `%s`", userName)
	}

	if _, err := r.GetUserByUserName(userName); err == nil {
		return UserRegistryData{}, fmt.Errorf("userName, `%s` already added", userName)
	}

	parsedPublicKey, err := ParsePublicKeyFromString(publicKey)
	if err != nil {
		return UserRegistryData{}, fmt.Errorf("invalid publicKey `%s`: %v", publicKey, err)
	}

	if _, err := r.GetUserByPublicKey(parsedPublicKey); err == nil {
		return UserRegistryData{}, fmt.Errorf("publicKey, `%s` already added", strings.TrimSpace(publicKey))
	}

	userData := UserRegistryData{
		User:      userName,
		PublicKey: strings.TrimSpace(publicKey),
	}
	r.DataSource.User[userName] = userData

	return userData, nil
}

func (r *FileRegistry) GetActiveUserByUserName(userName string) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByUserName(userName)
	if err != nil {
		return
	}
	if userData.Deactivated {
		err = fmt.Errorf("user, `%s`, deactivated", userName)
		return
	}
	return
}

func (r *FileRegistry) RemoveUser(userName string) error {
	_, ok := r.DataSource.User[userName]
	if !ok {
		return fmt.Errorf("userName, `%s`, not found", userName)
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

func (r *FileRegistry) SetAdmin(userName string, set bool) error {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return err
	}

	userData.IsAdmin = set
	r.DataSource.User[userName] = userData

	return nil
}

func (r *FileRegistry) IsUserActive(userName string) (bool, error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return false, err
	}

	return !userData.Deactivated, nil
}

func (r *FileRegistry) SetUserActive(userName string, active bool) error {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return err
	}
	if ok, _ := r.IsUserActive(userName); ok == active {
		return nil
	}

	userData.Deactivated = !active
	r.DataSource.User[userName] = userData

	return nil
}

func (r *FileRegistry) UpdateUserName(userName, newUserName string) (UserRegistryData, error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return UserRegistryData{}, err
	}

	if userData.User == newUserName {
		return userData, nil
	}

	userData.User = newUserName
	delete(r.DataSource.User, userName)

	r.DataSource.User[newUserName] = userData

	for hostName, users := range r.DataSource.Connected {
		if _, ok := users[userName]; !ok {
			continue
		}
		r.DataSource.Connected[hostName][newUserName] = r.DataSource.Connected[hostName][userName]

		delete(r.DataSource.Connected[hostName], userName)
	}

	return userData, nil
}

func (r *FileRegistry) UpdateUserPublicKey(userName, newPublicKey string) (UserRegistryData, error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return UserRegistryData{}, err
	}

	if userData.PublicKey == newPublicKey {
		return userData, nil
	}
	var publicKey saultSsh.PublicKey
	if publicKey, err = ParsePublicKeyFromString(newPublicKey); err != nil {
		return UserRegistryData{}, err
	}
	if another, err := r.GetUserByPublicKey(publicKey); err == nil && another.User != userData.User {
		return UserRegistryData{}, fmt.Errorf("another user has same publicKey")
	}

	userData.PublicKey = strings.TrimSpace(newPublicKey)
	userData.parsedPublicKey = nil
	r.DataSource.User[userName] = userData

	return userData, nil
}

func (r *FileRegistry) AddHost(
	hostName,
	defaultAccount,
	address string,
	port uint64,
	clientPrivateKey string,
	accounts []string,
) (HostRegistryData, error) {
	if clientPrivateKey != "" {
		if _, err := GetPrivateKeySignerFromString(clientPrivateKey); err != nil {
			return HostRegistryData{}, fmt.Errorf("invalid clientPrivateKey: %v", err)
		}
	}

	if _, err := r.GetHostByHostName(hostName); err == nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s` already added", hostName)
	}

	if len(accounts) < 1 {
		accounts = append(accounts, defaultAccount)
	}

	hostData := HostRegistryData{
		Host:           hostName,
		DefaultAccount: defaultAccount,
		Address:        address,
		Port:           port,
		Accounts:       accounts,
	}
	if clientPrivateKey != "" {
		if _, err := GetPrivateKeySignerFromString(clientPrivateKey); err != nil {
			return HostRegistryData{}, err
		}
		hostData.ClientPrivateKey = Base64ClientPrivateKey(clientPrivateKey)
	}

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *FileRegistry) GetHostCount(f ActiveFilter) (c int) {
	switch f {
	case activeFilterAll:
		c = len(r.DataSource.Host)
	default:
		for _, u := range r.DataSource.Host {
			if u.Deactivated && f == activeFilterDeactivated {
				c++
			} else if !u.Deactivated && f == activeFilterActive {
				c++
			}
		}
	}

	return
}

func (r *FileRegistry) RemoveHost(hostName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	delete(r.DataSource.Host, hostName)

	if _, ok := r.DataSource.Connected[hostName]; ok {
		delete(r.DataSource.Connected, hostName)
	}

	return nil
}

func (r *FileRegistry) UpdateHostName(hostName, newHostName string) (HostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}
	if hostName == newHostName {
		return HostRegistryData{}, nil
	}

	if _, err := r.GetHostByHostName(newHostName); err == nil {
		return HostRegistryData{}, fmt.Errorf("newHostName, `%s`, already exists", newHostName)
	}

	hostData.Host = newHostName

	delete(r.DataSource.Host, hostName)
	r.DataSource.Host[newHostName] = hostData

	if _, ok := r.DataSource.Connected[hostName]; ok {
		r.DataSource.Connected[newHostName] = r.DataSource.Connected[hostName]
		delete(r.DataSource.Connected, hostName)
	}

	return hostData, nil
}

func (r *FileRegistry) UpdateHostDefaultAccount(hostName, defaultAccount string) (HostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}
	if defaultAccount == hostData.DefaultAccount {
		return hostData, nil
	}

	hostData.DefaultAccount = defaultAccount

	var found bool
	for _, a := range hostData.Accounts {
		if a == defaultAccount {
			found = true
			break
		}
	}
	if !found {
		hostData.Accounts = append(hostData.Accounts, defaultAccount)
	}

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *FileRegistry) UpdateHostAccounts(hostName string, accounts []string) (HostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if reflect.DeepEqual(accounts, hostData.Accounts) {
		return hostData, nil
	}

	var found bool
	for _, a := range accounts {
		if a == hostData.DefaultAccount {
			found = true
			break
		}
	}
	if !found {
		accounts = append(accounts, hostData.DefaultAccount)
	}

	hostData.Accounts = accounts

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *FileRegistry) UpdateHostAddress(hostName, address string) (HostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if address == hostData.Address {
		return hostData, nil
	}

	hostData.Address = address

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *FileRegistry) UpdateHostPort(hostName string, port uint64) (HostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return HostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if port == hostData.Port {
		return hostData, nil
	}

	hostData.Port = port

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *FileRegistry) UpdateHostClientPrivateKey(hostName, clientPrivateKey string) (HostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return HostRegistryData{}, err
	}

	{
		newSigner, err := GetPrivateKeySignerFromString(clientPrivateKey)
		if err != nil {
			return HostRegistryData{}, err
		}

		if string(hostData.ClientPrivateKey) != "" {
			signer, _ := GetPrivateKeySignerFromString(string(hostData.ClientPrivateKey))

			if string(newSigner.PublicKey().Marshal()) == string(signer.PublicKey().Marshal()) {
				return hostData, nil
			}
		}
	}

	hostData.ClientPrivateKey = Base64ClientPrivateKey(clientPrivateKey)

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
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
		return errors.New("currently all account connected, DisconnectAll() first")
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

func (r *FileRegistry) GetConnectedHosts(userName string) map[string][]string {
	connected := map[string][]string{}
	for _, hostData := range r.GetHosts(activeFilterAll) {
		if _, ok := r.DataSource.Connected[hostData.Host]; !ok {
			continue
		}
		if ch, ok := r.DataSource.Connected[hostData.Host][userName]; !ok {
			continue
		} else {
			connected[hostData.Host] = ch.Account
		}
	}

	return connected
}
