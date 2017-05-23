package sault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/naoina/toml"
	"github.com/spikeekips/sault/ssh"
)

// UserRegistryData is the user data of registry
type UserRegistryData struct {
	User        string // must be unique
	PublicKey   string
	IsAdmin     bool
	Deactivated bool

	parsedPublicKey saultSsh.PublicKey
}

// GetPublicKey parses the public key string
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

// GetAuthorizedKey strips the public key string
func (u *UserRegistryData) GetAuthorizedKey() string {
	if u.GetPublicKey() == nil {
		return ""
	}

	return GetAuthorizedKey(u.parsedPublicKey)
}

func (u UserRegistryData) String() string {
	a := ""
	if u.IsAdmin {
		a = "*"
	}
	return fmt.Sprintf("{%s%s %s}", u.User, a, "...")
}

func (u UserRegistryData) ToJSON() []byte {
	jsoned, _ := json.Marshal(u)
	return jsoned
}

type hostRegistryData struct {
	Host           string // must be unique
	DefaultAccount string
	Accounts       []string
	Address        string
	Port           uint64
	Deactivated    bool
}

func (p hostRegistryData) String() string {
	return fmt.Sprintf("{%s %s %s %d %s}", p.Host, p.DefaultAccount, p.Address, p.Port, "...")
}

func (p hostRegistryData) GetPort() uint64 {
	port := p.Port
	if p.Port < 1 {
		port = 22
	}

	return port
}

func (p hostRegistryData) GetFullAddress() string {
	return fmt.Sprintf("%s:%d", p.Address, p.GetPort())
}

type linkedUserRegistryData struct {
	Accounts []string
}

type registryData struct {
	User   map[string]UserRegistryData
	Host   map[string]hostRegistryData
	Linked map[string]map[string]linkedUserRegistryData
}

type Registry struct {
	d      *registryData
	source RegistryDataSource
}

func (r *Registry) GetType() string {
	return r.source.GetType()
}

func (r *Registry) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	toml.NewEncoder(b).Encode(r.d)

	return b.Bytes()
}

func (r *Registry) Save() error {
	return r.source.Save(r.Bytes())
}

func (r *Registry) AddUser(userName, publicKey string) (userData UserRegistryData, err error) {
	if !CheckUserName(userName) {
		err = fmt.Errorf("invalid userName, '%s'", userName)
		return
	}

	if _, err = r.GetUserByUserName(userName); err == nil {
		err = fmt.Errorf("user, '%s' already added", userName)
		return
	}

	var parsedPublicKey saultSsh.PublicKey
	parsedPublicKey, err = ParsePublicKeyFromString(publicKey)
	if err != nil {
		err = fmt.Errorf("invalid publicKey '%s': %v", publicKey, err)
		return
	}

	if _, err = r.GetUserByPublicKey(parsedPublicKey); err == nil {
		err = fmt.Errorf("publicKey, '%s' already added", strings.TrimSpace(publicKey))
		return
	}
	err = nil

	userData = UserRegistryData{
		User:      userName,
		PublicKey: strings.TrimSpace(publicKey),
	}
	r.d.User[userName] = userData

	return

}

func (r *Registry) RemoveUser(userName string) error {
	_, ok := r.d.User[userName]
	if !ok {
		return fmt.Errorf("user, '%s', not found", userName)
	}

	delete(r.d.User, userName)

	for hostName, users := range r.d.Linked {
		if _, ok := users[userName]; !ok {
			continue
		}
		delete(r.d.Linked[hostName], userName)
	}

	return nil
}

func (r *Registry) GetUserCount(f activeFilter) (c int) {
	switch f {
	case activeFilterAll:
		c = len(r.d.User)
		return
	default:
		for _, u := range r.d.User {
			if u.Deactivated && f == activeFilterDeactivated {
				c++
			} else if !u.Deactivated && f == activeFilterActive {
				c++
			}
		}
	}

	return
}

func (r *Registry) GetUsers(f activeFilter) (users map[string]UserRegistryData) {
	users = map[string]UserRegistryData{}

	switch f {
	case activeFilterAll:
		users = r.d.User
		return
	default:
		for userName, u := range r.d.User {
			if u.Deactivated && f == activeFilterDeactivated {
				users[userName] = u
			} else if !u.Deactivated && f == activeFilterActive {
				users[userName] = u
			}
		}
	}

	return
}

func (r *Registry) GetUserByUserName(userName string) (userData UserRegistryData, err error) {
	var ok bool
	if userData, ok = r.d.User[userName]; !ok {
		err = fmt.Errorf("user, '%s', not found", userName)
		return
	}

	return
}

func (r *Registry) GetUserByPublicKey(publicKey saultSsh.PublicKey) (userData UserRegistryData, err error) {
	authorizedKey := GetAuthorizedKey(publicKey)

	var matchedUserData *UserRegistryData
	for _, ud := range r.d.User {
		userAuthorizedKey := ud.GetAuthorizedKey()
		if userAuthorizedKey == "" {
			log.Errorf("invalid publicKey for '%s', %v: %v", ud.User, ud.PublicKey)
			continue
		}
		if userAuthorizedKey == authorizedKey {
			matchedUserData = &ud
			break
		}
	}
	if matchedUserData == nil {
		err = fmt.Errorf("user with the publickey, not found: %v", authorizedKey)
		return
	}

	userData = *matchedUserData
	return
}

func (r *Registry) GetActiveUserByUserName(userName string) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	if userData.Deactivated {
		err = fmt.Errorf("user, '%s', deactivated", userName)
		return
	}

	return
}

func (r *Registry) GetActiveUserByPublicKey(publicKey saultSsh.PublicKey) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByPublicKey(publicKey)
	if err != nil {
		return
	}

	if userData.Deactivated {
		err = fmt.Errorf("user, '%s', deactivated", userData.User)
		return
	}

	return
}

func (r *Registry) SetAdmin(userName string, set bool) error {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return err
	}

	userData.IsAdmin = set

	err = r.UpdateUser(userName, userData)
	if err != nil {
		return err
	}

	return nil
}

func (r *Registry) UpdateUser(userName string, newUserData UserRegistryData) (err error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	old, _ := json.Marshal(userData)
	new, _ := json.Marshal(newUserData)
	if string(old) == string(new) {
		return
	}

	r.d.User[newUserData.User] = newUserData
	if userName == newUserData.User {
		return nil
	}

	delete(r.d.User, userName)

	for hostName, users := range r.d.Linked {
		if _, ok := users[userName]; !ok {
			continue
		}
		r.d.Linked[hostName][newUserData.User] = r.d.Linked[hostName][userName]

		delete(r.d.Linked[hostName], userName)
	}

	return nil
}

func (r *Registry) IsUserActive(userName string) (active bool, err error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	return !userData.Deactivated, nil
}

func (r *Registry) SetUserActive(userName string, active bool) error {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return err
	}

	if !userData.Deactivated == active {
		return nil
	}

	userData.Deactivated = !active

	err = r.UpdateUser(userName, userData)
	if err != nil {
		return err
	}

	return nil
}

func (r *Registry) UpdateUserName(userName, newUserName string) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	if _, err = r.GetUserByUserName(newUserName); err == nil {
		err = fmt.Errorf("new userName, '%s' already exits", newUserName)
		return
	}

	userData.User = newUserName

	err = r.UpdateUser(userName, userData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) UpdateUserPublicKey(userName string, newPublicKey string) (userData UserRegistryData, err error) {
	var publicKey saultSsh.PublicKey
	publicKey, err = ParsePublicKeyFromString(newPublicKey)
	if err != nil {
		return
	}

	userData, err = r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	if userData.PublicKey == newPublicKey {
		return
	}

	if another, err := r.GetUserByPublicKey(publicKey); err == nil && another.User != userData.User {
		return UserRegistryData{}, fmt.Errorf("another user has same publicKey")
	}

	userData.PublicKey = newPublicKey
	userData.parsedPublicKey = nil

	err = r.UpdateUser(userName, userData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) AddHost(hostName, defaultAccount, address string, port uint64, accounts []string) (
	hostData hostRegistryData,
	err error,
) {
	if !CheckHostName(hostName) {
		err = fmt.Errorf("invalid hostName, '%s'", hostName)
		return
	}

	if _, err = r.GetHostByHostName(hostName); err == nil {
		err = fmt.Errorf("hostName, '%s' already added", hostName)
		return
	}
	err = nil

	if len(accounts) < 1 {
		accounts = append(accounts, defaultAccount)
	}

	hostData = hostRegistryData{
		Host:           hostName,
		DefaultAccount: defaultAccount,
		Address:        address,
		Port:           port,
		Accounts:       accounts,
	}

	r.d.Host[hostName] = hostData

	return
}

func (r *Registry) GetHostCount(f activeFilter) (c int) {
	switch f {
	case activeFilterAll:
		c = len(r.d.Host)
		return
	default:
		for _, u := range r.d.Host {
			if u.Deactivated && f == activeFilterDeactivated {
				c++
			} else if !u.Deactivated && f == activeFilterActive {
				c++
			}
		}
	}

	return
}

func (r *Registry) GetHosts(f activeFilter) (hosts map[string]hostRegistryData) {
	if f == activeFilterAll {
		return r.d.Host
	}

	hosts = map[string]hostRegistryData{}
	for _, h := range r.d.Host {
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

func (r *Registry) GetHostByHostName(hostName string) (hostData hostRegistryData, err error) {
	var matchedHostData *hostRegistryData
	for _, hd := range r.d.Host {
		if hostName == hd.Host {
			matchedHostData = &hd
			break
		}
	}
	if matchedHostData == nil {
		err = fmt.Errorf("host, '%s' not found", hostName)
		return
	}

	hostData = *matchedHostData
	return
}

func (r *Registry) GetActiveHostByHostName(hostName string) (hostData hostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}
	if hostData.Deactivated {
		err = fmt.Errorf("host, '%s', deactivated", hostData.Host)
		return
	}

	return
}

func (r *Registry) IsHostActive(hostName string) (bool, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return false, err
	}

	return !hostData.Deactivated, nil
}

func (r *Registry) SetHostActive(hostName string, active bool) error {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return err
	}

	if !hostData.Deactivated == active {
		return nil
	}

	hostData.Deactivated = !active
	err = r.UpdateHost(hostName, hostData)
	if err != nil {
		return err
	}

	return nil
}

func (r *Registry) UpdateHost(hostName string, newHostData hostRegistryData) (err error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	old, _ := json.Marshal(hostData)
	new, _ := json.Marshal(newHostData)
	if string(old) == string(new) {
		return
	}

	r.d.Host[newHostData.Host] = newHostData
	if hostName == newHostData.Host {
		return nil
	}

	delete(r.d.Host, hostName)

	if _, ok := r.d.Linked[hostName]; ok {
		r.d.Linked[newHostData.Host] = r.d.Linked[hostName]
		delete(r.d.Linked, hostName)
	}

	return
}

func (r *Registry) RemoveHost(hostName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("host, '%s', not found", hostName)
	}

	delete(r.d.Host, hostName)

	if _, ok := r.d.Linked[hostName]; ok {
		delete(r.d.Linked, hostName)
	}

	return nil
}

func (r *Registry) UpdateHostName(hostName, newHostName string) (hostData hostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	if _, err = r.GetHostByHostName(newHostName); err == nil {
		err = fmt.Errorf("new hostName, '%s' already exits", newHostName)
		return
	}

	hostData.Host = newHostName
	err = r.UpdateHost(hostName, hostData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) UpdateHostDefaultAccount(hostName, defaultAccount string) (hostData hostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	var accounts []string
	var found bool
	for _, a := range hostData.Accounts {
		if a == hostData.DefaultAccount {
			continue
		} else if a == defaultAccount {
			found = true
		}
		accounts = append(accounts)
	}
	if !found {
		accounts = append(accounts, defaultAccount)
	}

	hostData.DefaultAccount = defaultAccount
	hostData.Accounts = accounts
	err = r.UpdateHost(hostName, hostData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) UpdateHostAccounts(hostName string, accounts []string) (hostData hostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	if reflect.DeepEqual(accounts, hostData.Accounts) {
		return
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

	err = r.UpdateHost(hostName, hostData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) UpdateHostAddress(hostName, address string) (hostData hostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	if hostData.Address == address {
		return
	}

	hostData.Address = address
	err = r.UpdateHost(hostName, hostData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) UpdateHostPort(hostName string, port uint64) (hostData hostRegistryData, err error) {
	hostData, err = r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	if hostData.Port == port {
		return
	}

	hostData.Port = port
	err = r.UpdateHost(hostName, hostData)
	if err != nil {
		return
	}

	return
}

func (r *Registry) Link(hostName, userName string, targetAccounts []string) (err error) {
	if r.IsLinkedAll(hostName, userName) {
		return
	}

	if _, err = r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	_, ok := r.d.Linked[hostName]
	if !ok {
		r.d.Linked[hostName] = map[string]linkedUserRegistryData{}
	}
	uc, ok := r.d.Linked[hostName][userName]
	if !ok {
		r.d.Linked[hostName][userName] = linkedUserRegistryData{Accounts: targetAccounts}
		return nil
	}

	var filtered []string
	filtered = append(filtered, uc.Accounts...)
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

	r.d.Linked[hostName][userName] = linkedUserRegistryData{Accounts: filtered}

	return nil
}

func (r *Registry) Unlink(hostName, userName string, targetAccounts []string) (err error) {
	if _, err = r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	_, ok := r.d.Linked[hostName]
	if !ok {
		return nil
	}
	uc, ok := r.d.Linked[hostName][userName]
	if !ok {
		return nil
	}

	var filtered []string
	for _, a := range uc.Accounts {
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

	if len(filtered) < 1 {
		delete(r.d.Linked[hostName], userName)
	} else {
		r.d.Linked[hostName][userName] = linkedUserRegistryData{Accounts: filtered}
	}

	return
}

func (r *Registry) LinkAll(hostName, userName string) (err error) {
	var hostData hostRegistryData
	{
		if hostData, err = r.GetHostByHostName(hostName); err != nil {
			return
		}
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	_, ok := r.d.Linked[hostName]
	if !ok {
		r.d.Linked[hostName] = map[string]linkedUserRegistryData{}
	}
	r.d.Linked[hostName][userName] = linkedUserRegistryData{Accounts: hostData.Accounts}

	return nil
}

func (r *Registry) UnlinkAll(hostName, userName string) (err error) {
	if _, err = r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	_, ok := r.d.Linked[hostName]
	if !ok {
		return
	}
	delete(r.d.Linked[hostName], userName)

	return
}

func (r *Registry) IsLinkedAll(hostName, userName string) bool {
	var hostData hostRegistryData
	{
		var err error
		if hostData, err = r.GetHostByHostName(hostName); err != nil {
			return false
		}
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	_, ok := r.d.Linked[hostName]
	if !ok {
		return false
	}
	uc, ok := r.d.Linked[hostName][userName]
	if !ok {
		return false
	}

	for _, a := range hostData.Accounts {
		var found bool
		for _, b := range uc.Accounts {
			if a == b {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (r *Registry) IsLinked(hostName, userName, targetAccount string) bool {
	if r.IsLinkedAll(hostName, userName) {
		return true
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return false
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	_, ok := r.d.Linked[hostName]
	if !ok {
		return false
	}
	uc, ok := r.d.Linked[hostName][userName]
	if !ok {
		return false
	}

	for _, a := range uc.Accounts {
		if a == targetAccount {
			return true
		}
	}

	return false
}

func (r *Registry) GetLinkedHosts(userName string) (hosts map[string][]string) {
	if _, err := r.GetUserByUserName(userName); err != nil {
		return
	}

	for _, hostData := range r.GetHosts(activeFilterAll) {
		accounts := r.GetLinkedAccounts(hostData.Host, userName)
		if len(accounts) < 1 {
			continue
		}
		hosts[hostData.Host] = accounts
	}

	return
}

func (r *Registry) GetLinkedAccounts(hostName, userName string) (accounts []string) {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return
	}

	if _, ok := r.d.Linked[hostName]; !ok {
		return
	}
	if _, ok := r.d.Linked[hostName][userName]; !ok {
		return
	}
	accounts = r.d.Linked[hostName][userName].Accounts
	return
}

type RegistryDataSource interface {
	GetType() string
	Bytes() ([]byte, error)
	Save(content []byte) error
}

func newRegistry(sourceType string, config configSourceRegistry, initialize bool) (registry *Registry, err error) {
	var source RegistryDataSource
	switch t := sourceType; t {
	case "toml":
		source, err = newTOMLRegistry(config.(configTOMLRegistry), initialize)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("registry source type, '%s' not found", t)
		return
	}

	d := &registryData{
		User:   map[string]UserRegistryData{},
		Host:   map[string]hostRegistryData{},
		Linked: map[string]map[string]linkedUserRegistryData{},
	}

	var content []byte
	content, err = source.Bytes()
	if err != nil {
		return
	}
	if err = defaultTOML.NewDecoder(bytes.NewReader(content)).Decode(d); err != nil {
		return
	}

	return &Registry{d: d, source: source}, nil
}
