package sault

import (
	"fmt"
	"io"
	"reflect"

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

type Registry struct {
	DataSource RegistryDataSource
}

func (r *Registry) GetType() string {
	return r.DataSource.GetType()
}

func (r *Registry) String() string {
	return r.DataSource.String()
}

func (r *Registry) Save(w io.Writer) error {
	return r.DataSource.Save(w)
}

func (r *Registry) Sync() error {
	return r.DataSource.Sync()
}

func (r *Registry) AddUser(userName, publicKey string) (UserRegistryData, error) {
	return r.DataSource.AddUser(userName, publicKey)
}

func (r *Registry) RemoveUser(userName string) error {
	return r.DataSource.RemoveUser(userName)
}

func (r *Registry) GetUserCount(f activeFilter) int {
	return r.DataSource.GetUserCount(f)
}

func (r *Registry) GetUsers(f activeFilter) map[string]UserRegistryData {
	return r.DataSource.GetUsers(f)
}

func (r *Registry) GetUserByUserName(userName string) (UserRegistryData, error) {
	return r.DataSource.GetUserByUserName(userName)
}

func (r *Registry) GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error) {
	return r.DataSource.GetUserByPublicKey(publicKey)
}

func (r *Registry) GetActiveUserByUserName(userName string) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	if userData.Deactivated {
		return UserRegistryData{}, fmt.Errorf("user, `%s`, deactivated", userName)
	}

	return
}

func (r *Registry) GetActiveUserByPublicKey(publicKey saultSsh.PublicKey) (userData UserRegistryData, err error) {
	userData, err = r.GetUserByPublicKey(publicKey)
	if err != nil {
		return
	}

	if userData.Deactivated {
		return UserRegistryData{}, fmt.Errorf("user, `%s`, deactivated", userData.User)
	}

	return
}

func (r *Registry) SetAdmin(userName string, set bool) error {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return err
	}

	userData.IsAdmin = set

	err = r.DataSource.UpdateUser(userName, userData)
	if err != nil {
		return err
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

	err = r.DataSource.UpdateUser(userName, userData)
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

	err = r.DataSource.UpdateUser(userName, userData)
	if err != nil {
		return
	}

	return userData, nil
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

	err = r.DataSource.UpdateUser(userName, userData)
	if err != nil {
		return
	}

	return userData, nil
}

func (r *Registry) AddHost(hostName, defaultAccount, address string, port uint64, accounts []string) (hostRegistryData, error) {
	if _, err := r.GetHostByHostName(hostName); err == nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s` already added", hostName)
	}

	if len(accounts) < 1 {
		accounts = append(accounts, defaultAccount)
	}

	return r.DataSource.AddHost(hostName, defaultAccount, address, port, accounts)
}

func (r *Registry) GetHostCount(f activeFilter) int {
	return r.DataSource.GetHostCount(f)
}

func (r *Registry) GetHosts(f activeFilter) map[string]hostRegistryData {
	return r.DataSource.GetHosts(f)
}

func (r *Registry) GetHostByHostName(hostName string) (hostRegistryData, error) {
	return r.DataSource.GetHostByHostName(hostName)
}

func (r *Registry) GetActiveHostByHostName(hostName string) (hostRegistryData, error) {
	return r.DataSource.GetActiveHostByHostName(hostName)
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
	err = r.DataSource.UpdateHost(hostName, hostData)
	if err != nil {
		return err
	}

	return nil
}

func (r *Registry) RemoveHost(hostName string) error {
	return r.DataSource.RemoveHost(hostName)
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
	err = r.DataSource.UpdateHost(hostName, hostData)
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
	err = r.DataSource.UpdateHost(hostName, hostData)
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

	err = r.DataSource.UpdateHost(hostName, hostData)
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
	err = r.DataSource.UpdateHost(hostName, hostData)
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
	err = r.DataSource.UpdateHost(hostName, hostData)
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

	return r.DataSource.Link(hostName, userName, targetAccounts)
}

func (r *Registry) Unlink(hostName, userName string, targetAccounts []string) (err error) {
	if _, err = r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	return r.DataSource.Unlink(hostName, userName, targetAccounts)
}

func (r *Registry) LinkAll(hostName, userName string) (err error) {
	if _, err = r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	return r.DataSource.LinkAll(hostName, userName)
}

func (r *Registry) UnlinkAll(hostName, userName string) (err error) {
	if _, err = r.GetHostByHostName(hostName); err != nil {
		return
	}

	if _, err = r.GetUserByUserName(userName); err != nil {
		return
	}

	return r.DataSource.UnlinkAll(hostName, userName)
}

func (r *Registry) IsLinkedAll(hostName, userName string) bool {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return false
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	return r.DataSource.IsLinkedAll(hostName, userName)
}

func (r *Registry) IsLinked(hostName, userName, targetAccount string) bool {
	return r.DataSource.IsLinked(hostName, userName, targetAccount)
}

func (r *Registry) GetLinkedHosts(userName string) (hosts map[string][]string) {
	if _, err := r.GetUserByUserName(userName); err != nil {
		return
	}

	for _, hostData := range r.GetHosts(activeFilterAll) {
		accounts := r.DataSource.GetLinkedAccounts(hostData.Host, userName)
		if len(accounts) < 1 {
			continue
		}
		hosts[hostData.Host] = accounts
	}

	return
}

type RegistryDataSource interface {
	GetType() string
	String() string
	Save(w io.Writer) error
	Sync() error

	AddUser(userName, publicKey string) (UserRegistryData, error)
	RemoveUser(userName string) error
	GetUserCount(f activeFilter) int
	GetUsers(f activeFilter) map[string]UserRegistryData
	GetUserByUserName(userName string) (UserRegistryData, error)
	GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error)
	UpdateUser(userName string, data UserRegistryData) error

	AddHost(
		hostName,
		defaultAccount,
		address string,
		port uint64,
		accounts []string,
	) (hostRegistryData, error)
	GetHostCount(f activeFilter) int
	GetHosts(f activeFilter) map[string]hostRegistryData
	GetHostByHostName(hostName string) (hostRegistryData, error)
	GetActiveHostByHostName(hostName string) (hostRegistryData, error)
	UpdateHost(hostName string, data hostRegistryData) error
	RemoveHost(hostName string) error

	Link(hostName, userName string, targetAccounts []string) error
	Unlink(hostName, userName string, targetAccounts []string) error
	LinkAll(hostName, userName string) error
	UnlinkAll(hostName, userName string) error
	IsLinked(hostName, userName, targetAccount string) bool
	IsLinkedAll(hostName, userName string) bool
	GetLinkedAccounts(hostName, userName string) []string
}

func NewRegistry(sourceType string, config configSourceRegistry, initialize bool) (*Registry, error) {
	var dataSource RegistryDataSource
	var err error
	switch t := sourceType; t {
	case "toml":
		dataSource, err = newTOMLRegistryDataSource(config.(configTOMLRegistry), initialize)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("registry source type, `%s` not found", t)
	}

	return &Registry{DataSource: dataSource}, nil
}
