package sault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/naoina/toml"
	"github.com/spikeekips/sault/ssh"
)

type tomlConnectedUserRegistryData struct {
	Account []string
}

type tomlRegistryDataSource struct {
	User      map[string]UserRegistryData
	Host      map[string]hostRegistryData
	Connected map[string]map[string]tomlConnectedUserRegistryData
}

type tomlRegistry struct {
	Path       string
	DataSource *tomlRegistryDataSource
}

func (r *tomlRegistry) marshal() *bytes.Buffer {
	b := bytes.NewBuffer([]byte{})
	toml.NewEncoder(b).Encode(r.DataSource)

	return b
}

func (r *tomlRegistry) Bytes() []byte {
	return r.marshal().Bytes()
}

func (r *tomlRegistry) String() string {
	return strings.TrimSpace(r.marshal().String())
}

func (r *tomlRegistry) Sync() error {
	os.Remove(r.Path)
	tomlFile, err := os.OpenFile(r.Path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer tomlFile.Close()

	return r.Save(tomlFile)
}

func (r *tomlRegistry) Save(w io.Writer) error {
	return toml.NewEncoder(w).Encode(r.DataSource)
}

func newTOMLRegistry(config configTOMLRegistry, initialize bool) (*tomlRegistry, error) {
	r := tomlRegistry{Path: config.Path}

	if initialize {
		f, err := os.OpenFile(config.Path, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}

	f, err := os.Open(config.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dataSource := &tomlRegistryDataSource{
		User:      map[string]UserRegistryData{},
		Host:      map[string]hostRegistryData{},
		Connected: map[string]map[string]tomlConnectedUserRegistryData{},
	}
	if err := toml.NewDecoder(f).Decode(dataSource); err != nil {
		return nil, err
	}
	r.DataSource = dataSource

	return &r, nil
}

func (r *tomlRegistry) GetType() string {
	return "toml"
}

func (r *tomlRegistry) GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error) {
	authorizedKey := GetAuthorizedKey(publicKey)

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

func (r *tomlRegistry) GetActiveUserByPublicKey(publicKey saultSsh.PublicKey) (userData UserRegistryData, err error) {
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

func (r *tomlRegistry) GetHostByHostName(hostName string) (hostRegistryData, error) {
	var matchedHostData *hostRegistryData
	for _, hostData := range r.DataSource.Host {
		if hostName == hostData.Host {
			matchedHostData = &hostData
			break
		}
	}
	if matchedHostData == nil {
		return hostRegistryData{}, fmt.Errorf("HostData not found")
	}

	return *matchedHostData, nil
}

func (r *tomlRegistry) GetActiveHostByHostName(hostName string) (hostData hostRegistryData, err error) {
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

func (r *tomlRegistry) IsHostActive(hostName string) (bool, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return false, err
	}

	return !hostData.Deactivated, nil
}

func (r *tomlRegistry) SetHostActive(hostName string, active bool) error {
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

func (r *tomlRegistry) GetHosts(f activeFilter) (hosts map[string]hostRegistryData) {
	if f == activeFilterAll {
		return r.DataSource.Host
	}

	hosts = map[string]hostRegistryData{}
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

func (r *tomlRegistry) GetUserCount(f activeFilter) (c int) {
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

func (r *tomlRegistry) GetUsers(f activeFilter) (users map[string]UserRegistryData) {
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

func (r *tomlRegistry) GetUserByUserName(userName string) (UserRegistryData, error) {
	userData, ok := r.DataSource.User[userName]
	if !ok {
		return UserRegistryData{}, fmt.Errorf("user with userName, `%s`, not found", userName)
	}

	return userData, nil
}

func (r *tomlRegistry) AddUser(userName, publicKey string) (UserRegistryData, error) {
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

func (r *tomlRegistry) GetActiveUserByUserName(userName string) (userData UserRegistryData, err error) {
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

func (r *tomlRegistry) RemoveUser(userName string) error {
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

func (r *tomlRegistry) SetAdmin(userName string, set bool) error {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return err
	}

	userData.IsAdmin = set
	r.DataSource.User[userName] = userData

	return nil
}

func (r *tomlRegistry) IsUserActive(userName string) (bool, error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return false, err
	}

	return !userData.Deactivated, nil
}

func (r *tomlRegistry) SetUserActive(userName string, active bool) error {
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

func (r *tomlRegistry) UpdateUserName(userName, newUserName string) (UserRegistryData, error) {
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

func (r *tomlRegistry) UpdateUserPublicKey(userName, newPublicKey string) (UserRegistryData, error) {
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

func (r *tomlRegistry) AddHost(
	hostName,
	defaultAccount,
	address string,
	port uint64,
	clientPrivateKey string,
	accounts []string,
) (hostRegistryData, error) {
	if clientPrivateKey != "" {
		if _, err := GetPrivateKeySignerFromString(clientPrivateKey); err != nil {
			return hostRegistryData{}, fmt.Errorf("invalid clientPrivateKey: %v", err)
		}
	}

	if _, err := r.GetHostByHostName(hostName); err == nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s` already added", hostName)
	}

	if len(accounts) < 1 {
		accounts = append(accounts, defaultAccount)
	}

	hostData := hostRegistryData{
		Host:           hostName,
		DefaultAccount: defaultAccount,
		Address:        address,
		Port:           port,
		Accounts:       accounts,
	}
	if clientPrivateKey != "" {
		if _, err := GetPrivateKeySignerFromString(clientPrivateKey); err != nil {
			return hostRegistryData{}, err
		}
		hostData.ClientPrivateKey = Base64ClientPrivateKey(clientPrivateKey)
	}

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *tomlRegistry) GetHostCount(f activeFilter) (c int) {
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

func (r *tomlRegistry) RemoveHost(hostName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	delete(r.DataSource.Host, hostName)

	if _, ok := r.DataSource.Connected[hostName]; ok {
		delete(r.DataSource.Connected, hostName)
	}

	return nil
}

func (r *tomlRegistry) UpdateHostName(hostName, newHostName string) (hostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}
	if hostName == newHostName {
		return hostRegistryData{}, nil
	}

	if _, err := r.GetHostByHostName(newHostName); err == nil {
		return hostRegistryData{}, fmt.Errorf("newHostName, `%s`, already exists", newHostName)
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

func (r *tomlRegistry) UpdateHostDefaultAccount(hostName, defaultAccount string) (hostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
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

func (r *tomlRegistry) UpdateHostAccounts(hostName string, accounts []string) (hostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
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

func (r *tomlRegistry) UpdateHostAddress(hostName, address string) (hostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if address == hostData.Address {
		return hostData, nil
	}

	hostData.Address = address

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *tomlRegistry) UpdateHostPort(hostName string, port uint64) (hostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return hostRegistryData{}, fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if port == hostData.Port {
		return hostData, nil
	}

	hostData.Port = port

	r.DataSource.Host[hostName] = hostData

	return hostData, nil
}

func (r *tomlRegistry) UpdateHostClientPrivateKey(hostName, clientPrivateKey string) (hostRegistryData, error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return hostRegistryData{}, err
	}

	{
		newSigner, err := GetPrivateKeySignerFromString(clientPrivateKey)
		if err != nil {
			return hostRegistryData{}, err
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

func (r *tomlRegistry) IsConnectedAll(hostName, userName string) bool {
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

func (r *tomlRegistry) IsConnected(hostName, userName, targetAccount string) bool {
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

func (r *tomlRegistry) ConnectAll(hostName, userName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.DataSource.Connected[hostName]
	if !ok {
		r.DataSource.Connected[hostName] = map[string]tomlConnectedUserRegistryData{}
	}
	r.DataSource.Connected[hostName][userName] = tomlConnectedUserRegistryData{Account: []string{"*"}}

	return nil
}

func (r *tomlRegistry) Connect(hostName, userName string, targetAccounts []string) error {
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
		r.DataSource.Connected[hostName] = map[string]tomlConnectedUserRegistryData{}
	}
	uc, ok := r.DataSource.Connected[hostName][userName]
	if !ok {
		r.DataSource.Connected[hostName][userName] = tomlConnectedUserRegistryData{Account: targetAccounts}
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

	r.DataSource.Connected[hostName][userName] = tomlConnectedUserRegistryData{Account: filtered}

	return nil
}
func (r *tomlRegistry) Disconnect(hostName, userName string, targetAccounts []string) error {
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

	r.DataSource.Connected[hostName][userName] = tomlConnectedUserRegistryData{Account: filtered}

	return nil
}

func (r *tomlRegistry) DisconnectAll(hostName, userName string) error {
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

func (r *tomlRegistry) GetConnectedHosts(userName string) map[string][]string {
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
