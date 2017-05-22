package sault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/naoina/toml"
	"github.com/spikeekips/sault/ssh"
)

type tomlLinkedUserRegistryData struct {
	Account []string
}

type tomlRegistryData struct {
	User   map[string]UserRegistryData
	Host   map[string]hostRegistryData
	Linked map[string]map[string]tomlLinkedUserRegistryData
}

type tomlRegistry struct {
	Path string
	Data *tomlRegistryData
}

func (r *tomlRegistry) marshal() *bytes.Buffer {
	b := bytes.NewBuffer([]byte{})
	toml.NewEncoder(b).Encode(r.Data)

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
	return toml.NewEncoder(w).Encode(r.Data)
}

func newTOMLRegistryDataSource(config configTOMLRegistry, initialize bool) (*tomlRegistry, error) {
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

	dataSource := &tomlRegistryData{
		User:   map[string]UserRegistryData{},
		Host:   map[string]hostRegistryData{},
		Linked: map[string]map[string]tomlLinkedUserRegistryData{},
	}

	if err := defaultTOML.NewDecoder(f).Decode(dataSource); err != nil {
		return nil, err
	}
	r.Data = dataSource

	return &r, nil
}

func (r *tomlRegistry) GetType() string {
	return "toml"
}

func (r *tomlRegistry) GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error) {
	authorizedKey := GetAuthorizedKey(publicKey)

	var matchedUserData *UserRegistryData
	for _, userData := range r.Data.User {
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
		return UserRegistryData{}, fmt.Errorf("user with the publickey, not found: %v", authorizedKey)
	}

	return *matchedUserData, nil
}

func (r *tomlRegistry) GetHostByHostName(hostName string) (hostRegistryData, error) {
	var matchedHostData *hostRegistryData
	for _, hostData := range r.Data.Host {
		if hostName == hostData.Host {
			matchedHostData = &hostData
			break
		}
	}
	if matchedHostData == nil {
		return hostRegistryData{}, fmt.Errorf("host, `%s` not found", hostName)
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

func (r *tomlRegistry) SetHostActive(hostName string, active bool) error {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return err
	}

	if !hostData.Deactivated == active {
		return nil
	}

	hostData.Deactivated = !active
	r.Data.Host[hostName] = hostData

	return nil
}

func (r *tomlRegistry) GetHosts(f activeFilter) (hosts map[string]hostRegistryData) {
	if f == activeFilterAll {
		return r.Data.Host
	}

	hosts = map[string]hostRegistryData{}
	for _, h := range r.Data.Host {
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
		c = len(r.Data.User)
		return
	default:
		for _, u := range r.Data.User {
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
		users = r.Data.User
		return
	default:
		for userName, u := range r.Data.User {
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
	userData, ok := r.Data.User[userName]
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
	r.Data.User[userName] = userData

	return userData, nil
}

func (r *tomlRegistry) RemoveUser(userName string) error {
	_, ok := r.Data.User[userName]
	if !ok {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	delete(r.Data.User, userName)

	for hostName, users := range r.Data.Linked {
		if _, ok := users[userName]; !ok {
			continue
		}
		delete(r.Data.Linked[hostName], userName)
	}

	return nil
}

func (r *tomlRegistry) UpdateUser(userName string, newUserData UserRegistryData) (err error) {
	userData, err := r.GetUserByUserName(userName)
	if err != nil {
		return
	}

	old, _ := json.Marshal(userData)
	new, _ := json.Marshal(newUserData)
	if string(old) == string(new) {
		return
	}

	r.Data.User[newUserData.User] = newUserData
	if userName == newUserData.User {
		return nil
	}

	delete(r.Data.User, userName)

	for hostName, users := range r.Data.Linked {
		if _, ok := users[userName]; !ok {
			continue
		}
		r.Data.Linked[hostName][newUserData.User] = r.Data.Linked[hostName][userName]

		delete(r.Data.Linked[hostName], userName)
	}

	return nil
}

func (r *tomlRegistry) AddHost(
	hostName,
	defaultAccount,
	address string,
	port uint64,
	accounts []string,
) (hostRegistryData, error) {
	hostData := hostRegistryData{
		Host:           hostName,
		DefaultAccount: defaultAccount,
		Address:        address,
		Port:           port,
		Accounts:       accounts,
	}

	r.Data.Host[hostName] = hostData

	return hostData, nil
}

func (r *tomlRegistry) GetHostCount(f activeFilter) (c int) {
	switch f {
	case activeFilterAll:
		c = len(r.Data.Host)
	default:
		for _, u := range r.Data.Host {
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

	delete(r.Data.Host, hostName)

	if _, ok := r.Data.Linked[hostName]; ok {
		delete(r.Data.Linked, hostName)
	}

	return nil
}

func (r *tomlRegistry) UpdateHost(hostName string, newHostData hostRegistryData) (err error) {
	hostData, err := r.GetHostByHostName(hostName)
	if err != nil {
		return
	}

	old, _ := json.Marshal(hostData)
	new, _ := json.Marshal(newHostData)
	if string(old) == string(new) {
		return
	}

	r.Data.Host[newHostData.Host] = newHostData
	if hostName == newHostData.Host {
		return nil
	}

	delete(r.Data.Host, hostName)

	if _, ok := r.Data.Linked[hostName]; ok {
		r.Data.Linked[newHostData.Host] = r.Data.Linked[hostName]
		delete(r.Data.Linked, hostName)
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

	delete(r.Data.Host, hostName)
	r.Data.Host[newHostName] = hostData

	if _, ok := r.Data.Linked[hostName]; ok {
		r.Data.Linked[newHostName] = r.Data.Linked[hostName]
		delete(r.Data.Linked, hostName)
	}

	return hostData, nil
}

func (r *tomlRegistry) IsLinkedAll(hostName, userName string) bool {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return false
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	_, ok := r.Data.Linked[hostName]
	if !ok {
		return false
	}
	uc, ok := r.Data.Linked[hostName][userName]
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

func (r *tomlRegistry) IsLinked(hostName, userName, targetAccount string) bool {
	if r.IsLinkedAll(hostName, userName) {
		return true
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return false
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return false
	}

	_, ok := r.Data.Linked[hostName]
	if !ok {
		return false
	}
	uc, ok := r.Data.Linked[hostName][userName]
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

func (r *tomlRegistry) LinkAll(hostName, userName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.Data.Linked[hostName]
	if !ok {
		r.Data.Linked[hostName] = map[string]tomlLinkedUserRegistryData{}
	}
	r.Data.Linked[hostName][userName] = tomlLinkedUserRegistryData{Account: []string{"*"}}

	return nil
}

func (r *tomlRegistry) Link(hostName, userName string, targetAccounts []string) error {
	if r.IsLinkedAll(hostName, userName) {
		return nil
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.Data.Linked[hostName]
	if !ok {
		r.Data.Linked[hostName] = map[string]tomlLinkedUserRegistryData{}
	}
	uc, ok := r.Data.Linked[hostName][userName]
	if !ok {
		r.Data.Linked[hostName][userName] = tomlLinkedUserRegistryData{Account: targetAccounts}
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

	r.Data.Linked[hostName][userName] = tomlLinkedUserRegistryData{Account: filtered}

	return nil
}
func (r *tomlRegistry) Unlink(hostName, userName string, targetAccounts []string) error {
	if r.IsLinkedAll(hostName, userName) {
		return errors.New("currently all account linked, UnlinkAll() first")
	}

	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.Data.Linked[hostName]
	if !ok {
		return nil
	}
	uc, ok := r.Data.Linked[hostName][userName]
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

	if len(filtered) < 1 {
		delete(r.Data.Linked[hostName], userName)
	} else {
		r.Data.Linked[hostName][userName] = tomlLinkedUserRegistryData{Account: filtered}
	}

	return nil
}

func (r *tomlRegistry) UnlinkAll(hostName, userName string) error {
	if _, err := r.GetHostByHostName(hostName); err != nil {
		return fmt.Errorf("hostName, `%s`, not found", hostName)
	}

	if _, err := r.GetUserByUserName(userName); err != nil {
		return fmt.Errorf("userName, `%s`, not found", userName)
	}

	_, ok := r.Data.Linked[hostName]
	if !ok {
		return nil
	}
	delete(r.Data.Linked[hostName], userName)

	return nil
}

func (r *tomlRegistry) GetLinkedHosts(userName string) map[string][]string {
	linked := map[string][]string{}
	for _, hostData := range r.GetHosts(activeFilterAll) {
		if _, ok := r.Data.Linked[hostData.Host]; !ok {
			continue
		}
		if ch, ok := r.Data.Linked[hostData.Host][userName]; !ok {
			continue
		} else {
			linked[hostData.Host] = ch.Account
		}
	}

	return linked
}
