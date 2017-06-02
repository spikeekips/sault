package saultregistry

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/sssh"
)

type UserFilter byte
type HostFilter byte

const (
	UserFilterNone UserFilter = 1 << iota
	UserFilterIsNotActive
	UserFilterIsAdmin
)

const (
	HostFilterNone HostFilter = 1 << iota
	HostFilterIsNotActive
)

type InvalidUserIDError struct {
	ID string
}

func (e *InvalidUserIDError) Error() string {
	return fmt.Sprintf("invalid user.ID, '%s'", e.ID)
}

type HostAndUserNotLinked struct {
	UserID string
	HostID string
}

func (e *HostAndUserNotLinked) Error() string {
	return fmt.Sprintf("user, '%s' and host, '%s' was not linked", e.UserID, e.HostID)
}

type InvalidHostAddressError struct {
	Address string
	Err     error
}

func (e *InvalidHostAddressError) Error() string {
	return fmt.Sprintf("invalid host.Address, '%s': %v", e.Address, e.Err)
}

type UserDoesNotExistError struct {
	ID        string
	PublicKey sssh.PublicKey
	Message   string
}

func (e *UserDoesNotExistError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	var v []string
	if e.ID != "" {
		v = append(v, fmt.Sprintf("id='%s'", e.ID))
	}
	if e.PublicKey != nil {
		v = append(v, fmt.Sprintf("publicKey='%s'", saultcommon.FingerprintSHA256PublicKey(e.PublicKey)))
	}

	return fmt.Sprintf("user, %s does not exist", strings.Join(v, " "))
}

type HostDoesNotExistError struct {
	ID      string
	Message string
}

func (e *HostDoesNotExistError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return fmt.Sprintf("host, '%s' does not exist", e.ID)
}

type UserExistsError struct {
	ID        string
	PublicKey string
}

func (e *UserExistsError) Error() string {
	var v []string
	if e.ID != "" {
		v = append(v, fmt.Sprintf("id='%s'", e.ID))
	}
	if e.PublicKey != "" {
		v = append(v, fmt.Sprintf("publicKey='%s'", e.PublicKey))
	}

	return fmt.Sprintf("user, %v already exists", v)
}

type HostExistError struct {
	ID string
}

func (e *HostExistError) Error() string {
	return fmt.Sprintf("host, '%s' already exists", e.ID)
}

type LinkedAllError struct {
}

func (e *LinkedAllError) Error() string {
	return "Linked all"
}

type UserRegistry struct {
	ID        string
	PublicKey string
	publicKey sssh.PublicKey

	IsAdmin     bool
	IsActive    bool
	DateAdded   time.Time
	DateUpdated time.Time
}

func (r UserRegistry) String() string {
	return fmt.Sprintf(
		"user=%s(%s)",
		r.ID,
		saultcommon.FingerprintSHA256PublicKey(r.GetPublicKey()),
	)
}

func (r UserRegistry) HasPublicKey(publicKey sssh.PublicKey) bool {
	return r.GetAuthorizedKey() == saultcommon.GetAuthorizedKey(publicKey)
}

func (r UserRegistry) GetPublicKey() sssh.PublicKey {
	p, _ := saultcommon.ParsePublicKeyFromString(r.PublicKey)

	return p
}

func (r UserRegistry) GetAuthorizedKey() string {
	return saultcommon.GetAuthorizedKey(r.GetPublicKey())
}

type LinkAccountRegistry struct {
	Accounts []string
	All      bool
}

type HostRegistry struct {
	ID       string
	Address  string
	Accounts []string

	IsActive    bool
	DateAdded   time.Time
	DateUpdated time.Time
}

func (r HostRegistry) String() string {
	return fmt.Sprintf(
		"host=%s(%s)",
		r.ID,
		r.Address,
	)
}

type RegistryData struct {
	TimeUpdated time.Time
	User        map[string]UserRegistry                   // map[<UserRegistry.ID>]UserRegistry
	Host        map[string]HostRegistry                   // map[<hostRegistry.ID>]hostRegistry
	Links       map[string]map[string]LinkAccountRegistry // map[hostRegistry.ID]map[<UserRegistry.ID>]<AccountRegistry>
}

func (d *RegistryData) updated() {
	d.TimeUpdated = time.Now()
}

func NewRegistryDataFromSource(source RegistrySource) (data *RegistryData, err error) {
	var b []byte
	b, err = source.Bytes()
	if err != nil {
		return
	}

	data = &RegistryData{
		User:  map[string]UserRegistry{},
		Host:  map[string]HostRegistry{},
		Links: map[string]map[string]LinkAccountRegistry{},
	}

	if err = saultcommon.DefaultTOML.NewDecoder(bytes.NewBuffer(b)).Decode(data); err != nil {
		return
	}

	return
}

func (registry *Registry) GetUserCount(f UserFilter) (c int) {
	for _, u := range registry.Data.User {
		if f&UserFilterIsNotActive == UserFilterIsNotActive && u.IsActive {
			continue
		}
		if f&UserFilterIsAdmin == UserFilterIsAdmin && !u.IsAdmin {
			continue
		}
		c++
	}

	return c
}

func (registry *Registry) GetUser(id string, publicKey sssh.PublicKey, f UserFilter) (user UserRegistry, err error) {
	user, err = registry.getUser(id, publicKey)
	if err != nil {
		return
	}

	if f == UserFilterNone {
		return
	}

	if f&UserFilterIsNotActive == UserFilterIsNotActive {
		if user.IsActive {
			user = UserRegistry{}
			err = &UserDoesNotExistError{Message: fmt.Sprintf("user, '%s' is active", user.ID)}
			return
		}
	}

	if f&UserFilterIsAdmin == UserFilterIsAdmin {
		if !user.IsAdmin {
			user = UserRegistry{}
			err = &UserDoesNotExistError{Message: fmt.Sprintf("user, '%s' is not admin", user.ID)}
			return
		}
	}

	return
}

func (registry *Registry) getUserByID(id string) (user UserRegistry, err error) {
	var ok bool
	user, ok = registry.Data.User[id]
	if !ok {
		err = &UserDoesNotExistError{ID: id}
		return
	}

	return
}

func (registry *Registry) getUserByPublicKey(publicKey sssh.PublicKey) (user UserRegistry, err error) {
	for _, u := range registry.Data.User {
		if u.HasPublicKey(publicKey) {
			user = u
			return
		}
	}

	err = &UserDoesNotExistError{PublicKey: publicKey}
	return
}

func (registry *Registry) getUser(id string, publicKey sssh.PublicKey) (user UserRegistry, err error) {
	if id == "" && publicKey == nil {
		err = &UserDoesNotExistError{Message: "id and publicKey is empty"}
		return
	}

	var userByID, userByPublicKey *UserRegistry

	if id != "" {
		var u UserRegistry
		u, err = registry.getUserByID(id)
		if err == nil {
			userByID = &u
		}
	}

	if publicKey != nil {
		var u UserRegistry
		u, err = registry.getUserByPublicKey(publicKey)
		if err == nil {
			userByPublicKey = &u
		}
	}

	if userByID != nil && userByPublicKey != nil {
		if userByID.HasPublicKey(userByPublicKey.GetPublicKey()) {
			user = *userByID
			return
		}

		err = &UserDoesNotExistError{ID: id, PublicKey: publicKey}
		return
	}
	if userByID != nil {
		err = nil
		user = *userByID
		return
	}

	if userByPublicKey != nil {
		err = nil
		user = *userByPublicKey
		return
	}

	err = &UserDoesNotExistError{ID: id, PublicKey: publicKey}
	return
}

func (registry *Registry) GetUsers(f UserFilter) (users []UserRegistry) {
	for _, u := range registry.Data.User {
		if f&UserFilterIsNotActive == UserFilterIsNotActive && u.IsActive {
			continue
		}
		if f&UserFilterIsAdmin == UserFilterIsAdmin && !u.IsAdmin {
			continue
		}
		users = append(users, u)
	}

	return
}

func (registry *Registry) AddUser(id string, publicKey string) (user UserRegistry, err error) {
	if !saultcommon.CheckUserID(id) {
		err = &InvalidUserIDError{ID: id}
		return
	}

	var parsedPublicKey sssh.PublicKey
	parsedPublicKey, err = saultcommon.ParsePublicKeyFromString(publicKey)
	if err != nil {
		return
	}

	user, _ = registry.GetUser(id, parsedPublicKey, UserFilterNone)
	if user.ID != "" {
		var eid, ePublicKey string
		if user.ID == id {
			eid = id
		}
		if user.HasPublicKey(parsedPublicKey) {
			ePublicKey = publicKey
		}
		err = &UserExistsError{ID: eid, PublicKey: ePublicKey}
		return
	}

	user = UserRegistry{
		ID:          id,
		PublicKey:   strings.TrimSpace(publicKey),
		IsActive:    true,
		IsAdmin:     false,
		DateAdded:   time.Now(),
		DateUpdated: time.Now(),
	}
	registry.Data.User[id] = user
	registry.Data.updated()

	return
}

func (registry *Registry) UpdateUser(id string, newUser UserRegistry) (user UserRegistry, err error) {
	var oldUser UserRegistry
	oldUser, err = registry.GetUser(id, nil, UserFilterNone)
	if err != nil {
		return
	}

	if id != newUser.ID {
		if !saultcommon.CheckUserID(newUser.ID) {
			err = &InvalidUserIDError{ID: id}
			return
		}

		_, err = registry.GetUser(newUser.ID, nil, UserFilterNone)
		if err == nil {
			err = &UserExistsError{ID: id}
			return
		}
	}

	if !oldUser.HasPublicKey(newUser.GetPublicKey()) {
		_, err = registry.GetUser("", newUser.GetPublicKey(), UserFilterNone)
		if err == nil {
			err = &UserExistsError{PublicKey: newUser.PublicKey}
			return
		}
	}

	err = nil

	delete(registry.Data.User, id)

	newUser.PublicKey = strings.TrimSpace(newUser.PublicKey)
	newUser.DateUpdated = time.Now()
	registry.Data.User[newUser.ID] = newUser

	for hostID, link := range registry.Data.Links {
		if _, ok := link[id]; !ok {
			continue
		}
		registry.Data.Links[hostID][newUser.ID] = link[id]
		delete(registry.Data.Links[hostID], id)
	}

	user = newUser
	registry.Data.updated()

	return
}

func (registry *Registry) RemoveUser(id string) (err error) {
	if _, err = registry.GetUser(id, nil, UserFilterNone); err != nil {
		return
	}

	delete(registry.Data.User, id)

	for hostID, link := range registry.Data.Links {
		if _, ok := link[id]; !ok {
			continue
		}
		delete(registry.Data.Links[hostID], id)
	}

	registry.Data.updated()
	return
}

func (registry *Registry) GetHostCount(f HostFilter) (c int) {
	for _, h := range registry.Data.Host {
		if f&HostFilterIsNotActive == HostFilterIsNotActive && h.IsActive {
			continue
		}
		c++
	}

	return c
}

func (registry *Registry) GetHost(id string, f HostFilter) (host HostRegistry, err error) {
	var ok bool
	if host, ok = registry.Data.Host[id]; !ok {
		err = &HostDoesNotExistError{ID: id}
		return
	}

	if f&HostFilterIsNotActive == HostFilterIsNotActive && host.IsActive {
		err = &HostDoesNotExistError{Message: fmt.Sprintf("host, '%s' is active", id)}
		return
	}

	return
}

func (registry *Registry) GetHosts(f HostFilter) (hosts []HostRegistry) {
	for _, h := range registry.Data.Host {
		if f&HostFilterIsNotActive == HostFilterIsNotActive && h.IsActive {
			continue
		}
		hosts = append(hosts, h)
	}

	return
}

func (registry *Registry) AddHost(id, address string, accounts []string) (host HostRegistry, err error) {
	if !saultcommon.CheckHostID(id) {
		err = &saultcommon.InvalidHostIDError{ID: id}
		return
	}

	var hostName string
	var port uint64
	if hostName, port, err = saultcommon.SplitHostPort(address, uint64(22)); err != nil {
		err = &InvalidHostAddressError{Address: address, Err: err}
		return
	}
	address = fmt.Sprintf("%s:%d", hostName, port)

	if _, notFound := registry.GetHost(id, HostFilterNone); notFound == nil {
		err = &HostExistError{ID: id}
		return
	}

	for _, a := range accounts {
		if !saultcommon.CheckUserName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}

	host = HostRegistry{
		ID:          id,
		Address:     address,
		Accounts:    accounts,
		IsActive:    true,
		DateAdded:   time.Now(),
		DateUpdated: time.Now(),
	}

	registry.Data.Host[id] = host
	registry.Data.updated()

	return
}

func (registry *Registry) UpdateHost(id string, newHost HostRegistry) (host HostRegistry, err error) {
	if id != newHost.ID {
		if !saultcommon.CheckHostID(newHost.ID) {
			err = &saultcommon.InvalidHostIDError{ID: newHost.ID}
			return
		}

		if _, notFound := registry.GetHost(newHost.ID, HostFilterNone); notFound == nil {
			err = &HostExistError{ID: newHost.ID}
			return
		}
	}

	var oldHost HostRegistry
	oldHost, err = registry.GetHost(id, HostFilterNone)
	if err != nil {
		return
	}

	if oldHost.Address != newHost.Address {
		var hostName string
		var port uint64
		if hostName, port, err = saultcommon.SplitHostPort(newHost.Address, uint64(22)); err != nil {
			err = &InvalidHostAddressError{Address: newHost.Address, Err: err}
			return
		}
		newHost.Address = fmt.Sprintf("%s:%d", hostName, port)
	}

	for _, a := range newHost.Accounts {
		if !saultcommon.CheckUserName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}

	registry.Data.Host[newHost.ID] = newHost
	delete(registry.Data.Host, id)

	if _, ok := registry.Data.Links[id]; ok {
		registry.Data.Links[newHost.ID] = registry.Data.Links[id]
		delete(registry.Data.Links, id)
	}

	host = newHost
	registry.Data.updated()

	return
}

func (registry *Registry) RemoveHost(id string) (err error) {
	if _, err = registry.GetHost(id, HostFilterNone); err != nil {
		return
	}

	delete(registry.Data.Host, id)

	if _, ok := registry.Data.Links[id]; ok {
		delete(registry.Data.Links, id)
	}

	registry.Data.updated()
	return
}

func (registry *Registry) GetLinksOfUser(id string) (links map[string]LinkAccountRegistry) {
	links = map[string]LinkAccountRegistry{}
	for hostID, link := range registry.Data.Links {
		var userLinks LinkAccountRegistry
		var ok bool
		if userLinks, ok = link[id]; !ok {
			continue
		}

		links[hostID] = userLinks
	}

	return
}

func (registry *Registry) Link(userID, hostID string, accounts ...string) (err error) {
	for _, a := range accounts {
		if !saultcommon.CheckUserName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}

	if _, err = registry.GetUser(userID, nil, UserFilterNone); err != nil {
		return
	}

	var host HostRegistry
	if host, err = registry.GetHost(hostID, HostFilterNone); err != nil {
		return
	}

	if _, ok := registry.Data.Links[host.ID]; !ok {
		registry.Data.Links[host.ID] = map[string]LinkAccountRegistry{
			userID: LinkAccountRegistry{Accounts: accounts},
		}
		return
	}

	var link LinkAccountRegistry
	var ok bool
	link, ok = registry.Data.Links[host.ID][userID]
	if !ok {
		registry.Data.Links[host.ID][userID] = LinkAccountRegistry{Accounts: accounts}
		return
	}
	if link.All {
		return
	}

	existingAccounts := link.Accounts
	existingAccounts = append(existingAccounts, accounts...)

	registry.Data.Links[host.ID][userID] = LinkAccountRegistry{Accounts: existingAccounts}

	registry.Data.updated()
	return
}

func (registry *Registry) IsLinked(userID, hostID, account string) bool {
	if _, ok := registry.Data.Links[hostID]; !ok {
		return false
	}

	var link LinkAccountRegistry
	var ok bool
	link, ok = registry.Data.Links[hostID][userID]
	if !ok {
		return false
	}

	if link.All {
		return true
	}

	for _, a := range registry.Data.Links[hostID][userID].Accounts {
		if a == account {
			return true
		}
	}

	return false
}

func (registry *Registry) LinkAll(userID, hostID string) (err error) {
	if _, err = registry.GetUser(userID, nil, UserFilterNone); err != nil {
		return
	}

	var host HostRegistry
	if host, err = registry.GetHost(hostID, HostFilterNone); err != nil {
		return
	}

	registry.Data.Links[host.ID][userID] = LinkAccountRegistry{All: true}

	registry.Data.updated()
	return
}

func (registry *Registry) Unlink(userID, hostID string, accounts ...string) (err error) {
	for _, a := range accounts {
		if !saultcommon.CheckUserName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}

	if _, err = registry.GetUser(userID, nil, UserFilterNone); err != nil {
		return
	}

	var host HostRegistry
	if host, err = registry.GetHost(hostID, HostFilterNone); err != nil {
		return
	}

	if _, ok := registry.Data.Links[host.ID]; !ok {
		err = &HostAndUserNotLinked{UserID: userID, HostID: hostID}
		return
	}

	if _, ok := registry.Data.Links[host.ID][userID]; !ok {
		err = &HostAndUserNotLinked{UserID: userID, HostID: hostID}
		return
	}

	link := registry.Data.Links[host.ID][userID]
	if link.All {
		err = &LinkedAllError{}
		return
	}

	var slicedAccounts []string
	for _, e := range link.Accounts {
		var found bool
		for _, a := range accounts {
			if e == a {
				found = true
			}
		}
		if !found {
			slicedAccounts = append(slicedAccounts, e)
		}
	}

	registry.Data.Links[host.ID][userID] = LinkAccountRegistry{Accounts: slicedAccounts}

	registry.Data.updated()
	return
}

func (registry *Registry) UnlinkAll(userID, hostID string) (err error) {
	if _, err = registry.GetUser(userID, nil, UserFilterNone); err != nil {
		return
	}

	var host HostRegistry
	if host, err = registry.GetHost(hostID, HostFilterNone); err != nil {
		return
	}

	if _, ok := registry.Data.Links[host.ID]; !ok {
		return
	}

	if _, ok := registry.Data.Links[host.ID][userID]; !ok {
		return
	}

	delete(registry.Data.Links[host.ID], userID)

	registry.Data.updated()
	return
}
