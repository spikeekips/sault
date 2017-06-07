package saultregistry

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/sssh"
)

type UserFilter byte
type HostFilter byte

const (
	UserFilterNone UserFilter = 1 << iota
	UserFilterIsActive
	UserFilterIsNotActive
	UserFilterIsAdmin
	UserFilterIsNotAdmin
)

const (
	HostFilterNone HostFilter = 1 << iota
	HostFilterIsActive
	HostFilterIsNotActive
)

type HostAndUserNotLinked struct {
	UserID string
	HostID string
}

func (e *HostAndUserNotLinked) Error() string {
	return fmt.Sprintf("user, '%s' and host, '%s' was not linked", e.UserID, e.HostID)
}

type UserNothingToUpdate struct {
	ID string
}

func (e *UserNothingToUpdate) Error() string {
	return fmt.Sprintf("nothing to be updated for user, '%s'", e.ID)
}

type HostNothingToUpdate struct {
	ID string
}

func (e *HostNothingToUpdate) Error() string {
	return fmt.Sprintf("nothing to be updated for host, '%s'", e.ID)
}

// TODO move to saultcommon
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

type RegistryPublicKey []byte

func (r *RegistryPublicKey) UnmarshalText(data []byte) (err error) {
	if _, err = saultcommon.ParsePublicKey(data); err != nil {
		return
	}

	*r = RegistryPublicKey(data)

	return
}

func (r RegistryPublicKey) MarshalText() ([]byte, error) {
	return r, nil
}

type UserRegistry struct {
	ID string

	PublicKey RegistryPublicKey
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
	p, _ := saultcommon.ParsePublicKey([]byte(r.PublicKey))

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
	HostName string
	Port     uint64
	Accounts []string

	IsActive    bool
	DateAdded   time.Time
	DateUpdated time.Time
}

func (r HostRegistry) Address() string {
	return fmt.Sprintf(
		"%s:%d",
		r.HostName,
		r.Port,
	)
}

func (r HostRegistry) String() string {
	return fmt.Sprintf(
		"host=%s(%s)",
		r.ID,
		r.Address(),
	)
}

func (r HostRegistry) HasAccount(accounts ...string) bool {
	for _, a := range accounts {
		var found bool
		for _, i := range r.Accounts {
			if a == i {
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
		if f&UserFilterIsActive == UserFilterIsActive && !u.IsActive {
			continue
		}
		if f&UserFilterIsNotActive == UserFilterIsNotActive && u.IsActive {
			continue
		}
		if f&UserFilterIsNotAdmin == UserFilterIsNotAdmin && u.IsAdmin {
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

	if f&UserFilterIsActive == UserFilterIsActive {
		if !user.IsActive {
			user = UserRegistry{}
			err = &saultcommon.UserDoesNotExistError{Message: fmt.Sprintf("user, '%s' is not active", user.ID)}
			return
		}
	}

	if f&UserFilterIsNotActive == UserFilterIsNotActive {
		if user.IsActive {
			user = UserRegistry{}
			err = &saultcommon.UserDoesNotExistError{Message: fmt.Sprintf("user, '%s' is active", user.ID)}
			return
		}
	}

	if f&UserFilterIsAdmin == UserFilterIsAdmin {
		if !user.IsAdmin {
			user = UserRegistry{}
			err = &saultcommon.UserDoesNotExistError{Message: fmt.Sprintf("user, '%s' is not admin", user.ID)}
			return
		}
	}

	if f&UserFilterIsNotAdmin == UserFilterIsNotAdmin {
		if user.IsAdmin {
			user = UserRegistry{}
			err = &saultcommon.UserDoesNotExistError{Message: fmt.Sprintf("user, '%s' is admin", user.ID)}
			return
		}
	}

	return
}

func (registry *Registry) getUserByID(id string) (user UserRegistry, err error) {
	var ok bool
	user, ok = registry.Data.User[id]
	if !ok {
		err = &saultcommon.UserDoesNotExistError{ID: id}
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

	err = &saultcommon.UserDoesNotExistError{PublicKey: publicKey}
	return
}

func (registry *Registry) getUser(id string, publicKey sssh.PublicKey) (user UserRegistry, err error) {
	if id == "" && publicKey == nil {
		err = &saultcommon.UserDoesNotExistError{Message: "id and publicKey is empty"}
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

		err = &saultcommon.UserDoesNotExistError{ID: id, PublicKey: publicKey}
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

	err = &saultcommon.UserDoesNotExistError{ID: id, PublicKey: publicKey}
	return
}

func (registry *Registry) GetUsers(f UserFilter, userIDs ...string) (users []UserRegistry) {
	for _, u := range registry.Data.User {
		if len(userIDs) > 0 {
			var found bool
			for _, id := range userIDs {
				if u.ID == id {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if f&UserFilterIsActive == UserFilterIsActive && !u.IsActive {
			continue
		}
		if f&UserFilterIsNotActive == UserFilterIsNotActive && u.IsActive {
			continue
		}
		if f&UserFilterIsAdmin == UserFilterIsAdmin && !u.IsAdmin {
			continue
		}
		if f&UserFilterIsNotAdmin == UserFilterIsNotAdmin && u.IsAdmin {
			continue
		}
		users = append(users, u)
	}

	return
}

func (registry *Registry) AddUser(id string, publicKey []byte) (user UserRegistry, err error) {
	if !saultcommon.CheckUserID(id) {
		err = &saultcommon.InvalidUserIDError{ID: id}
		return
	}

	var parsedPublicKey sssh.PublicKey
	parsedPublicKey, err = saultcommon.ParsePublicKey(publicKey)
	if err != nil {
		return
	}

	user, _ = registry.GetUser(id, parsedPublicKey, UserFilterNone)
	if user.ID != "" {
		var eid string
		var ePublicKey []byte
		if user.ID == id {
			eid = id
		}
		if user.HasPublicKey(parsedPublicKey) {
			ePublicKey = publicKey
		}
		err = &saultcommon.UserExistsError{ID: eid, PublicKey: ePublicKey}
		return
	}

	user = UserRegistry{
		ID:          id,
		PublicKey:   []byte(strings.TrimSpace(string(publicKey))),
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

	var updated bool
	if id != newUser.ID {
		if !saultcommon.CheckUserID(newUser.ID) {
			err = &saultcommon.InvalidUserIDError{ID: id}
			return
		}

		_, err = registry.GetUser(newUser.ID, nil, UserFilterNone)
		if err == nil {
			err = &saultcommon.UserExistsError{ID: id}
			return
		}
		updated = true
	}

	if !oldUser.HasPublicKey(newUser.GetPublicKey()) {
		_, err = registry.GetUser("", newUser.GetPublicKey(), UserFilterNone)
		if err == nil {
			err = &saultcommon.UserExistsError{PublicKey: newUser.PublicKey}
			return
		}
		updated = true
	}
	if oldUser.IsAdmin != newUser.IsAdmin {
		updated = true
	}
	if oldUser.IsActive != newUser.IsActive {
		updated = true
	}

	if !updated {
		user = oldUser
		err = &UserNothingToUpdate{ID: id}
		return
	}

	err = nil

	delete(registry.Data.User, id)

	newUser.PublicKey = []byte(strings.TrimSpace(string(newUser.PublicKey)))
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
		if f&HostFilterIsActive == HostFilterIsActive && !h.IsActive {
			continue
		}
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
		err = &saultcommon.HostDoesNotExistError{ID: id}
		return
	}

	if f&HostFilterIsActive == HostFilterIsActive && !host.IsActive {
		return
	}
	if f&HostFilterIsNotActive == HostFilterIsNotActive && host.IsActive {
		err = &saultcommon.HostDoesNotExistError{Message: fmt.Sprintf("host, '%s' is active", id)}
		return
	}

	return
}

func (registry *Registry) GetHosts(f HostFilter, hostIDs ...string) (hosts []HostRegistry) {
	for _, h := range registry.Data.Host {
		if len(hostIDs) > 0 {
			var found bool
			for _, a := range hostIDs {
				if a == h.ID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if f&HostFilterIsNotActive == HostFilterIsNotActive && h.IsActive {
			continue
		}
		if f&HostFilterIsNotActive == HostFilterIsNotActive && h.IsActive {
			continue
		}
		hosts = append(hosts, h)
	}

	return
}

func (registry *Registry) AddHost(id, hostName string, port uint64, accounts []string) (host HostRegistry, err error) {
	if !saultcommon.CheckHostID(id) {
		err = &saultcommon.InvalidHostIDError{ID: id}
		return
	}
	if hostName, port, err = saultcommon.SplitHostPort(fmt.Sprintf("%s:%d", hostName, port), uint64(22)); err != nil {
		return
	}

	if _, notFound := registry.GetHost(id, HostFilterNone); notFound == nil {
		err = &HostExistError{ID: id}
		return
	}

	for _, a := range accounts {
		if !saultcommon.CheckAccountName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}

	if len(accounts) > 0 {
		sort.Strings(accounts)
	}

	host = HostRegistry{
		ID:          id,
		HostName:    hostName,
		Port:        port,
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
	var updated bool
	if id != newHost.ID {
		if !saultcommon.CheckHostID(newHost.ID) {
			err = &saultcommon.InvalidHostIDError{ID: newHost.ID}
			return
		}

		if _, notFound := registry.GetHost(newHost.ID, HostFilterNone); notFound == nil {
			err = &HostExistError{ID: newHost.ID}
			return
		}
		updated = true
	}

	var oldHost HostRegistry
	oldHost, err = registry.GetHost(id, HostFilterNone)
	if err != nil {
		return
	}

	if oldHost.Address() != newHost.Address() {
		var hostName string
		var port uint64
		if hostName, port, err = saultcommon.SplitHostPort(newHost.Address(), uint64(22)); err != nil {
			err = &saultcommon.InvalidHostAddressError{Address: newHost.Address(), Err: err}
			return
		}
		newHost.HostName = hostName
		newHost.Port = port

		updated = true
	}

	for _, a := range newHost.Accounts {
		if !saultcommon.CheckAccountName(a) {
			err = &saultcommon.InvalidAccountNameError{Name: a}
			return
		}
	}
	sort.Strings(newHost.Accounts)

	if len(oldHost.Accounts) != len(newHost.Accounts) {
		updated = true
	} else {
		for i := 0; i < len(oldHost.Accounts); i++ {
			if oldHost.Accounts[i] != newHost.Accounts[i] {
				updated = true
			}
		}
	}

	if !updated {
		host = oldHost
		err = &HostNothingToUpdate{ID: id}
	}

	registry.Data.Host[newHost.ID] = newHost
	if id != newHost.ID {
		delete(registry.Data.Host, id)
	}

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
		if !saultcommon.CheckAccountName(a) {
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
	for _, a := range accounts {
		var found bool
		for _, b := range existingAccounts {
			if a == b {
				found = true
				break
			}
		}
		if found {
			continue
		}
		existingAccounts = append(existingAccounts, a)
	}

	sort.Strings(existingAccounts)

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

	if _, ok := registry.Data.Links[host.ID]; !ok {
		registry.Data.Links[host.ID] = map[string]LinkAccountRegistry{}
	}

	registry.Data.Links[host.ID][userID] = LinkAccountRegistry{All: true}

	registry.Data.updated()
	return
}

func (registry *Registry) Unlink(userID, hostID string, accounts ...string) (err error) {
	for _, a := range accounts {
		if !saultcommon.CheckAccountName(a) {
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
		if found {
			continue
		}
		slicedAccounts = append(slicedAccounts, e)
	}

	sort.Strings(slicedAccounts)

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
