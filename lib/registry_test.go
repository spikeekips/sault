package sault

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/spikeekips/sault/ssh"
)

func makeUserName() string {
	m := md5.New()
	m.Write([]byte(GetUUID()))
	return fmt.Sprintf("%x", m.Sum(nil))
}

func makeUsers(registry *Registry, c int) (users []UserRegistryData) {
	for i := 0; i < c; i++ {
		userData, _ := registry.AddUser(makeUserName(), generatePublicKey())
		users = append(users, userData)
	}

	return
}

func TestNewRegistry(t *testing.T) {
	sourceType := "toml"

	registryToml, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(registryToml.Name())

	configSource := configTOMLRegistry{
		Path: registryToml.Name(),
	}
	_, err := newRegistry(sourceType, configSource, false)
	if err != nil {
		t.Error(err)
	}
}

func TestFileRegistry(t *testing.T) {
	sourceType := "toml"

	registryToml, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(registryToml.Name())

	configSource := configTOMLRegistry{
		Path: registryToml.Name(),
	}
	registry, _ := newRegistry(sourceType, configSource, false)
	if registry.GetType() != "toml" {
		t.Errorf("invalid registry type, '%v'", registry.GetType())
	}
}

func registrySetup() (registry *Registry) {
	sourceType := "toml"

	registryToml, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(registryToml.Name())

	configSource := configTOMLRegistry{
		Path: registryToml.Name(),
	}
	registry, _ = newRegistry(sourceType, configSource, false)
	return
}

func generatePublicKey() string {
	privateKey, _ := CreateRSAPrivateKey(48)
	publicKey, _ := EncodePublicKey(&privateKey.PublicKey)

	return strings.TrimSpace(string(publicKey))
}

func generatePrivateKey() string {
	privateKey, _ := CreateRSAPrivateKey(48)
	privateKeyBytes, _ := EncodePrivateKey(privateKey)

	return string(privateKeyBytes)
}

func TestRegistryAddUser(t *testing.T) {
	registry := registrySetup()

	userName := "spikeekips"
	publicKeyString := generatePublicKey()

	userData, err := registry.AddUser(userName, publicKeyString)
	if err != nil {
		t.Error(err)
	}

	if userData.User != userName {
		t.Errorf("userData.User != userName, '%v' != '%v'", userData.User, userName)
	}

	if userData.PublicKey != publicKeyString {
		t.Errorf("userData.PublicKey != publicKeyString, '%v' != '%v'", userData.PublicKey, publicKeyString)
	}

	if len(registry.d.User) != 1 {
		t.Errorf("wrong user count, %d", len(registry.d.User))
	}
}

func TestRegistryRemoveUser(t *testing.T) {
	registry := registrySetup()

	userName := "spikeekips"

	{
		registry.AddUser(userName, generatePublicKey())
		if userCount := registry.GetUserCount(activeFilterAll); userCount != 1 {
			t.Errorf("wrong user count, %d", userCount)
		}
		_, err := registry.AddUser(userName+"1", generatePublicKey())
		if userCount := registry.GetUserCount(activeFilterAll); userCount != 2 {
			t.Errorf("wrong user count, %d", userCount, err)
		}
	}

	{
		registry.RemoveUser(userName + "1")
		if userCount := registry.GetUserCount(activeFilterAll); userCount != 1 {
			t.Errorf("wrong user count, %d", userCount)
		}
		_, err := registry.GetUserByUserName(userName + "1")
		if err == nil {
			t.Errorf("user must be removed")
		}
	}

	{
		registry.RemoveUser(userName)
		if userCount := registry.GetUserCount(activeFilterAll); userCount != 0 {
			t.Errorf("wrong user count, %d", userCount)
		}
		_, err := registry.GetUserByUserName(userName)
		if err == nil {
			t.Errorf("user must be removed")
		}
	}
}

func TestRegistrySetAdmin(t *testing.T) {
	registry := registrySetup()

	userName := "spikeekips"

	{
		registry.AddUser(userName, generatePublicKey())
		if userCount := registry.GetUserCount(activeFilterAll); userCount != 1 {
			t.Errorf("wrong user count, %d", userCount)
		}
		_, err := registry.AddUser(userName+"1", generatePublicKey())
		if userCount := registry.GetUserCount(activeFilterAll); userCount != 2 {
			t.Errorf("wrong user count, %d", userCount, err)
		}
	}

	{
		registry.SetAdmin(userName, true)
		userData, _ := registry.GetUserByUserName(userName)
		if !userData.IsAdmin {
			t.Errorf("failed to set admin")
		}
	}

	{
		registry.SetAdmin(userName, false)
		userData, _ := registry.GetUserByUserName(userName)
		if userData.IsAdmin {
			t.Errorf("failed to set admin")
		}
	}
}

func TestUserRegistryData(t *testing.T) {
	registry := registrySetup()

	userName := "spikeekips"
	publicKeyString := generatePublicKey()

	userData, _ := registry.AddUser(userName, publicKeyString)
	addedAuthorizedKey := userData.GetAuthorizedKey()

	authorizedKeyString := strings.TrimSpace(string(saultSsh.MarshalAuthorizedKey(userData.GetPublicKey())))
	if addedAuthorizedKey != authorizedKeyString {
		t.Errorf("wrong userData.publicKey, '%v'", addedAuthorizedKey)
	}

	{
		_, err := registry.GetUserByPublicKey(userData.GetPublicKey())
		if err != nil {
			t.Errorf("failed to get userData from publickey")
		}
	}
}

func TestRegistryAddHost(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	port := uint64(22)

	_, err := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		[]string{},
	)
	if err != nil {
		t.Error(err)
	}
	if hostCount := registry.GetHostCount(activeFilterAll); hostCount != 1 {
		t.Errorf("r.GetHostCount(activeFilterAll) mismatch: '%v' != '%v'", hostCount, 1)
	}
}

func TestRegistryHostData(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	port := uint64(22)

	hostData, _ := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		[]string{},
	)

	if hostData.Host != hostName {
		t.Errorf("hostData.Host != hostName: '%v' != '%v'", hostData.Host, hostName)
	}
	if hostData.DefaultAccount != defaultAccount {
		t.Errorf("hostData.DefaultAccount != defaultAccount: '%v' != '%v'", hostData.DefaultAccount, defaultAccount)
	}
	if hostData.Address != address {
		t.Errorf("hostData.Address != address: '%v' != '%v'", hostData.Address, address)
	}
	if hostData.Port != port {
		t.Errorf("hostData.Port != port: '%v' != '%v'", hostData.Port, port)
	}
}

func TestRegistryHostDataWithoutPort(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64

	hostData, _ := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		[]string{},
	)

	if fullAddress := hostData.GetFullAddress(); fullAddress != fmt.Sprintf("%s:%d", address, 22) {
		t.Errorf("wrong hostData.GetFullAddress(), '%v'", fullAddress)
	}

	// set none-default port
	newPort := uint64(2000)
	hostData.Port = newPort

	if fullAddress := hostData.GetFullAddress(); fullAddress != fmt.Sprintf("%s:%d", address, newPort) {
		t.Errorf("wrong hostData.GetFullAddress(), '%v'", fullAddress)
	}
}

func TestRegistryRemoveHost(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64

	_, _ = registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		[]string{},
	)

	latestHostCount := registry.GetHostCount(activeFilterAll)

	_, _ = registry.AddHost(
		hostName+"1",
		defaultAccount,
		address,
		port,
		[]string{},
	)
	if registry.GetHostCount(activeFilterAll) != latestHostCount+1 {
		t.Errorf("wrong hostCount, '%d' != '%d'", registry.GetHostCount(activeFilterAll), latestHostCount+1)
	}

	err := registry.RemoveHost(hostName)
	if err != nil {
		t.Error(err)
	}

	_, err = registry.GetHostByHostName(hostName)
	if err == nil {
		t.Errorf("host was not removed")
	}

	if registry.GetHostCount(activeFilterAll) != latestHostCount {
		t.Errorf("wrong hostCount, '%d' != '%d'", registry.GetHostCount(activeFilterAll), latestHostCount)
	}
}

func TestRegistryLink(t *testing.T) {
	registry := registrySetup()

	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64

	var hostsData []hostRegistryData
	var usersData []UserRegistryData
	{
		hostData, _ := registry.AddHost(
			GetUUID(),
			defaultAccount,
			address,
			port,
			[]string{},
		)
		hostsData = append(hostsData, hostData)
	}

	{
		hostData, _ := registry.AddHost(
			GetUUID(),
			defaultAccount,
			address,
			port,
			[]string{},
		)
		hostsData = append(hostsData, hostData)
	}

	{
		userName := makeUserName()
		publicKeyString := generatePublicKey()

		userData, _ := registry.AddUser(userName, publicKeyString)
		usersData = append(usersData, userData)
	}

	{
		userName := makeUserName()
		publicKeyString := generatePublicKey()

		userData, _ := registry.AddUser(userName, publicKeyString)
		usersData = append(usersData, userData)
	}

	targetAccounts := []string{"a", "b"}
	err := registry.Link(hostsData[0].Host, usersData[0].User, targetAccounts)
	if err != nil {
		t.Errorf("%v %v|||", err, usersData[0], makeUserName())
	}

	for _, a := range targetAccounts {
		if registry.IsLinked(hostsData[0].Host, usersData[1].User, a) {
			t.Errorf("'%s' was linked", a)
		}
	}
	for _, a := range targetAccounts {
		if registry.IsLinked(hostsData[1].Host, usersData[0].User, a) {
			t.Errorf("'%s' was not linked, but linked", a)
		}
	}
}

func TestRegistryUnlink(t *testing.T) {
	registry := registrySetup()

	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64

	var usersData []UserRegistryData
	hostData, _ := registry.AddHost(
		GetUUID(),
		defaultAccount,
		address,
		port,
		[]string{},
	)
	{
		userName := makeUserName()
		publicKeyString := generatePublicKey()

		userData, _ := registry.AddUser(userName, publicKeyString)
		usersData = append(usersData, userData)
	}

	{
		userName := makeUserName()
		publicKeyString := generatePublicKey()

		userData, _ := registry.AddUser(userName, publicKeyString)
		usersData = append(usersData, userData)
	}

	targetAccounts := []string{"a", "b"}
	registry.Link(hostData.Host, usersData[0].User, targetAccounts)
	registry.Unlink(hostData.Host, usersData[0].User, []string{targetAccounts[0]})
}

func TestRegistryLinkAll(t *testing.T) {
	registry := registrySetup()

	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64

	var usersData []UserRegistryData
	hostData, _ := registry.AddHost(
		GetUUID(),
		defaultAccount,
		address,
		port,
		[]string{},
	)
	{
		userName := makeUserName()
		publicKeyString := generatePublicKey()

		userData, _ := registry.AddUser(userName, publicKeyString)
		usersData = append(usersData, userData)
	}

	targetAccounts := []string{"a", "b"}
	{
		err := registry.LinkAll(hostData.Host, usersData[0].User)
		if err != nil {
			t.Error(err)
		}
	}
	if !registry.IsLinkedAll(hostData.Host, usersData[0].User) {
		t.Errorf("! registry.IsLinkedAll")
	}

	for _, a := range targetAccounts {
		if !registry.IsLinked(hostData.Host, usersData[0].User, a) {
			t.Errorf("'%s' was not linked", a)
		}
	}

	{
		err := registry.UnlinkAll(hostData.Host, usersData[0].User)
		if err != nil {
			t.Error(err)
		}
	}

	if registry.IsLinkedAll(hostData.Host, usersData[0].User) {
		t.Errorf("registry.IsLinkedAll")
	}
	for _, a := range targetAccounts {
		if registry.IsLinked(hostData.Host, usersData[0].User, a) {
			t.Errorf("'%s' was linked, but unlinked", a)
		}
	}
}

func TestRegistrySave(t *testing.T) {
	registry := registrySetup()

	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64

	userName := makeUserName()
	publicKeyString := generatePublicKey()

	userData, _ := registry.AddUser(userName, publicKeyString)
	hostData, _ := registry.AddHost(
		GetUUID(),
		defaultAccount,
		address,
		port,
		[]string{},
	)

	tmpl, _ := template.New("t").Parse(`
[user.{{.user.User}}]
user = "{{.user.User}}"
public_key = "{{.publicKey}}"
is_admin = false
deactivated = false

[host.{{.host.Host}}]
host = "{{.host.Host}}"
default_account = "{{.host.DefaultAccount}}"
accounts = ["{{.host.DefaultAccount}}"]
address = "{{.host.Address}}"
port = {{.host.Port}}
deactivated = false
	`)

	bw := bytes.NewBuffer([]byte{})
	tmpl.Execute(
		bw,
		map[string]interface{}{
			"user":      userData,
			"host":      hostData,
			"publicKey": template.HTML(userData.PublicKey),
		},
	)

	rString := strings.TrimSpace(string(registry.Bytes()))
	bwString := strings.TrimSpace(bw.String())
	if rString != bwString {
		t.Errorf("registry.String() != bw.String()")
		fmt.Printf(`
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
	`, rString, bwString)
	}

	err := registry.Save()
	if err != nil {
		t.Error(err)
	}

	saved, err := registry.source.Bytes()
	if err != nil {
		t.Error(err)
	}

	savedString := strings.TrimSpace(string(saved))

	if rString != savedString {
		t.Errorf("registry.String() != savedString")
		fmt.Printf(`
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
	`, rString, savedString)
	}
}

func TestRegistryActiveUser(t *testing.T) {
	registry := registrySetup()

	users := makeUsers(registry, 3)

	{
		c := registry.GetUserCount(activeFilterAll)
		if c != len(users) {
			t.Errorf(
				"registry.GetUserCount(activeFilterAll) != len(users); '%d' != '%d'",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterActive)
		if c != len(users) {
			t.Errorf(
				"registry.GetUserCount(activeFilterActive) != len(users); '%d' != '%d'",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterDeactivated)
		if c != 0 {
			t.Errorf(
				"registry.GetUserCount(activeFilterDeactivated) != 0; '%d' != `0`",
				c,
			)
		}
	}

	registry.SetUserActive(users[0].User, false)

	{
		c := registry.GetUserCount(activeFilterAll)
		if c != len(users) {
			t.Errorf(
				"registry.GetUserCount(activeFilterAll) != len(users); '%d' != '%d'",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterActive)
		if c != len(users)-1 {
			t.Errorf(
				"registry.GetUserCount(activeFilterActive) != len(users) -1 ; '%d' != '%d'",
				c,
				len(users)-1,
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterDeactivated)
		if c != 1 {
			t.Errorf(
				"registry.GetUserCount(activeFilterDeactivated) != 1; '%d' != `1`",
				c,
			)
		}
	}
}

func TestRegistryGetUsers(t *testing.T) {
	registry := registrySetup()

	users := makeUsers(registry, 3)

	{
		c := registry.GetUsers(activeFilterAll)
		if len(c) != len(users) {
			t.Errorf(
				"registry.GetUsers(activeFilterAll) != len(users); '%d' != '%d'",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterActive)
		if len(c) != len(users) {
			t.Errorf(
				"registry.GetUsers(activeFilterActive) != len(users); '%d' != '%d'",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterDeactivated)
		if len(c) != 0 {
			t.Errorf(
				"registry.GetUsers(activeFilterDeactivated) != 0; '%d' != `0`",
				c,
			)
		}
	}

	registry.SetUserActive(users[0].User, false)

	{
		c := registry.GetUsers(activeFilterAll)
		if len(c) != len(users) {
			t.Errorf(
				"registry.GetUsers(activeFilterAll) != len(users); '%d' != '%d'",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterActive)
		if len(c) != len(users)-1 {
			t.Errorf(
				"registry.GetUsers(activeFilterActive) != len(users) -1 ; '%d' != '%d'",
				c,
				len(users)-1,
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterDeactivated)
		if len(c) != 1 {
			t.Errorf(
				"registry.GetUsers(activeFilterDeactivated) != 1; '%d' != `1`",
				c,
			)
		}
	}
}

func TestRegistryGetActiveUserByUserName(t *testing.T) {
	registry := registrySetup()

	users := makeUsers(registry, 3)

	{
		u, err := registry.GetActiveUserByUserName(users[0].User)
		if err != nil {
			t.Errorf("registry.GetActiveUserByUserName() must not be failed")
		}
		if u.User != users[0].User {
			t.Errorf("registry.GetActiveUserByUserName() == users[0].User; but '%v' != '%v'", u.User, users[0].User)
		}
	}

	registry.SetUserActive(users[0].User, false)
	{
		_, err := registry.GetActiveUserByUserName(users[0].User)
		if err == nil {
			t.Errorf("registry.GetActiveUserByUserName() must be failed")
		}
	}
}
func TestRegistryGetActiveUserByPublicKey(t *testing.T) {
	registry := registrySetup()

	users := makeUsers(registry, 3)

	{
		u, err := registry.GetActiveUserByPublicKey(users[0].GetPublicKey())
		if err != nil {
			t.Errorf("registry.GetActiveUserByPublicKey() must not be failed")
		}
		if u.User != users[0].User {
			t.Errorf("registry.GetActiveUserByPublicKey() == users[0].User; but '%v' != '%v'", u.User, users[0].User)
		}
	}

	registry.SetUserActive(users[0].User, false)
	{
		_, err := registry.GetActiveUserByPublicKey(users[0].GetPublicKey())
		if err == nil {
			t.Errorf("registry.GetActiveUserByPublicKey() must be failed")
		}
	}
}
