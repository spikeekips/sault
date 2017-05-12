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

func makeUsers(registry Registry, c int) (users []UserRegistryData) {
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
	_, err := NewRegistry(sourceType, configSource, false)
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
	registry, _ := NewRegistry(sourceType, configSource, false)
	if registry.GetType() != "toml" {
		t.Errorf("invalid registry type, `%v`", registry.GetType())
	}
}

func registrySetup() (registry Registry) {
	sourceType := "toml"

	registryToml, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(registryToml.Name())

	configSource := configTOMLRegistry{
		Path: registryToml.Name(),
	}
	registry, _ = NewRegistry(sourceType, configSource, false)
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
		t.Errorf("userData.User != userName, `%v` != `%v`", userData.User, userName)
	}

	if userData.PublicKey != publicKeyString {
		t.Errorf("userData.PublicKey != publicKeyString, `%v` != `%v`", userData.PublicKey, publicKeyString)
	}

	if len(registry.(*tomlRegistry).DataSource.User) != 1 {
		t.Errorf("wrong user count, %d", len(registry.(*tomlRegistry).DataSource.User))
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
		t.Errorf("wrong userData.publicKey, `%v`", addedAuthorizedKey)
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
	clientPrivateKey := ""

	_, err := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		clientPrivateKey,
		[]string{},
	)
	if err != nil {
		t.Error(err)
	}
	if hostCount := registry.GetHostCount(activeFilterAll); hostCount != 1 {
		t.Errorf("r.GetHostCount(activeFilterAll) mismatch: `%v` != `%v`", hostCount, 1)
	}
}

func TestRegistryHostData(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	port := uint64(22)
	clientPrivateKey := ""

	hostData, _ := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		clientPrivateKey,
		[]string{},
	)

	if hostData.Host != hostName {
		t.Errorf("hostData.Host != hostName: `%v` != `%v`", hostData.Host, hostName)
	}
	if hostData.DefaultAccount != defaultAccount {
		t.Errorf("hostData.DefaultAccount != defaultAccount: `%v` != `%v`", hostData.DefaultAccount, defaultAccount)
	}
	if hostData.Address != address {
		t.Errorf("hostData.Address != address: `%v` != `%v`", hostData.Address, address)
	}
	if hostData.Port != port {
		t.Errorf("hostData.Port != port: `%v` != `%v`", hostData.Port, port)
	}
	if hostData.ClientPrivateKey != Base64ClientPrivateKey(clientPrivateKey) {
		t.Errorf("hostData.ClientPrivateKey != clientPrivateKey: `%v` != `%v`", hostData.ClientPrivateKey, clientPrivateKey)
	}
	if signer, _ := hostData.ClientPrivateKey.getSigner(); signer != nil {
		t.Errorf("hostData.ClientPrivateKey is empty and the signer also must be <nil>, but `%v`", signer)
	}
}

func TestRegistryHostDataWithoutPort(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64
	clientPrivateKey := ""

	hostData, _ := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		clientPrivateKey,
		[]string{},
	)

	if fullAddress := hostData.GetFullAddress(); fullAddress != fmt.Sprintf("%s:%d", address, 22) {
		t.Errorf("wrong hostData.GetFullAddress(), `%v`", fullAddress)
	}

	// set none-default port
	newPort := uint64(2000)
	hostData.Port = newPort

	if fullAddress := hostData.GetFullAddress(); fullAddress != fmt.Sprintf("%s:%d", address, newPort) {
		t.Errorf("wrong hostData.GetFullAddress(), `%v`", fullAddress)
	}
}

func TestRegistryHostDataInvalidClientPrivateKey(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64
	clientPrivateKey := generatePrivateKey()

	hostData, err := registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		clientPrivateKey,
		[]string{},
	)
	if err != nil {
		t.Errorf("failed to add hostData")
	}

	if hostData.ClientPrivateKey == Base64ClientPrivateKey("") {
		t.Error("hostData.ClientPrivateKey was set, but <nil>")
	}

	latestHostCount := registry.GetHostCount(activeFilterAll)

	// invalid ClientPrivateKey
	hostName = "server1"
	invalidClientPrivateKey := `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx0yz3QRFewa8zuVkwsAZyC9UCnEfkCZJ6d2r8moGLraCkZpo
b498TV481bTLq7HBVWMNYJCwyevSbCvoSq7PI1UuFz03Q8MZrxUzEQUeiy3S/Hd1
9GV2cQKBgQCPoBUoGh2RgvdKyfV+8hnXRcfgf5EEeBwN77xm4gyTIh2/1AYXMrEz
mcDVxXw9zpsWq/Xxs84OoArVL2mZj6wSnDyGjHCBpQiWRlFJ/j0soGmgLb3cZxGa
+Msh98PiCWJ/aDaQrUak1Y1z4OtJZR7OgC+kaXanm7RtKPL3bS+bd
-----END RSA PRIVATE KEY-----
		`

	_, err = registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		invalidClientPrivateKey,
		[]string{},
	)
	if err == nil {
		t.Errorf("with invalid ClientPrivateKey, must be failed to AddHost")
	}
	if hostCount := registry.GetHostCount(activeFilterAll); hostCount != latestHostCount {
		t.Errorf("wrong hostCount, `%v`", hostCount)
	}
}

func TestRegistryRemoveHost(t *testing.T) {
	registry := registrySetup()

	hostName := "server0"
	defaultAccount := "ubuntu"
	address := "192.168.99.110"
	var port uint64
	clientPrivateKey := ""

	_, _ = registry.AddHost(
		hostName,
		defaultAccount,
		address,
		port,
		clientPrivateKey,
		[]string{},
	)

	latestHostCount := registry.GetHostCount(activeFilterAll)

	_, _ = registry.AddHost(
		hostName+"1",
		defaultAccount,
		address,
		port,
		clientPrivateKey,
		[]string{},
	)
	if registry.GetHostCount(activeFilterAll) != latestHostCount+1 {
		t.Errorf("wrong hostCount, `%d` != `%d`", registry.GetHostCount(activeFilterAll), latestHostCount+1)
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
		t.Errorf("wrong hostCount, `%d` != `%d`", registry.GetHostCount(activeFilterAll), latestHostCount)
	}
}

func TestRegistryConnect(t *testing.T) {
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
			"",
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
			"",
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
	err := registry.Connect(hostsData[0].Host, usersData[0].User, targetAccounts)
	if err != nil {
		t.Errorf("%v %v|||", err, usersData[0], makeUserName())
	}

	for _, a := range targetAccounts {
		if registry.IsConnected(hostsData[0].Host, usersData[1].User, a) {
			t.Errorf("`%s` was connected", a)
		}
	}
	for _, a := range targetAccounts {
		if registry.IsConnected(hostsData[1].Host, usersData[0].User, a) {
			t.Errorf("`%s` was not connected, but connected", a)
		}
	}
}

func TestRegistryDisconnect(t *testing.T) {
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
		"",
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
	registry.Connect(hostData.Host, usersData[0].User, targetAccounts)
	registry.Disconnect(hostData.Host, usersData[0].User, []string{targetAccounts[0]})
}

func TestRegistryConnectAll(t *testing.T) {
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
		"",
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
		err := registry.ConnectAll(hostData.Host, usersData[0].User)
		if err != nil {
			t.Error(err)
		}
	}
	if !registry.IsConnectedAll(hostData.Host, usersData[0].User) {
		t.Errorf("! registry.IsConnectedAll")
	}

	for _, a := range targetAccounts {
		if !registry.IsConnected(hostData.Host, usersData[0].User, a) {
			t.Errorf("`%s` was not connected", a)
		}
	}

	{
		err := registry.DisconnectAll(hostData.Host, usersData[0].User)
		if err != nil {
			t.Error(err)
		}
	}

	if registry.IsConnectedAll(hostData.Host, usersData[0].User) {
		t.Errorf("registry.IsConnectedAll")
	}
	for _, a := range targetAccounts {
		if registry.IsConnected(hostData.Host, usersData[0].User, a) {
			t.Errorf("`%s` was connected, but disconnected", a)
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
		"",
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
client_private_key = "{{.host.ClientPrivateKey}}"
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

	rString := registry.String()
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

	newToml, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(newToml.Name())

	err := registry.Save(newToml)
	if err != nil {
		t.Error(err)
	}
	newToml.Close()

	saved, err := ioutil.ReadFile(newToml.Name())
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

func TestRegistrySync(t *testing.T) {
	registry := registrySetup()
	defer os.Remove(registry.(*tomlRegistry).Path)

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
		"",
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
client_private_key = "{{.host.ClientPrivateKey}}"
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

	bwString := strings.TrimSpace(bw.String())

	err := registry.Sync()
	if err != nil {
		t.Error(err)
	}
	synced, err := ioutil.ReadFile(registry.(*tomlRegistry).Path)
	if err != nil {
		t.Error(err)
	}

	syncedString := strings.TrimSpace(string(synced))

	if syncedString != bwString {
		t.Errorf("syncedString != bwString")
		fmt.Printf(`
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
%s
--------------------------------------------------------------------------------
			`, syncedString, bwString)
	}
}

func TestRegistryActiveUser(t *testing.T) {
	registry := registrySetup()

	users := makeUsers(registry, 3)

	{
		c := registry.GetUserCount(activeFilterAll)
		if c != len(users) {
			t.Errorf(
				"registry.GetUserCount(activeFilterAll) != len(users); `%d` != `%d`",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterActive)
		if c != len(users) {
			t.Errorf(
				"registry.GetUserCount(activeFilterActive) != len(users); `%d` != `%d`",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterDeactivated)
		if c != 0 {
			t.Errorf(
				"registry.GetUserCount(activeFilterDeactivated) != 0; `%d` != `0`",
				c,
			)
		}
	}

	registry.SetUserActive(users[0].User, false)

	{
		c := registry.GetUserCount(activeFilterAll)
		if c != len(users) {
			t.Errorf(
				"registry.GetUserCount(activeFilterAll) != len(users); `%d` != `%d`",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterActive)
		if c != len(users)-1 {
			t.Errorf(
				"registry.GetUserCount(activeFilterActive) != len(users) -1 ; `%d` != `%d`",
				c,
				len(users)-1,
			)
		}
	}
	{
		c := registry.GetUserCount(activeFilterDeactivated)
		if c != 1 {
			t.Errorf(
				"registry.GetUserCount(activeFilterDeactivated) != 1; `%d` != `1`",
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
				"registry.GetUsers(activeFilterAll) != len(users); `%d` != `%d`",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterActive)
		if len(c) != len(users) {
			t.Errorf(
				"registry.GetUsers(activeFilterActive) != len(users); `%d` != `%d`",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterDeactivated)
		if len(c) != 0 {
			t.Errorf(
				"registry.GetUsers(activeFilterDeactivated) != 0; `%d` != `0`",
				c,
			)
		}
	}

	registry.SetUserActive(users[0].User, false)

	{
		c := registry.GetUsers(activeFilterAll)
		if len(c) != len(users) {
			t.Errorf(
				"registry.GetUsers(activeFilterAll) != len(users); `%d` != `%d`",
				c,
				len(users),
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterActive)
		if len(c) != len(users)-1 {
			t.Errorf(
				"registry.GetUsers(activeFilterActive) != len(users) -1 ; `%d` != `%d`",
				c,
				len(users)-1,
			)
		}
	}
	{
		c := registry.GetUsers(activeFilterDeactivated)
		if len(c) != 1 {
			t.Errorf(
				"registry.GetUsers(activeFilterDeactivated) != 1; `%d` != `1`",
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
			t.Errorf("registry.GetActiveUserByUserName() == users[0].User; but `%v` != `%v`", u.User, users[0].User)
		}
	}

	registry.SetUserActive(users[0].User, false)
	{
		u, err := registry.GetActiveUserByUserName(users[0].User)
		if err == nil {
			t.Errorf("registry.GetActiveUserByUserName() must be failed")
		}
		if u.User != users[0].User {
			t.Errorf("registry.GetActiveUserByUserName() == users[0].User; but `%v` != `%v`", u.User, users[0].User)
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
			t.Errorf("registry.GetActiveUserByPublicKey() == users[0].User; but `%v` != `%v`", u.User, users[0].User)
		}
	}

	registry.SetUserActive(users[0].User, false)
	{
		u, err := registry.GetActiveUserByPublicKey(users[0].GetPublicKey())
		if err == nil {
			t.Errorf("registry.GetActiveUserByPublicKey() must be failed")
		}
		if u.User != users[0].User {
			t.Errorf("registry.GetActiveUserByPublicKey() == users[0].User; but `%v` != `%v`", u.User, users[0].User)
		}
	}
}
