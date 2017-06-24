package saultregistry

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/saultssh"
	"github.com/stretchr/testify/assert"
)

func testRegistryGetPublicKey() (publicKey saultssh.PublicKey) {
	privateKey, _ := saultcommon.CreateRSAPrivateKey(256)
	publicKey, _ = saultssh.NewPublicKey(privateKey.Public())

	return
}

func TestBasicRegistry(t *testing.T) {
	_, err := NewTestRegistryFromBytes([]byte{})
	assert.Nil(t, err)
}

func TestRegistryAddUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	{
		// with valid data
		now := time.Now()
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())

		user, err := registry.AddUser(id, encoded)
		assert.Nil(t, err)
		assert.Equal(t, id, user.ID)
		assert.Equal(t, strings.TrimSpace(string(encoded)), strings.TrimSpace(string(user.PublicKey)))
		assert.True(t, user.IsActive)
		assert.True(t, user.DateAdded.After(now))
	}

	{
		// with long user ID
		id := saultcommon.MakeRandomString() + saultcommon.MakeRandomString()
		assert.True(t, len(id) >= saultcommon.MaxLengthUserID)

		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(id, encoded)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidUserIDError{}, err)
	}

	{
		// with invalid user ID
		id := saultcommon.MakeRandomString()[:10] + "-"

		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(id, encoded)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidUserIDError{}, err)
	}

	{
		// with invalid user ID
		id := saultcommon.MakeRandomString()
		id = id[:5] + "*" + id[10:20]

		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(id, encoded)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidUserIDError{}, err)
	}

	{
		// with invalid publicKey
		id := saultcommon.MakeRandomString()
		_, err := registry.AddUser(id, []byte("findme"))
		assert.NotNil(t, err)
	}

	{
		// with duplicated user.ID
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())

		user0, _ := registry.AddUser(id, encoded)

		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(user0.ID, encoded)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.UserExistsError{}, err)
	}

	{
		// with duplicated user.PublicKey
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())

		registry.AddUser(id, encoded)

		id = saultcommon.MakeRandomString()
		_, err := registry.AddUser(id, encoded)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.UserExistsError{}, err)
	}
}

func TestRegistryGetUsers(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var id string
	var user, admin, userNotActive UserRegistry
	{
		id = saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user, _ = registry.AddUser(id, encoded)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		userNotActive, _ = registry.AddUser(id, encoded)
		userNotActive.IsActive = false
		userNotActive, _ = registry.UpdateUser(id, userNotActive)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		admin, _ = registry.AddUser(id, encoded)
		admin.IsAdmin = true
		admin, _ = registry.UpdateUser(id, admin)
	}

	{
		filter := UserFilterNone
		users := registry.GetUsers(filter)

		assert.Equal(t, registry.GetUserCount(filter), len(users))

		expectedUserIDs := []string{user.ID, userNotActive.ID, admin.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			assert.Equal(t, expectedUserIDs[i], userIDs[i])
		}
	}

	{
		filter := UserFilterIsNotActive
		users := registry.GetUsers(filter)

		assert.Equal(t, registry.GetUserCount(filter), len(users))

		expectedUserIDs := []string{userNotActive.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			assert.Equal(t, expectedUserIDs[i], userIDs[i])
		}
	}

	{
		filter := UserFilterIsActive
		users := registry.GetUsers(filter)

		assert.Equal(t, registry.GetUserCount(filter), len(users))

		expectedUserIDs := []string{user.ID, admin.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			assert.Equal(t, expectedUserIDs[i], userIDs[i])
		}
	}

	{
		filter := UserFilterIsAdmin
		users := registry.GetUsers(filter)

		assert.Equal(t, registry.GetUserCount(filter), len(users))

		expectedUserIDs := []string{admin.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			assert.Equal(t, expectedUserIDs[i], userIDs[i])
		}
	}
}

func TestRegistryGetUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var user, admin, userNotActive UserRegistry
	{
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		registry.AddUser(id, encoded)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user, _ = registry.AddUser(id, encoded)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		userNotActive, _ = registry.AddUser(id, encoded)
		userNotActive.IsActive = false
		userNotActive, _ = registry.UpdateUser(id, userNotActive)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		admin, _ = registry.AddUser(id, encoded)
		admin.IsAdmin = true
		admin, _ = registry.UpdateUser(id, admin)
	}

	{
		// by user.ID
		userFound, err := registry.GetUser(user.ID, nil, UserFilterNone)
		assert.Nil(t, err)
		assert.Equal(t, user.ID, userFound.ID)
		assert.Equal(t, user.GetAuthorizedKey(), userFound.GetAuthorizedKey())
		assert.Equal(t, user.IsActive, userFound.IsActive)
		assert.Equal(t, user.IsAdmin, userFound.IsAdmin)
	}

	{
		// by user.PublicKey
		userFound, err := registry.GetUser("", user.GetPublicKey(), UserFilterNone)
		assert.Nil(t, err)

		assert.Equal(t, user.ID, userFound.ID)
		assert.Equal(t, user.GetAuthorizedKey(), userFound.GetAuthorizedKey())
		assert.Equal(t, user.IsActive, userFound.IsActive)
		assert.Equal(t, user.IsAdmin, userFound.IsAdmin)
	}

	{
		{
			// by filter: only active user
			userFound, err := registry.GetUser(user.ID, nil, UserFilterNone)
			assert.Nil(t, err)

			assert.Equal(t, user.ID, userFound.ID)
		}

		{
			// by filter: only not active user
			_, err := registry.GetUser(user.ID, nil, UserFilterIsNotActive)
			assert.Error(t, &saultcommon.UserDoesNotExistError{}, err)
		}

		{
			// by filter: only not active user
			userFound, err := registry.GetUser(userNotActive.ID, nil, UserFilterIsNotActive)
			assert.Nil(t, err)

			assert.Equal(t, userNotActive.ID, userFound.ID)
		}

		{
			// by filter: only deactivated user
			_, err := registry.GetUser(user.ID, nil, UserFilterIsNotActive)
			assert.Error(t, &saultcommon.UserDoesNotExistError{}, err)
		}

		{
			// by filter: only admin user
			_, err := registry.GetUser(user.ID, nil, UserFilterIsAdmin)
			assert.Error(t, &saultcommon.UserDoesNotExistError{}, err)
		}

		{
			// by filter: only admin user
			userFound, err := registry.GetUser(admin.ID, nil, UserFilterIsAdmin)
			assert.Nil(t, err)
			assert.Equal(t, admin.ID, userFound.ID)
		}
	}
}

func TestRegistryRemoveUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	{
		err := registry.RemoveUser(saultcommon.MakeRandomString())
		assert.Error(t, &saultcommon.UserDoesNotExistError{}, err)
	}

	var user0 UserRegistry
	{
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user0, _ = registry.AddUser(id, encoded)
	}

	userCount := registry.GetUserCount(UserFilterNone)

	{
		var err error
		err = registry.RemoveUser(user0.ID)
		assert.Nil(t, err)

		_, err = registry.GetUser(user0.ID, nil, UserFilterNone)
		assert.Error(t, &saultcommon.UserDoesNotExistError{}, err)
		assert.NotNil(t, err)
		assert.Equal(t, userCount-1, registry.GetUserCount(UserFilterNone))
	}
}

func TestRegistryUpdateUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var user0, user1 UserRegistry
	{
		var id string
		id = saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user0, _ = registry.AddUser(id, encoded)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user1, _ = registry.AddUser(id, encoded)
	}

	{
		_, err := registry.UpdateUser(saultcommon.MakeRandomString(), user0)
		assert.Error(t, &saultcommon.UserDoesNotExistError{}, err)
	}

	{
		// with existing user.ID
		_, err := registry.UpdateUser(user0.ID, user1)
		assert.Error(t, &saultcommon.UserExistsError{}, err)
		assert.NotNil(t, err)
	}

	{
		// with existing user.PublicKey
		user0.PublicKey = user1.PublicKey
		_, err := registry.UpdateUser(user0.ID, user0)
		assert.Error(t, &saultcommon.UserExistsError{}, err)
		assert.NotNil(t, err)
	}

	{
		// with invalid user id
		oldID := user0.ID
		id := saultcommon.MakeRandomString()
		user0.ID = id[:5] + "*" + id[10:13]
		_, err := registry.UpdateUser(oldID, user0)
		assert.Error(t, &saultcommon.InvalidUserIDError{}, err)
		assert.NotNil(t, err)
	}

	{
		// update PublicKey
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user1.PublicKey = encoded

		updatedUser, err := registry.UpdateUser(user1.ID, user1)
		assert.Nil(t, err)
		assert.True(t, updatedUser.DateUpdated.After(user1.DateUpdated))
	}
}

func TestRegistryAddHost(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	{
		id := saultcommon.MakeRandomString()
		hostName := "new-server"
		port := uint64(22)
		host, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.Nil(t, err)

		assert.Equal(t, id, host.ID)
		assert.Equal(t, hostName, host.HostName)
	}

	{
		// with 0 port
		id := saultcommon.MakeRandomString()
		hostName := "new-server"
		port := uint64(0)
		host, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.Nil(t, err)
		assert.Equal(t, id, host.ID)

		parsedAddress := fmt.Sprintf("%s:22", hostName)
		assert.Equal(t, parsedAddress, host.GetAddress())
	}

	{
		// with invalid HostName
		id := saultcommon.MakeRandomString()
		hostName := "new-server:"
		port := uint64(0)
		_, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.NotNil(t, err)
	}

	{
		// with invalid HostName
		id := saultcommon.MakeRandomString()
		hostName := ":"
		port := uint64(0)
		_, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.NotNil(t, err)
	}

	{
		// with long id
		id := saultcommon.MakeRandomString() + saultcommon.MakeRandomString() + saultcommon.MakeRandomString() + saultcommon.MakeRandomString() + saultcommon.MakeRandomString()
		assert.True(t, saultcommon.MaxLengthHostID <= len(id))

		hostName := "new-server"
		port := uint64(22)
		_, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidHostIDError{}, err)
	}

	{
		// with invalid id
		id := saultcommon.MakeRandomString()
		id = id[:5] + "*" + id[5:10]
		hostName := "new-server"
		port := uint64(22)
		_, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidHostIDError{}, err)
	}

	{
		// with invalid id
		id := saultcommon.MakeRandomString()
		id = id[:5] + "-"
		hostName := "new-server"
		port := uint64(22)
		_, err := registry.AddHost(id, hostName, port, []string{"ubuntu"})
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidHostIDError{}, err)
	}

	{
		// with accounts
		id := saultcommon.MakeRandomString()
		hostName := "new-server"
		port := uint64(22)
		accounts := []string{saultcommon.MakeRandomString(), saultcommon.MakeRandomString()}
		host, err := registry.AddHost(id, hostName, port, accounts)
		assert.Nil(t, err)

		hostAccounts := host.Accounts
		sort.Strings(hostAccounts)
		sort.Strings(accounts)
		for i := 0; i < len(hostAccounts); i++ {
			assert.Equal(t, accounts[i], hostAccounts[i])
		}
	}

	{
		// with invalid accounts
		id := saultcommon.MakeRandomString()
		hostName := "new-server"
		port := uint64(22)
		accounts := []string{"showme-", saultcommon.MakeRandomString()}
		_, err := registry.AddHost(id, hostName, port, accounts)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidAccountNameError{}, err)
	}
}

func TestRegistryUpdateHost(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var host HostRegistry
	{
		id := saultcommon.MakeRandomString()
		hostName := "new-server"
		port := uint64(22)
		host, _ = registry.AddHost(id, hostName, port, []string{"ubuntu"})
	}

	{
		// with valid host.ID
		oldID := host.ID
		host.ID = saultcommon.MakeRandomString()
		newHost, err := registry.UpdateHost(oldID, host)
		assert.Nil(t, err)
		assert.Equal(t, host.ID, newHost.ID)

		_, err = registry.GetHost(oldID, HostFilterNone)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.HostDoesNotExistError{}, err)
	}

	{
		// with invalid host.ID
		oldID := host.ID
		host.ID = host.ID[:5] + "*"
		_, err := registry.UpdateHost(oldID, host)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidHostIDError{}, err)

		host.ID = oldID
	}

	{
		// with invalid host.Address
		host.HostName = "showme:::"
		_, err := registry.UpdateHost(host.ID, host)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidHostAddressError{}, err)
	}

	{
		// with invalid host.Accounts
		host.Accounts = []string{saultcommon.MakeRandomString(), "findme-"}
		_, err := registry.UpdateHost(host.ID, host)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.InvalidHostAddressError{}, err)
	}
}

func TestRegistryRemoveHost(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var host HostRegistry
	{
		id := saultcommon.MakeRandomString()
		host, _ = registry.AddHost(id, "new-server", uint64(22), []string{"ubuntu"})
	}

	{
		err := registry.RemoveHost(host.ID)
		assert.Nil(t, err)
	}

	{
		_, err := registry.GetHost(host.ID, HostFilterNone)
		assert.NotNil(t, err)
		assert.Error(t, &saultcommon.HostDoesNotExistError{}, err)
	}
}

func TestRegistryLink(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
	user, _ := registry.AddUser(saultcommon.MakeRandomString(), encoded)

	accounts := []string{"ubuntu", "spike"}
	host, _ := registry.AddHost(saultcommon.MakeRandomString(), "new-server", uint64(22), accounts)

	{
		err := registry.Link(user.ID, host.ID, accounts[0])
		assert.Nil(t, err)

		assert.True(t, registry.IsLinked(user.ID, host.ID, accounts[0]))
		assert.False(t, registry.IsLinked(user.ID, host.ID, accounts[1]))

		link := registry.GetLinksOfUser(user.ID)[host.ID]
		assert.Equal(t, accounts[0], link.Accounts[0])
	}
	{
		// link again
		err := registry.Link(user.ID, host.ID, accounts[0])
		assert.Nil(t, err)

		assert.True(t, registry.IsLinked(user.ID, host.ID, accounts[0]))
		assert.False(t, registry.IsLinked(user.ID, host.ID, accounts[1]))

		link := registry.GetLinksOfUser(user.ID)[host.ID]
		assert.Equal(t, 1, len(link.Accounts))
		assert.Equal(t, accounts[0], link.Accounts[0])
	}
}

func TestRegistryUnlink(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
	user, _ := registry.AddUser(saultcommon.MakeRandomString(), encoded)

	accounts := []string{"ubuntu", "spike"}
	host, _ := registry.AddHost(saultcommon.MakeRandomString(), "new-server", uint64(22), accounts)

	{
		registry.Link(user.ID, host.ID, accounts[0])
		registry.Unlink(user.ID, host.ID, accounts[0])

		assert.False(t, registry.IsLinked(user.ID, host.ID, accounts[0]))
	}
}

func TestRegistryToBytes(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var user UserRegistry
	var host HostRegistry
	{
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user, _ = registry.AddUser(id, encoded)
	}

	{
		accounts := []string{"ubuntu", "spike"}
		host, _ = registry.AddHost(saultcommon.MakeRandomString(), "new-server", uint64(22), accounts)
	}

	{
		registry.Link(user.ID, host.ID, "ubuntu")
	}

	{
		b := registry.Bytes()
		assert.False(t, len(b) == 0)
	}
}

func TestRegistryTomlRegistryWithBadSource(t *testing.T) {
	registry := NewRegistry()

	{
		// load without source
		err := registry.Load()
		assert.NotNil(t, err)
	}

	{
		// TomlRegistry with invalid file extension
		tmpFile, _ := ioutil.TempFile("/tmp/", "sault-test")
		os.Remove(tmpFile.Name())

		registryFile := saultcommon.BaseJoin(
			fmt.Sprintf("%s%s", tmpFile.Name(), RegistryFileExt+"1"),
		)

		source := TomlConfigRegistry{Path: registryFile}
		err := registry.AddSource(source)
		assert.NotNil(t, err)
		assert.Error(t, &os.PathError{}, err)
	}

	{
		// TomlRegistry with not-exist file
		tmpFile, _ := ioutil.TempFile("/tmp/", "sault-test")
		os.Remove(tmpFile.Name())

		registryFile := saultcommon.BaseJoin(
			fmt.Sprintf("%s%s", tmpFile.Name(), RegistryFileExt),
		)

		source := TomlConfigRegistry{Path: registryFile}
		err := registry.AddSource(source)
		assert.NotNil(t, err)
		assert.Error(t, &os.PathError{}, err)
	}

	{
		// TomlRegistry with wrong filename, without extension
		registryFile, _ := ioutil.TempFile("/tmp/", "sault-test")
		defer os.Remove(registryFile.Name())

		source := TomlConfigRegistry{Path: registryFile.Name()}
		err := registry.AddSource(source)
		assert.NotNil(t, err)
		assert.Error(t, &os.PathError{}, err)
	}
}

func TestRegistryTomlRegistryWithValidSource(t *testing.T) {
	registry := NewRegistry()

	tmpFile, _ := ioutil.TempFile("/tmp/", "sault-test")
	os.Remove(tmpFile.Name())

	registryFile := saultcommon.BaseJoin(
		fmt.Sprintf("%s%s", tmpFile.Name(), RegistryFileExt),
	)
	defer os.Remove(registryFile)

	content := ``
	ioutil.WriteFile(registryFile, []byte(content), RegistryFileMode)

	source := TomlConfigRegistry{Path: registryFile}
	err := registry.AddSource(source)
	assert.Nil(t, err)
}

func TestRegistryLoadRegistryByTimeUpdated(t *testing.T) {
	registry := NewRegistry()

	var sources []RegistrySource
	var lastTimeUpdated string
	for i := 0; i < 3; i++ {
		tmpFile, _ := ioutil.TempFile("/tmp/", "sault-test")
		os.Remove(tmpFile.Name())

		registryFile := saultcommon.BaseJoin(
			fmt.Sprintf("%s%s", tmpFile.Name(), RegistryFileExt),
		)
		defer os.Remove(registryFile)

		lastTimeUpdated = fmt.Sprintf("0001-0%d-01T00:00:00Z", i)
		content := fmt.Sprintf("time_updated = %s", lastTimeUpdated)
		ioutil.WriteFile(registryFile, []byte(content), RegistryFileMode)

		source := TomlConfigRegistry{Path: registryFile}
		registry.AddSource(source)
		sources = append(sources, source)
	}

	{
		err := registry.Load()
		assert.Nil(t, err)

		parsed, _ := time.Parse(time.RFC3339Nano, lastTimeUpdated)
		assert.True(t, parsed.Equal(registry.Data.TimeUpdated))
	}

	{
		// update middle one
		registryFile := sources[0].(TomlConfigRegistry).Path

		lastTimeUpdated = "2001-01-01T00:00:00Z"
		content := fmt.Sprintf("time_updated = %s", lastTimeUpdated)
		ioutil.WriteFile(registryFile, []byte(content), RegistryFileMode)

		err := registry.Load()
		assert.Nil(t, err)

		parsed, _ := time.Parse(time.RFC3339Nano, lastTimeUpdated)
		assert.True(t, parsed.Equal(registry.Data.TimeUpdated))
	}
}
