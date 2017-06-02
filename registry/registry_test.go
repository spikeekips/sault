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
	"github.com/spikeekips/sault/sssh"
)

func testRegistryGetPublicKey() (publicKey sssh.PublicKey) {
	privateKey, _ := saultcommon.CreateRSAPrivateKey(256)
	publicKey, _ = sssh.NewPublicKey(privateKey.Public())

	return
}

func TestBasicRegistry(t *testing.T) {
	_, err := NewTestRegistryFromBytes([]byte{})
	if err != nil {
		t.Error(err)
	}
}

func TestRegistryAddUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	{
		// with valid data
		now := time.Now()
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey := string(encoded)

		user, err := registry.AddUser(id, publicKey)
		if err != nil {
			t.Error(err)
		}
		if user.ID != id {
			t.Errorf("user.ID != id; '%s' != '%s'", user.ID, id)
		}
		if strings.TrimSpace(user.PublicKey) != strings.TrimSpace(publicKey) {
			t.Errorf("user.PublicKey != publicKey; '%s' != '%s'", user.PublicKey, publicKey)
		}
		if !user.IsActive {
			t.Errorf("user.IsActive must be true; %v", user.IsActive)
		}

		if !user.DateAdded.After(now) {
			t.Error("user.DateAdded was not updated")
		}
	}

	{
		// with long user ID
		id := saultcommon.MakeRandomString() + saultcommon.MakeRandomString()
		if len(id) < saultcommon.MaxLengthUserID {
			t.Errorf("len(id) < saultcommon.MaxLengthUserID; %d < %d", len(id), saultcommon.MaxLengthUserID)
		}

		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(id, string(encoded))
		if err == nil {
			t.Errorf("'InvalidUserIDError' must be occured")
		}
		if _, ok := err.(*InvalidUserIDError); !ok {
			t.Errorf("'InvalidUserIDError' must be occured; %v", err)
		}
	}

	{
		// with invalid user ID
		id := saultcommon.MakeRandomString()[:10] + "-"

		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(id, string(encoded))
		if err == nil {
			t.Errorf("'InvalidUserIDError' must be occured")
		}
		if _, ok := err.(*InvalidUserIDError); !ok {
			t.Errorf("'InvalidUserIDError' must be occured; %v", err)
		}
	}

	{
		// with invalid user ID
		id := saultcommon.MakeRandomString()
		id = id[:5] + "*" + id[10:20]

		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		_, err := registry.AddUser(id, string(encoded))
		if err == nil {
			t.Errorf("'InvalidUserIDError' must be occured")
		}
		if _, ok := err.(*InvalidUserIDError); !ok {
			t.Errorf("'InvalidUserIDError' must be occured; %v", err)
		}
	}

	{
		// with invalid publicKey
		id := saultcommon.MakeRandomString()
		_, err := registry.AddUser(id, "findme")
		if err == nil {
			t.Errorf("error must be occured")
		}
	}

	{
		// with duplicated user.ID
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey0 := string(encoded)

		user0, _ := registry.AddUser(id, publicKey0)

		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey1 := string(encoded)
		_, err := registry.AddUser(user0.ID, publicKey1)
		if err == nil {
			t.Errorf("err must be 'UserExistsError'")
		}

		if uerr, ok := err.(*UserExistsError); !ok || uerr.ID == "" {
			t.Errorf("err must be 'UserExistsError'")
		}
	}

	{
		// with duplicated user.PublicKey
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey := string(encoded)

		registry.AddUser(id, publicKey)

		id = saultcommon.MakeRandomString()
		_, err := registry.AddUser(id, publicKey)
		if err == nil {
			t.Errorf("err must be 'UserExistsError'")
		}

		if uerr, ok := err.(*UserExistsError); !ok || uerr.PublicKey == "" {
			t.Errorf("err must be 'UserExistsError'")
		}
	}
}

func TestRegistryGetUsers(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var id, publicKey string
	var user, admin, userNotActive UserRegistry
	{
		id = saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		user, _ = registry.AddUser(id, publicKey)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		userNotActive, _ = registry.AddUser(id, publicKey)
		userNotActive.IsActive = false
		userNotActive, _ = registry.UpdateUser(id, userNotActive)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		admin, _ = registry.AddUser(id, publicKey)
		admin.IsAdmin = true
		admin, _ = registry.UpdateUser(id, admin)
	}

	{
		filter := UserFilterNone
		users := registry.GetUsers(filter)

		if len(users) != registry.GetUserCount(filter) {
			t.Error("len(users) != registry.GetUserCount(filter); %d != %d", len(users), registry.GetUserCount(filter))
		}

		expectedUserIDs := []string{user.ID, userNotActive.ID, admin.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			if userIDs[i] != expectedUserIDs[i] {
				t.Error("userIDs != expectedUserIDs; %v != %v", userIDs, expectedUserIDs)
				break
			}
		}
	}

	{
		filter := UserFilterIsNotActive
		users := registry.GetUsers(filter)

		if len(users) != registry.GetUserCount(filter) {
			t.Error("len(users) != registry.GetUserCount(filter); %d != %d", len(users), registry.GetUserCount(filter))
		}

		expectedUserIDs := []string{userNotActive.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			if userIDs[i] != expectedUserIDs[i] {
				t.Error("userIDs != expectedUserIDs; %v != %v", userIDs, expectedUserIDs)
				break
			}
		}
	}

	{
		filter := UserFilterIsAdmin
		users := registry.GetUsers(filter)

		if len(users) != registry.GetUserCount(filter) {
			t.Error("len(users) != registry.GetUserCount(filter); %d != %d", len(users), registry.GetUserCount(filter))
		}

		expectedUserIDs := []string{admin.ID}
		var userIDs []string
		for _, u := range users {
			userIDs = append(userIDs, u.ID)
		}

		sort.Strings(userIDs)
		sort.Strings(expectedUserIDs)
		for i := 0; i < len(users); i++ {
			if userIDs[i] != expectedUserIDs[i] {
				t.Error("userIDs != expectedUserIDs; %v != %v", userIDs, expectedUserIDs)
				break
			}
		}
	}
}

func TestRegistryGetUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var user, admin, userNotActive UserRegistry
	{
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey := string(encoded)
		registry.AddUser(id, publicKey)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		user, _ = registry.AddUser(id, publicKey)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		userNotActive, _ = registry.AddUser(id, publicKey)
		userNotActive.IsActive = false
		userNotActive, _ = registry.UpdateUser(id, userNotActive)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		admin, _ = registry.AddUser(id, publicKey)
		admin.IsAdmin = true
		admin, _ = registry.UpdateUser(id, admin)
	}

	{
		// by user.ID
		userFound, err := registry.GetUser(user.ID, nil, UserFilterNone)
		if err != nil {
			t.Error(err)
		}

		if userFound.ID != user.ID {
			t.Errorf("userFound.ID != user.ID; '%s' != '%s'", userFound.ID, user.ID)
		}
		if userFound.PublicKey != user.PublicKey {
			t.Errorf("userFound.PublicKey != user.PublicKey; '%s' != '%s'", userFound.PublicKey, user.PublicKey)
		}
		if userFound.IsActive != user.IsActive {
			t.Errorf("userFound.IsActive != user.IsActive; '%s' != '%s'", userFound.IsActive, user.IsActive)
		}
		if userFound.IsAdmin != user.IsAdmin {
			t.Errorf("userFound.IsAdmin != user.IsAdmin; '%s' != '%s'", userFound.IsAdmin, user.IsAdmin)
		}
	}

	{
		// by user.PublicKey
		userFound, err := registry.GetUser("", user.GetPublicKey(), UserFilterNone)
		if err != nil {
			t.Error(err)
		}

		if userFound.ID != user.ID {
			t.Errorf("userFound.ID != user.ID; '%s' != '%s'", userFound.ID, user.ID)
		}
		if userFound.PublicKey != user.PublicKey {
			t.Errorf("userFound.PublicKey != user.PublicKey; '%s' != '%s'", userFound.PublicKey, user.PublicKey)
		}
		if userFound.IsActive != user.IsActive {
			t.Errorf("userFound.IsActive != user.IsActive; '%s' != '%s'", userFound.IsActive, user.IsActive)
		}
		if userFound.IsAdmin != user.IsAdmin {
			t.Errorf("userFound.IsAdmin != user.IsAdmin; '%s' != '%s'", userFound.IsAdmin, user.IsAdmin)
		}
	}

	{
		{
			// by filter: only active user
			userFound, err := registry.GetUser(user.ID, nil, UserFilterNone)
			if err != nil {
				t.Error(err)
			}

			if userFound.ID != user.ID {
				t.Errorf("userFound.ID != user.ID; '%s' != '%s'", userFound.ID, user.ID)
			}
		}

		{
			// by filter: only not active user
			_, err := registry.GetUser(user.ID, nil, UserFilterIsNotActive)
			if _, ok := err.(*UserDoesNotExistError); !ok {
				t.Errorf("'UserDoesNotExistError' must be occured")
			}
			if err == nil {
				t.Errorf("'UserDoesNotExistError' must be occured")
			}
		}

		{
			// by filter: only not active user
			userFound, err := registry.GetUser(userNotActive.ID, nil, UserFilterIsNotActive)
			if err != nil {
				t.Error(err)
			}

			if userFound.ID != userNotActive.ID {
				t.Errorf("userFound.ID != userNotActive.ID; '%s' != '%s'", userFound.ID, userNotActive.ID)
			}
		}

		{
			// by filter: only deactivated user
			_, err := registry.GetUser(user.ID, nil, UserFilterIsNotActive)
			if _, ok := err.(*UserDoesNotExistError); !ok {
				t.Errorf("'UserDoesNotExistError' must be occured")
			}
		}

		{
			// by filter: only admin user
			_, err := registry.GetUser(user.ID, nil, UserFilterIsAdmin)
			if _, ok := err.(*UserDoesNotExistError); !ok {
				t.Errorf("'UserDoesNotExistError' must be occured")
			}
		}

		{
			// by filter: only admin user
			userFound, err := registry.GetUser(admin.ID, nil, UserFilterIsAdmin)
			if err != nil {
				t.Error(err)
			}

			if userFound.ID != admin.ID {
				t.Errorf("userFound.ID != admin.ID; '%s' != '%s'", userFound.ID, admin.ID)
			}
		}
	}
}

func TestRegistryRemoveUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	{
		err := registry.RemoveUser(saultcommon.MakeRandomString())
		if err, ok := err.(*UserDoesNotExistError); !ok {
			t.Error(err)
		}
	}

	var user0 UserRegistry
	{
		var publicKey string
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		user0, _ = registry.AddUser(id, publicKey)
	}

	userCount := registry.GetUserCount(UserFilterNone)

	{
		if err := registry.RemoveUser(user0.ID); err != nil {
			t.Error(err)
		}

		_, err := registry.GetUser(user0.ID, nil, UserFilterNone)
		if _, ok := err.(*UserDoesNotExistError); !ok {
			t.Errorf("'UserDoesNotExistError' must be occured")
		}
		if err == nil {
			t.Errorf("'UserDoesNotExistError' must be occured")
		}

		if registry.GetUserCount(UserFilterNone) != userCount-1 {
			t.Errorf("registry.GetUserCount() != userCount - 1; '%d' != '%d'", registry.GetUserCount(UserFilterNone), userCount-1)
		}
	}
}

func TestRegistryUpdateUser(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var user0, user1 UserRegistry
	{
		var id, publicKey string
		id = saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		user0, _ = registry.AddUser(id, publicKey)

		id = saultcommon.MakeRandomString()
		encoded, _ = saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey = string(encoded)
		user1, _ = registry.AddUser(id, publicKey)
	}

	{
		_, err := registry.UpdateUser(saultcommon.MakeRandomString(), user0)
		if _, ok := err.(*UserDoesNotExistError); !ok {
			t.Error(err)
		}
	}

	{
		// with existing user.ID
		_, err := registry.UpdateUser(user0.ID, user1)
		if _, ok := err.(*UserExistsError); !ok {
			t.Errorf("err must be 'UserExistsError'; %v", err)
		}

		if err == nil {
			t.Errorf("err must be 'UserExistsError'")
		}
	}

	{
		// with existing user.PublicKey
		user0.PublicKey = user1.PublicKey
		_, err := registry.UpdateUser(user0.ID, user0)
		if _, ok := err.(*UserExistsError); !ok {
			t.Errorf("err must be 'UserExistsError'; %v", err)
		}

		if err == nil {
			t.Errorf("err must be 'UserExistsError'")
		}
	}

	{
		// with invalid user id
		oldID := user0.ID
		id := saultcommon.MakeRandomString()
		user0.ID = id[:5] + "*" + id[10:13]
		_, err := registry.UpdateUser(oldID, user0)
		if _, ok := err.(*InvalidUserIDError); !ok {
			t.Errorf("err must be 'InvalidUserIDError'; %v", err)
		}

		if err == nil {
			t.Errorf("err must be 'InvalidUserIDError'")
		}
	}

	{
		// update PublicKey
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		user1.PublicKey = string(encoded)

		updatedUser, err := registry.UpdateUser(user1.ID, user1)
		if err != nil {
			t.Error(err)
		}

		if !updatedUser.DateUpdated.After(user1.DateUpdated) {
			t.Error("user.DateUpdated was not updated")
		}
	}
}

func TestRegistryAddHost(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	{
		id := saultcommon.MakeRandomString()
		address := "new-server:22"
		host, err := registry.AddHost(id, address, nil)
		if err != nil {
			t.Error(err)
		}

		if host.ID != id {
			t.Errorf("host.ID != id; '%s' != '%s'", host.ID, id)
		}
		if host.Address != address {
			t.Errorf("host.Address != address; '%s' != '%s'", host.Address, address)
		}
	}

	{
		// with address without port
		id := saultcommon.MakeRandomString()
		address := "new-server"
		host, err := registry.AddHost(id, address, nil)
		if err != nil {
			t.Error(err)
		}

		if host.ID != id {
			t.Errorf("host.ID != id; '%s' != '%s'", host.ID, id)
		}

		parsedAddress := fmt.Sprintf("%s:22", address)
		if host.Address != parsedAddress {
			t.Errorf("host.Address != parsedAddress; '%s' != '%s'", host.Address, parsedAddress)
		}
	}

	{
		// with invalid address
		id := saultcommon.MakeRandomString()
		address := "new-server:"
		host, err := registry.AddHost(id, address, nil)
		if err != nil {
			t.Error(err)
		}

		if host.ID != id {
			t.Errorf("host.ID != id; '%s' != '%s'", host.ID, id)
		}

		parsedAddress := fmt.Sprintf("%s22", address)
		if host.Address != parsedAddress {
			t.Errorf("host.Address != parsedAddress; '%s' != '%s'", host.Address, parsedAddress)
		}
	}

	{
		// with address without host name
		id := saultcommon.MakeRandomString()
		address := ":3333"
		host, err := registry.AddHost(id, address, nil)
		if err != nil {
			t.Error(err)
		}

		if host.ID != id {
			t.Errorf("host.ID != id; '%s' != '%s'", host.ID, id)
		}

		if host.Address != address {
			t.Errorf("host.Address != address; '%s' != '%s'", host.Address, address)
		}
	}

	{
		// with long id
		id := saultcommon.MakeRandomString() + saultcommon.MakeRandomString() + saultcommon.MakeRandomString() + saultcommon.MakeRandomString() + saultcommon.MakeRandomString()
		if len(id) < saultcommon.MaxLengthHostID {
			t.Errorf("len(id) < saultcommon.MaxLengthHostID; %d < %d", len(id), saultcommon.MaxLengthHostID)
		}

		address := "new-server:22"
		_, err := registry.AddHost(id, address, nil)
		if err == nil {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured")
		}
		if _, ok := err.(*saultcommon.InvalidHostIDError); !ok {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured: %v", err)
		}
	}

	{
		// with invalid id
		id := saultcommon.MakeRandomString()
		id = id[:5] + "*" + id[5:10]
		address := "new-server:22"
		_, err := registry.AddHost(id, address, nil)
		if err == nil {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured")
		}
		if _, ok := err.(*saultcommon.InvalidHostIDError); !ok {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured: %v", err)
		}
	}

	{
		// with invalid id
		id := saultcommon.MakeRandomString()
		id = id[:5] + "-"
		address := "new-server:22"
		_, err := registry.AddHost(id, address, nil)
		if err == nil {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured")
		}
		if _, ok := err.(*saultcommon.InvalidHostIDError); !ok {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured: %v", err)
		}
	}

	{
		// with accounts
		id := saultcommon.MakeRandomString()
		address := "new-server:22"
		accounts := []string{saultcommon.MakeRandomString(), saultcommon.MakeRandomString()}
		host, err := registry.AddHost(id, address, accounts)
		if err != nil {
			t.Error(err)
		}

		hostAccounts := host.Accounts
		sort.Strings(hostAccounts)
		sort.Strings(accounts)
		for i := 0; i < len(hostAccounts); i++ {
			if hostAccounts[i] != accounts[i] {
				t.Errorf("hostAccounts[i] != accounts[i]; '%s' != '%s'", hostAccounts[i], accounts[i])
			}
		}
	}

	{
		// with invalid accounts
		id := saultcommon.MakeRandomString()
		address := "new-server:22"
		accounts := []string{"showme-", saultcommon.MakeRandomString()}
		_, err := registry.AddHost(id, address, accounts)
		if err == nil {
			t.Errorf("'saultcommon.InvalidAccountNameError' must be occured")
		}
		if _, ok := err.(*saultcommon.InvalidAccountNameError); !ok {
			t.Errorf("'saultcommon.InvalidAccountNameError' must be occured: %v", err)
		}
	}
}

func TestRegistryUpdateHost(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var host HostRegistry
	{
		id := saultcommon.MakeRandomString()
		address := "new-server:22"
		host, _ = registry.AddHost(id, address, nil)
	}

	{
		// with valid host.ID
		oldID := host.ID
		host.ID = saultcommon.MakeRandomString()
		newHost, err := registry.UpdateHost(oldID, host)
		if err != nil {
			t.Error(err)
		}

		if newHost.ID != host.ID {
			t.Errorf("newHost.ID != host.ID; '%s' != '%s'", newHost.ID, host.ID)
		}

		_, err = registry.GetHost(oldID, HostFilterNone)
		if err == nil {
			t.Errorf("'HostDoesNotExistError' must be occured")
		}
		if _, ok := err.(*HostDoesNotExistError); !ok {
			t.Errorf("'HostDoesNotExistError' must be occured: %v", err)
		}
	}

	{
		// with invalid host.ID
		oldID := host.ID
		host.ID = host.ID[:5] + "*"
		_, err := registry.UpdateHost(oldID, host)
		if err == nil {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured")
		}
		if _, ok := err.(*saultcommon.InvalidHostIDError); !ok {
			t.Errorf("'saultcommon.InvalidHostIDError' must be occured: %v", err)
		}

		host.ID = oldID
	}

	{
		// with invalid host.Address
		host.Address = "showme:::"
		_, err := registry.UpdateHost(host.ID, host)
		if err == nil {
			t.Errorf("'InvalidHostAddressError' must be occured")
		}
		if _, ok := err.(*InvalidHostAddressError); !ok {
			t.Errorf("'InvalidHostAddressError' must be occured: %v", err)
		}
	}

	{
		// with invalid host.Accounts
		host.Accounts = []string{saultcommon.MakeRandomString(), "findme-"}
		_, err := registry.UpdateHost(host.ID, host)
		if err == nil {
			t.Errorf("'saultcommon.InvalidAccountNameError' must be occured")
		}
		if _, ok := err.(*InvalidHostAddressError); !ok {
			t.Errorf("'saultcommon.InvalidAccountNameError' must be occured: %v", err)
		}
	}
}

func TestRegistryRemoveHost(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var host HostRegistry
	{
		id := saultcommon.MakeRandomString()
		address := "new-server:22"
		host, _ = registry.AddHost(id, address, nil)
	}

	{
		err := registry.RemoveHost(host.ID)
		if err != nil {
			t.Error(err)
		}
	}

	{
		_, err := registry.GetHost(host.ID, HostFilterNone)
		if err == nil {
			t.Errorf("'HostDoesNotExistError' must be occured")
		}
		if _, ok := err.(*HostDoesNotExistError); !ok {
			t.Errorf("'HostDoesNotExistError' must be occured: %v", err)
		}
	}
}

func TestRegistryLink(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
	user, _ := registry.AddUser(saultcommon.MakeRandomString(), string(encoded))

	accounts := []string{"ubuntu", "spike"}
	host, _ := registry.AddHost(saultcommon.MakeRandomString(), "new-server:22", accounts)

	{
		err := registry.Link(user.ID, host.ID, accounts[0])
		if err != nil {
			t.Error(err)
		}

		if !registry.IsLinked(user.ID, host.ID, accounts[0]) {
			t.Errorf("must be linked")
		}

		if registry.IsLinked(user.ID, host.ID, accounts[1]) {
			t.Errorf("must be unlinked")
		}

		link := registry.GetLinksOfUser(user.ID)[host.ID]
		if link.Accounts[0] != accounts[0] {
			t.Errorf("link.Accounts[0] != accounts[0]; '%s' != '%s'", link.Accounts[0], accounts[0])
		}
	}
}

func TestRegistryUnlink(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
	user, _ := registry.AddUser(saultcommon.MakeRandomString(), string(encoded))

	accounts := []string{"ubuntu", "spike"}
	host, _ := registry.AddHost(saultcommon.MakeRandomString(), "new-server:22", accounts)

	{
		registry.Link(user.ID, host.ID, accounts[0])
		registry.Unlink(user.ID, host.ID, accounts[0])

		if registry.IsLinked(user.ID, host.ID, accounts[0]) {
			t.Errorf("must be unlinked")
		}
	}
}

func TestRegistryToBytes(t *testing.T) {
	registry, _ := NewTestRegistryFromBytes([]byte{})

	var user UserRegistry
	var host HostRegistry
	{
		id := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(testRegistryGetPublicKey())
		publicKey := string(encoded)
		user, _ = registry.AddUser(id, publicKey)
	}

	{
		accounts := []string{"ubuntu", "spike"}
		host, _ = registry.AddHost(saultcommon.MakeRandomString(), "new-server:22", accounts)
	}

	{
		registry.Link(user.ID, host.ID, "ubuntu")
	}

	{
		b := registry.Bytes()
		if len(b) == 0 {
			t.Errorf("failed to get Bytes()")
		}
	}
}

func TestRegistryTomlRegistryWithBadSource(t *testing.T) {
	registry := NewRegistry()

	{
		// load without source
		err := registry.Load()
		if err == nil {
			t.Errorf("err must be occured")
		}
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
		if err == nil {
			t.Errorf("'os.PathError' must be occured")
		}
		if _, ok := err.(*os.PathError); !ok {
			t.Errorf("'os.PathError' must be occured")
		}
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
		if err == nil {
			t.Errorf("'os.PathError' must be occured")
		}
		if _, ok := err.(*os.PathError); !ok {
			t.Errorf("'os.PathError' must be occured")
		}
	}

	{
		// TomlRegistry with wrong filename, without extension
		registryFile, _ := ioutil.TempFile("/tmp/", "sault-test")
		defer os.Remove(registryFile.Name())

		source := TomlConfigRegistry{Path: registryFile.Name()}
		err := registry.AddSource(source)
		if err == nil {
			t.Errorf("err must be occured")
		}
		if err == nil {
			t.Errorf("'os.PathError' must be occured")
		}
		if _, ok := err.(*os.PathError); !ok {
			t.Errorf("'os.PathError' must be occured")
		}
	}
}

func TestRegistryTomlRegistryWithValidSource(t *testing.T) {
	registry := NewRegistry()

	tmpFile, _ := ioutil.TempFile("/tmp/", "sault-test")
	os.Remove(tmpFile.Name())

	registryFile := saultcommon.BaseJoin(
		fmt.Sprintf("%s%s", tmpFile.Name(), RegistryFileExt),
	)

	content := ``
	ioutil.WriteFile(registryFile, []byte(content), RegistryFileMode)

	source := TomlConfigRegistry{Path: registryFile}
	if err := registry.AddSource(source); err != nil {
		t.Error(err)
	}
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

		lastTimeUpdated = fmt.Sprintf("0001-0%d-01T00:00:00Z", i)
		content := fmt.Sprintf("time_updated = %s", lastTimeUpdated)
		ioutil.WriteFile(registryFile, []byte(content), RegistryFileMode)

		source := TomlConfigRegistry{Path: registryFile}
		registry.AddSource(source)
		sources = append(sources, source)
	}

	{
		err := registry.Load()
		if err != nil {
			t.Error(err)
		}

		parsed, _ := time.Parse(time.RFC3339Nano, lastTimeUpdated)
		if !parsed.Equal(registry.Data.TimeUpdated) {
			t.Errorf("parsed.Equal(registry.Data.TimeUpdated); %s != %s", parsed, registry.Data.TimeUpdated)
		}
	}

	{
		// update middle one
		registryFile := sources[0].(TomlConfigRegistry).Path

		lastTimeUpdated = "2001-01-01T00:00:00Z"
		content := fmt.Sprintf("time_updated = %s", lastTimeUpdated)
		ioutil.WriteFile(registryFile, []byte(content), RegistryFileMode)

		err := registry.Load()
		if err != nil {
			t.Error(err)
		}

		parsed, _ := time.Parse(time.RFC3339Nano, lastTimeUpdated)
		if !parsed.Equal(registry.Data.TimeUpdated) {
			t.Errorf("parsed.Equal(registry.Data.TimeUpdated); %s != %s", parsed, registry.Data.TimeUpdated)
		}
	}
}
