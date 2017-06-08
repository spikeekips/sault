package sault

import (
	"fmt"
	"net"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/sssh"
)

type testSSHConn struct {
	user string
}

func (c *testSSHConn) User() string {
	return c.user
}

func (c *testSSHConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *testSSHConn) Close() error {
	return nil
}

func (c *testSSHConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *testSSHConn) SessionID() []byte {
	return []byte(fmt.Sprintf("%q", c))
}

func (c *testSSHConn) ClientVersion() []byte {
	return []byte("0.0")
}

func (c *testSSHConn) ServerVersion() []byte {
	return []byte("0.0")
}

func TestPublicKeyCallback(t *testing.T) {
	registry, _ := saultregistry.NewTestRegistryFromBytes([]byte{})

	server, _ := NewServer(registry, nil, nil, nil, DefaultSaultServerName)

	conn := &connection{server: server, log: log.WithFields(logrus.Fields{})}

	privateKey, _ := saultcommon.CreateRSAPrivateKey(256)
	publicKey, _ := sssh.NewPublicKey(privateKey.Public())

	{
		// with empty connMeta.User()
		connMeta := &testSSHConn{}
		_, err := conn.publicKeyCallback(connMeta, publicKey)
		if err == nil {
			t.Errorf("'AuthenticationFailedError' must be occurred")
		}
		if _, ok := err.(*AuthenticationFailedError); !ok {
			t.Errorf("'AuthenticationFailedError' must be occurred: %v", err)
		}
	}

	{
		// with invalid connMeta.User()
		connMeta := &testSSHConn{user: "anonymous+host"}
		_, err := conn.publicKeyCallback(connMeta, publicKey)
		if err == nil {
			t.Errorf("'AuthenticationFailedError' must be occurred")
		}
		if _, ok := err.(*AuthenticationFailedError); !ok {
			t.Errorf("'AuthenticationFailedError' must be occurred: %v", err)
		}
	}

	{
		// with valid connMeta.User(), but not linked with user and host
		var err error

		userID := saultcommon.MakeRandomString()
		hostID := saultcommon.MakeRandomString()
		account := "ubuntu"
		encoded, _ := saultcommon.EncodePublicKey(publicKey)
		_, _ = registry.AddUser(userID, encoded)
		host, _ := registry.AddHost(hostID, "fake", uint64(22), []string{account})

		connMeta := &testSSHConn{user: fmt.Sprintf("%s+%s", account, host.ID)}

		_, err = conn.publicKeyCallback(connMeta, publicKey)
		if err == nil {
			t.Errorf("'AuthenticationFailedError' must be occurred")
		}
		if _, ok := err.(*AuthenticationFailedError); !ok {
			t.Errorf("'AuthenticationFailedError' must be occurred: %v", err)
		}
	}

	{
		// with valid connMeta.User(), and linked
		var err error

		userID := saultcommon.MakeRandomString()
		hostID := saultcommon.MakeRandomString()
		account := "ubuntu"
		encoded, _ := saultcommon.EncodePublicKey(publicKey)
		user, _ := registry.AddUser(userID, encoded)
		host, _ := registry.AddHost(hostID, "fake", uint64(22), []string{account})

		registry.Link(user.ID, host.ID, account)

		connMeta := &testSSHConn{user: fmt.Sprintf("%s+%s", account, host.ID)}

		_, err = conn.publicKeyCallback(connMeta, publicKey)
		if err != nil {
			t.Error(err)
		}
	}

	{
		// with not linked, but user is admin
		var err error

		userID := saultcommon.MakeRandomString()
		hostID := saultcommon.MakeRandomString()
		account := "ubuntu"
		encoded, _ := saultcommon.EncodePublicKey(publicKey)
		user, _ := registry.AddUser(userID, encoded)
		user.IsAdmin = true
		registry.UpdateUser(user.ID, user)

		host, _ := registry.AddHost(hostID, "fake", uint64(22), []string{account})

		connMeta := &testSSHConn{user: fmt.Sprintf("%s+%s", account, host.ID)}

		_, err = conn.publicKeyCallback(connMeta, publicKey)
		if err != nil {
			t.Error(err)
		}
	}

}

func TestPublicKeyCallbackInSaultServer(t *testing.T) {
	registry, _ := saultregistry.NewTestRegistryFromBytes([]byte{})

	server, _ := NewServer(registry, nil, nil, nil, DefaultSaultServerName)

	conn := &connection{server: server, log: log.WithFields(logrus.Fields{})}

	privateKey, _ := saultcommon.CreateRSAPrivateKey(256)
	publicKey, _ := sssh.NewPublicKey(privateKey.Public())

	{
		// not admin
		var err error

		userID := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(publicKey)
		_, _ = registry.AddUser(userID, encoded)

		connMeta := &testSSHConn{user: DefaultSaultServerName}

		_, err = conn.publicKeyCallback(connMeta, publicKey)
		if err == nil {
			t.Errorf("'AuthenticationFailedError' must be occurred")
		}
		if _, ok := err.(*AuthenticationFailedError); !ok {
			t.Errorf("'AuthenticationFailedError' must be occurred: %v", err)
		}
	}

	{
		// admin, but with account name
		var err error

		userID := saultcommon.MakeRandomString()
		account := "ubuntu"
		encoded, _ := saultcommon.EncodePublicKey(publicKey)
		user, _ := registry.AddUser(userID, encoded)
		user.IsAdmin = true
		registry.UpdateUser(user.ID, user)

		connMeta := &testSSHConn{user: fmt.Sprintf("%s+%s", account, DefaultSaultServerName)}

		_, err = conn.publicKeyCallback(connMeta, publicKey)
		if err == nil {
			t.Errorf("'AuthenticationFailedError' must be occurred")
		}
		if _, ok := err.(*AuthenticationFailedError); !ok {
			t.Errorf("'AuthenticationFailedError' must be occurred: %v", err)
		}
	}

	{
		// admin
		var err error

		userID := saultcommon.MakeRandomString()
		encoded, _ := saultcommon.EncodePublicKey(publicKey)
		user, _ := registry.AddUser(userID, encoded)
		user.IsAdmin = true
		registry.UpdateUser(user.ID, user)

		connMeta := &testSSHConn{user: DefaultSaultServerName}

		_, err = conn.publicKeyCallback(connMeta, publicKey)
		if err != nil {
			t.Error(err)
		}
	}

}
