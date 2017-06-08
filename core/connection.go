package sault

import (
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/sssh"
)

type AuthenticationFailedError struct {
	Err error
}

func (e *AuthenticationFailedError) Error() string {
	return fmt.Sprintf("failed to be authenticated: %v", e.Err)
}

type connection struct {
	net.Conn
	server *Server

	log *logrus.Entry

	account     string
	user        saultregistry.UserRegistry
	host        saultregistry.HostRegistry
	insideSault bool
}

func newConnection(server *Server, conn net.Conn) (*connection, error) {
	pconn := &connection{
		Conn:   conn,
		server: server,
		log: log.WithFields(logrus.Fields{
			"id":         fmt.Sprintf("%v", &conn),
			"remoteAddr": conn.RemoteAddr(),
		}),
	}

	pconn.log.Debugf("client connected")

	go func() {
		defer pconn.close()

		if err := pconn.openConnection(); err != nil {
			pconn.log.Error(err)
		}
	}()

	return pconn, nil
}

func (c *connection) getServerConfig() *sssh.ServerConfig {
	serverConfig := &sssh.ServerConfig{
		PublicKeyCallback: c.publicKeyCallback,
	}

	serverConfig.AddHostKey(c.server.hostKeySigner)
	return serverConfig
}

func (c *connection) close() {
	c.Conn.Close()
	c.log.Debugf("cilent connection closed")
}

func (c *connection) publicKeyCallback(
	conn sssh.ConnMetadata,
	publicKey sssh.PublicKey,
) (perm *sssh.Permissions, err error) {
	account, hostID, err := saultcommon.ParseSaultAccountName(conn.User())
	if err != nil {
		err = &AuthenticationFailedError{Err: err}
		c.log.Error(err)
		return
	}

	var user saultregistry.UserRegistry
	user, err = c.server.registry.GetUser("", publicKey, saultregistry.UserFilterIsActive)
	if err != nil {
		err = &AuthenticationFailedError{Err: err}
		c.log.Error(err)
		return
	}

	if hostID == c.server.saultServerName {
		return c.publicKeyCallbackInsideSault(conn, publicKey, user, account, hostID)
	}

	var host saultregistry.HostRegistry
	host, err = c.server.registry.GetHost(hostID, saultregistry.HostFilterIsActive)
	if err != nil {
		err = &AuthenticationFailedError{Err: err}
		c.log.Error(err)
		return
	}
	if !host.HasAccount(account) {
		err = &AuthenticationFailedError{Err: fmt.Errorf("unknown account, '%s'", account)}
		c.log.Error(err)
		return
	}

	if !user.IsAdmin && !c.server.registry.IsLinked(user.ID, host.ID, account) {
		err = &AuthenticationFailedError{
			Err: fmt.Errorf(
				"user, '%s' host, '%s' and it's account, '%s' is not linked",
				user.ID,
				host.ID,
				account,
			),
		}
		c.log.Error(err)
		return
	}

	c.account = account
	c.user = user
	c.host = host

	c.log.Debugf("authenticated; %s, %s", user, host)

	return nil, nil
}

func (c *connection) publicKeyCallbackInsideSault(
	conn sssh.ConnMetadata,
	publicKey sssh.PublicKey,
	user saultregistry.UserRegistry,
	account, hostID string,
) (perm *sssh.Permissions, err error) {
	c.insideSault = true

	if len(account) > 0 {
		err = &AuthenticationFailedError{
			Err: &saultcommon.InvalidAccountNameError{Name: account},
		}
		c.log.Errorf("in 'inSaultServer', account name is prohibited")
		return
	}

	if !user.IsAdmin {
		err = &AuthenticationFailedError{
			Err: fmt.Errorf("trying to enter sault server, but user, '%s' is not admin", user),
		}
		c.log.Error(err)
		return
	}

	c.user = user

	c.log.Debugf("authenticated; %s, inside sault", user)

	return nil, nil
}

func (c *connection) openConnection() error {
	conn, channels, requests, err := sssh.NewServerConn(c, c.getServerConfig())
	if err != nil {
		c.log.Error(err)
		return err
	}

	defer conn.Close()

	go sssh.DiscardRequests(requests)

	{
		var err error
		if c.insideSault {
			err = c.openInsideSaultConnection(channels)
		} else {
			err = c.openProxyConnection(channels)
		}
		if err != nil {
			c.log.Error(err)
			return err
		}
	}

	return nil
}
