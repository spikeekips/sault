package sault

import (
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

type authenticationFailedError struct {
	Err error
}

func (e *authenticationFailedError) Error() string {
	return fmt.Sprintf("failed to be authenticated: %v", e.Err)
}

type connection struct {
	net.Conn
	server *Server

	log *logrus.Entry

	account      string
	user         saultregistry.UserRegistry
	host         saultregistry.HostRegistry
	insideSault  bool
	openChannels []func()
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

func (c *connection) getServerConfig() *saultssh.ServerConfig {
	serverConfig := &saultssh.ServerConfig{
		PublicKeyCallback: c.publicKeyCallback,
	}

	serverConfig.AddHostKey(c.server.hostKeySigner)
	return serverConfig
}

func (c *connection) addOpenChannel(f func()) {
	c.openChannels = append(c.openChannels, f)
}

func (c *connection) close() {
	for _, closeFunc := range c.openChannels {
		closeFunc()
	}
	c.Conn.Close()
	c.log.Debugf("cilent connection closed")
}

func (c *connection) publicKeyCallback(
	conn saultssh.ConnMetadata,
	publicKey saultssh.PublicKey,
) (perm *saultssh.Permissions, err error) {
	account, hostID, err := saultcommon.ParseSaultAccountName(conn.User())
	if err != nil {
		err = &authenticationFailedError{Err: err}
		c.log.Error(err)
		return
	}

	var user saultregistry.UserRegistry
	user, err = c.server.registry.GetUser("", publicKey, saultregistry.UserFilterIsActive)
	if err != nil {
		err = &authenticationFailedError{Err: err}
		c.log.Error(err)
		return
	}

	if hostID == c.server.saultServerName {
		return c.publicKeyCallbackInsideSault(conn, publicKey, user, account, hostID)
	}

	var host saultregistry.HostRegistry
	host, err = c.server.registry.GetHost(hostID, saultregistry.HostFilterIsActive)
	if err != nil {
		err = &authenticationFailedError{Err: err}
		c.log.Error(err)
		return
	}
	if !host.HasAccount(account) {
		err = &authenticationFailedError{Err: fmt.Errorf("unknown account, '%s'", account)}
		c.log.Error(err)
		return
	}

	if !c.server.registry.IsLinked(user.ID, host.ID, account) {
		err = &authenticationFailedError{
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
	conn saultssh.ConnMetadata,
	publicKey saultssh.PublicKey,
	user saultregistry.UserRegistry,
	account, hostID string,
) (perm *saultssh.Permissions, err error) {
	c.insideSault = true

	if len(account) > 0 {
		err = &authenticationFailedError{
			Err: &saultcommon.InvalidAccountNameError{Name: account},
		}
		c.log.Errorf("in 'inSaultServer', account name is prohibited")
		return
	}

	/*
		if !user.IsAdmin {
			err = &AuthenticationFailedError{
				Err: fmt.Errorf("trying to enter sault server, but user, '%s' is not admin", user),
			}
			c.log.Error(err)
			return
		}
	*/

	c.user = user

	c.log.Debugf("authenticated; %s, inside sault", user)

	return nil, nil
}

func (c *connection) openConnection() error {
	conn, channels, requests, err := saultssh.NewServerConn(c, c.getServerConfig())
	if err != nil {
		c.log.Error(err)
		return err
	}

	defer conn.Close()

	go saultssh.DiscardRequests(requests)
	/*
		go func(in <-chan *saultssh.Request) {
			for request := range in {
				c.log.WithFields(logrus.Fields{
					"requestType":    request.Type,
					"requestPayload": len(request.Payload),
				}).Debugf("got channel request")

				if request.WantReply {
					request.Reply(true, nil)
				}
			}
		}(requests)
	*/

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
