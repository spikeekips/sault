package sault

import (
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

type Proxy struct {
	Config   *Config
	Registry Registry
}

func NewProxy(config *Config, registry Registry) (*Proxy, error) {
	return &Proxy{Config: config, Registry: registry}, nil
}

func (p *Proxy) Run() error {
	listener, err := net.Listen("tcp", p.Config.Server.Bind)
	if err != nil {
		log.Errorf("net.Listen failed: %v", err)
		return err
	}

	log.Infof("listen %s", listener.Addr().String())

	defer listener.Close()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Errorf("net.Accept failed: %v", err)
			clientConn.Close()
			continue
		}

		proxyConnection, err := p.newConnection(clientConn)
		if err != nil {
			log.Errorf("failed to create proxy connection: %v", err)
			clientConn.Close()
			continue
		}

		go func() {
			if err := proxyConnection.handleNewConnection(); err != nil {
				log.Errorf("proxy.handleNewConnection failed: %v", err)
			}
			proxyConnection.Close()
			clientConn.Close()
			log.Debugf("connection closed")
		}()
	}

	return nil
}

func (p *Proxy) newConnection(conn net.Conn) (*proxyConnection, error) {
	proxyConnection := &proxyConnection{Conn: conn, proxy: p}

	// `saultSsh.ServerConfig` for proxy server
	sshServerConfig := &saultSsh.ServerConfig{
		PublicKeyCallback: proxyConnection.publicKeyCallback,
	}

	config := *p.Config

	sshServerConfig.AddHostKey(config.Server.hostKeySigner)
	proxyConnection.sshServerConfig = sshServerConfig

	return proxyConnection, nil
}
