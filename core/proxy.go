package sault

import (
	"net"

	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

// Server is the main server of sault
type Server struct {
	saultServerName string
	registry        *saultregistry.Registry
	config          *Config
	hostKeySigner   saultssh.Signer
	clientKeySigner saultssh.Signer
}

// NewServer makes server
func NewServer(
	registry *saultregistry.Registry,
	config *Config,
	hostKeySigner saultssh.Signer,
	clientKeySigner saultssh.Signer,
	saultServerName string,
) (*Server, error) {
	return &Server{
		saultServerName: saultServerName,
		registry:        registry,
		config:          config,
		hostKeySigner:   hostKeySigner,
		clientKeySigner: clientKeySigner,
	}, nil
}

// Run runs sault server
func (p *Server) Run(bind string) (err error) {
	var listener net.Listener
	listener, err = net.Listen("tcp", bind)
	if err != nil {
		log.Error(err)
		return
	}
	defer listener.Close()

	log.Infof("started to listen %s", listener.Addr().String())

	for {
		var clientConn net.Conn
		clientConn, err = listener.Accept()
		if err != nil {
			log.Error(err)
			clientConn.Close()
			continue
		}

		if _, err = newConnection(p, clientConn); err != nil {
			log.Error(err)
			clientConn.Close()
			continue
		}
	}

	return nil
}
