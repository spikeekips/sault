package sault

import (
	"net"

	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/sssh"
)

type Server struct {
	saultServerName string
	registry        *saultregistry.Registry
	config          *Config
	hostKeySigner   sssh.Signer
	clientKeySigner sssh.Signer
}

func NewServer(
	registry *saultregistry.Registry,
	config *Config,
	hostKeySigner sssh.Signer,
	clientKeySigner sssh.Signer,
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
