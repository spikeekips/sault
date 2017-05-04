package sault

import (
	"errors"
	"io"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

type proxyConnection struct {
	net.Conn
	proxy *Proxy

	sshServerConfig *saultSsh.ServerConfig
	innerClient     *saultSsh.Client

	userData          UserRegistryData
	hostData          HostRegistryData
	manualAccountName string
}

func (pc *proxyConnection) String() {
}

func (pc *proxyConnection) publicKeyCallback(conn saultSsh.ConnMetadata, key saultSsh.PublicKey) (*saultSsh.Permissions, error) {
	manualAccountName, hostName, err := ParseAccountName(conn.User())
	if err != nil {
		return nil, errors.New("authentication failed, but something wrong; empty `conn.User()`")
	}
	userData, hostData, err := pc.proxy.Registry.GetConnectedByPublicKeyAndHostName(
		key,
		hostName,
		manualAccountName,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"RemoteAddr":        conn.RemoteAddr(),
			"hostName":          hostName,
			"manualAccountName": manualAccountName,
		}).Errorf("failed to authenticate: %v", err)
		return nil, errors.New("authentication failed")
	}

	log.WithFields(log.Fields{
		"RemoteAddr":        conn.RemoteAddr(),
		"hostName":          hostName,
		"manualAccountName": manualAccountName,
		"userData":          userData,
		"hostData":          hostData,
	}).Debug("authenticated")

	pc.userData = userData
	pc.hostData = hostData
	pc.manualAccountName = manualAccountName

	return nil, nil
}

func (pc *proxyConnection) handleNewConnection() error {
	conn, newChannels, requests, err := saultSsh.NewServerConn(pc, pc.sshServerConfig)
	if err != nil {
		log.Debugf("proxy.serve: %v", err)
		return err
	}

	defer conn.Close()

	innerClient, err := pc.createInnerClient()
	if err != nil {
		log.Errorf("fail to create inner client: %v", err)
		return err
	}
	defer innerClient.Close()

	pc.innerClient = innerClient

	go saultSsh.DiscardRequests(requests)

	for newChannel := range newChannels {
		go func() {
			if err := pc.handleChannel(newChannel); err != nil {
				log.Errorf("%v", err)
				return
			}
		}()
	}

	return nil
}

func (pc *proxyConnection) handleChannel(newChannel saultSsh.NewChannel) error {
	proxyChannel, proxyRequests, err := newChannel.Accept()
	if err != nil {
		log.Errorf("Could not accept server channel: %v", err)
		return err
	}
	defer proxyChannel.Close()

	innerChannel, innerRequests, err := pc.innerClient.OpenChannel(
		newChannel.ChannelType(),
		newChannel.ExtraData(),
	)
	if err != nil {
		log.Errorf("Could not accept inner client channel: %v", err)
		return err
	}
	defer innerChannel.Close()

	go io.Copy(proxyChannel, innerChannel)
	go io.Copy(innerChannel, proxyChannel)

	var requestOrigin string
	for {
		var request *saultSsh.Request
		var toChannel saultSsh.Channel
		var fromChannel saultSsh.Channel

		select {
		case request = <-proxyRequests:
			toChannel = innerChannel
			fromChannel = proxyChannel

			requestOrigin = "client"
		case request = <-innerRequests:
			toChannel = proxyChannel
			fromChannel = innerChannel

			requestOrigin = "host"
		}

		if request == nil {
			log.Debug("request == nil")
			break
		}

		requestLog := log.WithFields(log.Fields{})
		requestLog.Debugf("got request message from %s: %v", requestOrigin, fromChannel)
		requestLog.Debugf("request.Type: %v", request.Type)

		if request.Type == "EOF" {
			toChannel.CloseWrite()
			continue
		}

		ok, err := toChannel.SendRequest(request.Type, request.WantReply, request.Payload)
		if err != nil {
			log.Errorf("failed to `toChannel.SendRequest`: %v", err)
		}

		request.Reply(ok, nil)

		switch request.Type {
		case "exit-status":
			break
		default:
			//
		}
	}

	return nil
}

func (pc *proxyConnection) createInnerClient() (*saultSsh.Client, error) {
	signer, err := pc.hostData.ClientPrivateKey.GetSigner()
	if err != nil {
		log.Errorf("fail to load inner client key: %v", err)
		return nil, err
	}

	if signer != nil {
		log.Debugf("ClientPrivateKey for host will be used")
	} else {
		signer = pc.proxy.Config.Server.globalClientKeySigner
		log.Debugf("ClientPrivateKey for host is missing, so GlobalClientKeySigner will be used")
	}
	innerClientConfig := &saultSsh.ClientConfig{
		User: pc.hostData.DefaultAccount,
		Auth: []saultSsh.AuthMethod{
			saultSsh.PublicKeys(signer),
		},
		HostKeyCallback: saultSsh.InsecureIgnoreHostKey(),
	}

	innerClient, err := saultSsh.Dial("tcp", pc.hostData.GetFullAddress(), innerClientConfig)
	if err != nil {
		return nil, err
	}

	return innerClient, nil
}
