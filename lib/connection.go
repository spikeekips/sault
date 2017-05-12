package sault

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

type clientType uint8

const (
	saultClient clientType = iota + 1
	sshClient
)

type proxyConnection struct {
	net.Conn
	proxy *Proxy

	sshServerConfig *saultSsh.ServerConfig
	innerClient     *saultSsh.Client

	userData          UserRegistryData
	hostData          hostRegistryData
	manualAccountName string

	insideSault bool
	clientType  clientType
}

func (pc *proxyConnection) String() {
}

func (pc *proxyConnection) publicKeyCallback(conn saultSsh.ConnMetadata, key saultSsh.PublicKey) (*saultSsh.Permissions, error) {
	requestLog := log.WithFields(logrus.Fields{
		"RemoteAddr": conn.RemoteAddr(),
		"user":       conn.User(),
		//"key":        FingerprintSHA256(key),
		"key": FingerprintMD5PublicKey(key),
	})

	requestLog.Debug("trying to authenticate")

	manualAccountName, hostName, err := ParseAccountName(conn.User())
	if err != nil {
		return nil, errors.New("authentication failed, but something wrong; empty `conn.User()`")
	}

	var insideSault bool
	var userData UserRegistryData

	{
		var err error
		userData, err = pc.proxy.Registry.GetActiveUserByPublicKey(key)
		if err != nil {
			requestLog.Debugf("trying to access as inside-sault mode, but failed: %v", err)
			return nil, errors.New("authentication failed*")
		}
	}

	var hostData hostRegistryData
	if hostName == pc.proxy.Config.Server.ServerName {
		hostData = hostRegistryData{Host: pc.proxy.Config.Server.ServerName}
		/*
			if !userData.IsAdmin {
				requestLog.Debugf("trying to access as admin mode, but failed: %v, %v", userData, hostData)
				return nil, errors.New("authentication failed*")
			}
		*/

		insideSault = true
	} else {
		var err error
		hostData, err = pc.proxy.Registry.GetActiveHostByHostName(hostName)
		if err != nil {
			requestLog.Errorf("failed to authenticate: %v", err)
			return nil, errors.New("authentication failed")
		}

		if !userData.IsAdmin {
			if !pc.proxy.Registry.IsConnected(hostData.Host, userData.User, manualAccountName) {
				requestLog.Errorf("host, `%v` and user, `%v` is not connected", hostData, userData)
				return nil, errors.New("authentication failed")
			}
		}
	}

	requestLog.Debugf("authenticated; inside-sault mode: %v", insideSault)

	pc.userData = userData
	pc.hostData = hostData
	pc.manualAccountName = manualAccountName
	pc.insideSault = insideSault

	return nil, nil
}

func (pc *proxyConnection) handleNewConnection() error {
	conn, newChannels, requests, err := saultSsh.NewServerConn(pc, pc.sshServerConfig)
	if err != nil {
		log.Debugf("proxy.serve: %v", err)
		return err
	}

	defer conn.Close()

	go saultSsh.DiscardRequests(requests)

	if pc.insideSault {
		for newChannel := range newChannels {
			go func() {
				if err := pc.handleInsideSaultChannel(newChannel); err != nil {
					log.Errorf("%v", err)
					return
				}
			}()
		}
	} else {
		signer, err := pc.hostData.ClientPrivateKey.getSigner()
		if err != nil {
			log.Errorf("fail to load inner client key: %v", err)
			return err
		}

		if signer != nil {
			log.Debugf("ClientPrivateKey will be used")
		} else {
			signer = pc.proxy.Config.Server.globalClientKeySigner
			log.Debugf("ClientPrivateKey is missing, GlobalClientKeySigner will be used")
		}

		innerClient, err := createSSHClient(signer, pc.hostData.DefaultAccount, pc.hostData.GetFullAddress())
		if err != nil {
			log.Errorf("fail to create inner client: %v", err)
			return err
		}
		defer innerClient.Close()

		pc.innerClient = innerClient

		for newChannel := range newChannels {
			go func() {
				if err := pc.handleProxyChannel(newChannel); err != nil {
					log.Errorf("%v", err)
					return
				}
			}()
		}
	}

	return nil
}

func (pc *proxyConnection) handleInsideSaultChannel(newChannel saultSsh.NewChannel) error {
	proxyChannel, requests, err := newChannel.Accept()
	if err != nil {
		log.Errorf("Could not accept server channel: %v", err)
		return err
	}
	proxyChannel.SetProxy(false)
	defer proxyChannel.Close()

L:
	for request := range requests {
		switch t := request.Type; t {
		case "exec":
			log.Debugf("got inside-sault request.Type: %v", t)
		default:
			log.Debugf("got inside-sault request.Type: %v; not allowed", t)

			proxyChannel.SendRequest(
				"exit-status",
				true,
				saultSsh.Marshal(exitStatusMsg{Status: exitStatusNotAllowed}),
			)

			break L
		}

		var msg commandMsg
		if err := saultSsh.Unmarshal(request.Payload[4:], &msg); err == nil {
			pc.clientType = saultClient
		} else {
			log.Errorf("got invalid CommandMsg: %v", err)

			var em execMsg // when sent command using native ssh client
			if err := saultSsh.Unmarshal(request.Payload, &em); err != nil {
				log.Errorf("got invalid execMsg: %v", err)
				request.Reply(false, nil)

				break L
			}

			pc.clientType = sshClient
			log.Errorf("but got execMsg: %v", em)
			splitedCommand := strings.SplitN(em.Command, " ", 2)
			msg = commandMsg{
				Command: splitedCommand[0],
				Data:    []byte(strings.Join(splitedCommand[1:], " ")),
			}
		}
		request.Reply(true, nil)

		log.Debugf("got CommandMsg: %v", msg)
		exitStatus, err := handleCommandMsg(pc, proxyChannel, msg)
		if err != nil {
			log.Errorf("exitStatus: %v, err: %v", exitStatus, err)
		}

		proxyChannel.SendRequest(
			"exit-status",
			true,
			saultSsh.Marshal(exitStatusMsg{Status: exitStatus}),
		)
		log.Debugf("end request")

		break L

	}

	log.Debugf("end inside-sault")

	return nil
}

func (pc *proxyConnection) handleProxyChannel(newChannel saultSsh.NewChannel) error {
	proxyChannel, proxyRequests, err := newChannel.Accept()
	if err != nil {
		log.Errorf("Could not accept server channel: %v", err)
		return err
	}
	defer proxyChannel.Close()
	proxyChannel.SetProxy(true)

	innerChannel, innerRequests, err := pc.innerClient.OpenChannel(
		newChannel.ChannelType(),
		newChannel.ExtraData(),
	)
	if err != nil {
		log.Errorf("Could not accept inner client channel: %v", err)
		return err
	}
	defer innerChannel.Close()
	innerChannel.SetProxy(true)

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

		requestLog := log.WithFields(logrus.Fields{})
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

func createSSHClient(signer saultSsh.Signer, account, address string) (*saultSsh.Client, error) {
	log.Debugf("trying to make ssh client: account=%v address=%v", account, address)
	clientConfig := &saultSsh.ClientConfig{
		User: account,
		Auth: []saultSsh.AuthMethod{
			saultSsh.PublicKeys(signer),
		},
		HostKeyCallback: saultSsh.InsecureIgnoreHostKey(),
	}

	client, err := saultSsh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}
