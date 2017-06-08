package sault

import (
	"io"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/sssh"
)

func (c *connection) openProxyConnection(
	channels <-chan sssh.NewChannel,
) error {
	innerclient := saultcommon.NewSSHClient(c.account, c.host.GetAddress())
	innerclient.AddAuthMethod(sssh.PublicKeys(c.server.clientKeySigner))
	innerclient.SetTimeout(DefaultTimeoutProxyClient)

	if err := innerclient.Connect(); err != nil {
		c.log.Error(err)
		return err
	}
	defer innerclient.Close()

	for channel := range channels {
		go func() {
			if err := c.openProxyChannel(innerclient, channel); err != nil {
				c.log.Error(err)
				return
			}
		}()
	}

	return nil
}

func (c *connection) openProxyChannel(innerclient *saultcommon.SSHClient, channel sssh.NewChannel) error {
	proxyChannel, proxyRequests, err := channel.Accept()
	if err != nil {
		c.log.Error(err)
		return err
	}
	defer proxyChannel.Close()
	proxyChannel.SetProxy(true)

	innerChannel, innerRequests, err := innerclient.Client.OpenChannel(
		channel.ChannelType(),
		channel.ExtraData(),
	)
	if err != nil {
		log.Error(err)
		return err
	}
	defer innerChannel.Close()
	innerChannel.SetProxy(true)

	go io.Copy(proxyChannel, innerChannel)
	go io.Copy(innerChannel, proxyChannel)

	var requestOrigin string
	for {
		var request *sssh.Request
		var toChannel sssh.Channel

		select {
		case request = <-proxyRequests:
			toChannel = innerChannel

			requestOrigin = "client"
		case request = <-innerRequests:
			toChannel = proxyChannel

			requestOrigin = "host"
		}

		if request == nil {
			break
		}

		rlog := c.log.WithFields(logrus.Fields{
			"from":        requestOrigin,
			"requestType": request.Type,
		})

		rlog.Debug("got request")

		if request.Type == "EOF" {
			toChannel.CloseWrite()
			continue
		}

		ok, err := toChannel.SendRequest(request.Type, request.WantReply, request.Payload)
		if err != nil {
			rlog.Error(err)
		}

		request.Reply(ok, nil)

		switch request.Type {
		case "exit-status":
			break
		case "pty-req":
			// TODO: print welcome message
		default:
			//
		}
	}

	return nil
}
