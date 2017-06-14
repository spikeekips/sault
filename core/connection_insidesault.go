package sault

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/saultssh"
)

var exitStatusNotAllowed uint32 = 254
var exitStatusInvalidRequest uint32 = 255

type exitStatusMsg struct {
	Status uint32
}

func (c *connection) openInsideSaultConnection(
	channels <-chan saultssh.NewChannel,
) error {
	for channel := range channels {
		c.log.Debugf("got new channel: %v(%d)", channel.ChannelType(), len(channel.ExtraData()))
		switch channel.ChannelType() {
		case "direct-tcpip":
			go func() {
				if err := c.openInsideSaultDirectTCPIPChannel(channel); err != nil {
					c.log.Error(err)
					return
				}
			}()
		case "session":
			go func() {
				if err := c.openInsideSaultSessionChannel(channel); err != nil {
					c.log.Error(err)
					return
				}
			}()
		}
	}

	return nil
}

func sendExitStatusThruChannel(channel saultssh.Channel, status uint32) {
	channel.SendRequest(
		"exit-status",
		true,
		saultssh.Marshal(exitStatusMsg{Status: status}),
	)
}

type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

func (c *connection) openInsideSaultDirectTCPIPChannel(channel saultssh.NewChannel) (err error) {
	var msg channelOpenDirectMsg
	if err = saultssh.Unmarshal(channel.ExtraData(), &msg); err != nil {
		return
	}

	var newChannel saultssh.Channel
	newChannel, _, err = channel.Accept()
	if err != nil {
		c.log.Error(err)
		return
	}
	defer newChannel.Close()
	newChannel.SetProxy(false)

	remoteAddress := fmt.Sprintf("%s:%d", msg.Raddr, msg.Rport)

	var remoetListener net.Conn
	remoetListener, err = net.Dial("tcp", remoteAddress)
	if err != nil {
		c.log.Error(err)
		return err
	}
	defer remoetListener.Close()

	c.addOpenChannel(func() {
		remoetListener.Close()
		newChannel.Close()
	})
	c.log.Debugf("open host listener: %s", remoteAddress)

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(newChannel, remoetListener); err != nil {
			c.log.Error(err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(remoetListener, newChannel); err != nil {
			c.log.Error(err)
		}
	}()
	wg.Wait()

	return nil
}

func (c *connection) openInsideSaultSessionChannel(channel saultssh.NewChannel) error {
	newChannel, requests, err := channel.Accept()
	if err != nil {
		c.log.Error(err)
		return err
	}
	defer newChannel.Close()
	newChannel.SetProxy(false)

L:
	for request := range requests {
		rlog := c.log.WithFields(logrus.Fields{
			"insideSault":    c.insideSault,
			"requestType":    request.Type,
			"requestPayload": len(request.Payload),
		})

		rlog.Debugf("got request")

		switch t := request.Type; t {
		case "exec":
			if err := c.handleCommandMsg(newChannel, request, rlog); err != nil {
				rlog.Debugf("error: %v", err)
				return err
			}

			break L
		default:
			rlog.Debugf("request.Type: %v, but not allowed", t)

			rendered, _ := saultcommon.SimpleTemplating(
				`{{ "* sault" | blue }} {{ "error" | red }} This kind of access is not allowed. hejdå vän~`,
				nil,
			)
			newChannel.Write([]byte(rendered + "\r\n"))

			sendExitStatusThruChannel(newChannel, exitStatusNotAllowed)

			break L
		}
	}

	return nil
}

func parseSaultCommandMsg(payload []byte) (saultcommon.CommandMsg, error) {
	{
		var msg saultcommon.CommandMsg
		if err := saultssh.Unmarshal(payload, &msg); err == nil {
			msg.IsSaultClient = true
			return msg, nil
		}
	}

	args := strings.Fields(string(payload))
	msg, err := saultcommon.NewCommandMsg(args[0], args[1:])

	return *msg, err
}

func (c *connection) handleCommandMsg(channel saultssh.Channel, request *saultssh.Request, rlog *logrus.Entry) (err error) {
	var msg saultcommon.CommandMsg
	if msg, err = parseSaultCommandMsg(request.Payload[4:]); err != nil {
		sendExitStatusThruChannel(channel, exitStatusInvalidRequest)
		return
	}

	rlog.Debugf("CommandMsg: %v", msg)

	request.Reply(true, nil)

	var command Command
	{
		var ok bool
		if command, ok = Commands[msg.Name]; !ok {
			err = fmt.Errorf("unknown command name, '%s'", msg.Name)
			if !msg.IsSaultClient {
				t, _ := saultcommon.SimpleTemplating("{{ \"error\" | red }} {{ . }}\r\n", err)
				channel.Write([]byte(t))
				return
			}
			response, _ := saultcommon.NewResponseMsg(
				nil,
				saultcommon.CommandErrorCommon,
				err,
			).ToJSON()
			channel.Write(response)

			return
		}

		switch msg.Name {
		case "whoami":
			//
		case "publickey":
			//
		default:
			if !c.user.IsAdmin {
				if !msg.IsSaultClient {
					t, _ := saultcommon.SimpleTemplating("{{ \"error\" | red }} Prohibited\r\n", nil)
					fmt.Println(t)
					channel.Write([]byte(t))
					err = errors.New("")
				} else {
					response, _ := saultcommon.NewResponseMsg(
						nil,
						saultcommon.CommandErrorCommon,
						fmt.Errorf("Prohibited"),
					).ToJSON()
					channel.Write(response)

					sendExitStatusThruChannel(channel, 0)
					err = nil
				}
				return
			}
		}
	}

	err = command.Response(c.user, channel, msg, c.server.registry, c.server.config)
	if err != nil {
		if !msg.IsSaultClient {
			t, _ := saultcommon.SimpleTemplating("{{ \"error\" | red }} {{ . }}\r\n", err)
			channel.Write([]byte(t))
			return
		} else {
			if responseErr, ok := err.(*saultcommon.ResponseMsgError); ok {
				return responseErr
			}

			response, _ := saultcommon.NewResponseMsg(
				nil,
				saultcommon.CommandErrorCommon,
				err,
			).ToJSON()
			channel.Write(response)
		}
	}

	sendExitStatusThruChannel(channel, 0)
	rlog.Debugf("request end")

	return err
}
