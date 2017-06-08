package sault

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/sssh"
)

var exitStatusNotAllowed uint32 = 254
var exitStatusInvalidRequest uint32 = 255

type exitStatusMsg struct {
	Status uint32
}

func (c *connection) openInsideSaultConnection(
	channels <-chan sssh.NewChannel,
) error {
	for channel := range channels {
		go func() {
			if err := c.openInsideSaultChannel(channel); err != nil {
				c.log.Error(err)
				return
			}
		}()
	}

	return nil
}

func sendExitStatusThruChannel(channel sssh.Channel, status uint32) {
	channel.SendRequest(
		"exit-status",
		true,
		sssh.Marshal(exitStatusMsg{Status: status}),
	)
}

func (c *connection) openInsideSaultChannel(channel sssh.NewChannel) error {
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
			"insideSault": c.insideSault,
			"requestType": request.Type,
		})

		switch t := request.Type; t {
		case "exec":
			rlog.Debugf("request.Type: %v", t)
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

		var msg saultcommon.CommandMsg
		if err := sssh.Unmarshal(request.Payload[4:], &msg); err != nil {
			sendExitStatusThruChannel(newChannel, exitStatusInvalidRequest)
			return err
		}
		rlog.Debugf("CommandMsg: %v", msg)

		request.Reply(true, nil)

		if err := c.handleCommandMsg(newChannel, msg); err != nil {
			rlog.Debugf("error: %v", err)
		}

		sendExitStatusThruChannel(newChannel, 0)
		rlog.Debugf("request end")

		break L

	}

	return nil
}

func (c *connection) handleCommandMsg(channel sssh.Channel, msg saultcommon.CommandMsg) (err error) {
	var command Command
	{
		var ok bool
		if command, ok = Commands[msg.Name]; !ok {
			err = fmt.Errorf("unknown command name, '%s'", msg.Name)
			response, _ := saultcommon.NewResponseMsg(
				nil,
				saultcommon.CommandErrorCommon,
				err,
			).ToJSON()
			channel.Write(response)

			return
		}
	}

	err = command.Response(channel, msg, c.server.registry, c.server.config)
	if err != nil {
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

	return err
}
