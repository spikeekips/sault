package sault

import (
	"encoding/json"
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

var UserRemoveOptionsTemplate OptionsTemplate = OptionsTemplate{
	Name:      "remove",
	Help:      "remove user",
	Usage:     "[flags] <userName>",
	Options:   []OptionTemplate{AtOptionTemplate, POptionTemplate},
	ParseFunc: ParseUserRemoveOptions,
}

func ParseUserRemoveOptions(op *Options, args []string) error {
	err := ParseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("<userName> is missing")
	}

	op.Extra["UserName"] = args[0]

	return nil
}

func RequestUserRemove(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)
	address := ov["SaultServerAddress"].(string)
	serverName := ov["SaultServerName"].(string)

	connection, err := makeConnectionForSaultServer(serverName, address)
	if err != nil {
		log.Error(err)

		exitStatus = 1
		return
	}

	userName := ov["UserName"].(string)

	var output []byte
	{
		var err error
		msg, err := NewCommandMsg(
			"user.remove",
			UserRemoveRequestData{
				UserName: userName,
			},
		)
		if err != nil {
			log.Errorf("failed to make message: %v", err)
			exitStatus = 1
			return
		}

		log.Debug("msg sent")
		output, exitStatus, err = runCommand(connection, msg)
		if err != nil {
			log.Error(err)
			return
		}
	}

	var responseMsg ResponseMsg
	if err := saultSsh.Unmarshal(output, &responseMsg); err != nil {
		log.Errorf("got invalid response: %v", err)
		exitStatus = 1
		return
	}

	if responseMsg.Error != "" {
		log.Errorf("%s", responseMsg.Error)
		exitStatus = 1

		return
	}

	fmt.Fprintf(os.Stdout, "user, `%s` was removed", userName)

	exitStatus = 0

	return
}

func ResponseUserRemove(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	var data UserRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to remove user: %v", data)
	err = pc.proxy.Registry.RemoveUser(data.UserName)
	if err != nil {
		log.Errorf("failed to remove user: %v", err)

		channel.Write(ToResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(ToResponse(nil, err))
		return
	}

	channel.Write(ToResponse(nil, nil))
	return
}
