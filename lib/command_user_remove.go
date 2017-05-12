package sault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spikeekips/sault/ssh"
)

var userRemoveOptionsTemplate = OptionsTemplate{
	Name:      "remove",
	Help:      "remove user",
	Usage:     "[flags] <userName>",
	ParseFunc: parseUserRemoveOptions,
}

func parseUserRemoveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("<userName> is missing")
	}

	op.Extra["UserName"] = args[0]

	return nil
}

func requestUserRemove(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)
	serverName := gov["SaultServerName"].(string)

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
		msg, err := newCommandMsg(
			"user.remove",
			userRemoveRequestData{
				User: userName,
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

	var rm responseMsg
	if err := saultSsh.Unmarshal(output, &rm); err != nil {
		log.Errorf("got invalid response: %v", err)
		exitStatus = 1
		return
	}

	if rm.Error != "" {
		log.Errorf("%s", rm.Error)
		exitStatus = 1

		return
	}

	fmt.Fprintf(os.Stdout, "user, `%s` was removed", userName)

	exitStatus = 0

	return
}

func responseUserRemove(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data userRemoveRequestData
	json.Unmarshal(msg.Data, &data)

	log.Debugf("trying to remove user: %v", data)
	err = pc.proxy.Registry.RemoveUser(data.User)
	if err != nil {
		log.Errorf("failed to remove user: %v", err)

		channel.Write(toResponse(nil, err))
		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write(toResponse(nil, err))
		return
	}

	channel.Write(toResponse(nil, nil))
	return
}
