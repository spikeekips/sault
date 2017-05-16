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

func requestUserRemove(options OptionsValues, globalOptions OptionsValues) (exitStatus int, err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	userName := ov["UserName"].(string)

	exitStatus, err = RunCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		"user.remove",
		userRemoveRequestData{
			User: userName,
		},
		nil,
	)
	if err != nil {
		log.Error(err)
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

		return
	}

	err = pc.proxy.Registry.Sync()
	if err != nil {
		return
	}

	channel.Write(toResponse(nil, nil))
	return
}
