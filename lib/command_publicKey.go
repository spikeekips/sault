package sault

import (
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/ssh"
)

func ResponseUpdatePublicKey(pc *proxyConnection, channel saultSsh.Channel, msg CommandMsg) (exitStatus uint32, err error) {
	log.Debugf("trying to update publicKey")

	publicKey := strings.TrimSpace(string(msg.Data))
	_, err = ParsePublicKeyFromString(publicKey)
	if err != nil {
		log.Error(err)
		channel.Write([]byte(err.Error()))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.UpdateUserPublicKey(pc.userData.User, publicKey)
	if err != nil {
		log.Error(err)
		channel.Write([]byte(err.Error()))
		return
	}
	err = pc.proxy.Registry.Sync()
	if err != nil {
		log.Error(err)
		channel.Write([]byte(err.Error()))
		return
	}

	result := FormatResponse(`
{{ .result }}
{{ .line }}
successfully updated your publicKey
`,
		map[string]interface{}{
			"result": PrintUser(NewUserResponseData(pc.proxy.Registry, userData)),
		},
	)

	channel.Write([]byte(result))
	return
}
