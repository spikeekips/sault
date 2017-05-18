package sault

import (
	"strings"

	"github.com/spikeekips/sault/ssh"
)

func responseUpdatePublicKey(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	publicKey := strings.TrimSpace(string(msg.Data))
	_, err = ParsePublicKeyFromString(publicKey)
	if err != nil {
		channel.Write([]byte(err.Error()))
		return
	}

	var userData UserRegistryData
	userData, err = pc.proxy.Registry.UpdateUserPublicKey(pc.userData.User, publicKey)
	if err != nil {
		channel.Write([]byte(err.Error()))
		return
	}
	err = pc.proxy.Registry.Sync()
	if err != nil {
		channel.Write([]byte(err.Error()))
		return
	}

	result, err := ExecuteCommonTemplate(`
{{ .result }}
{{ .line }}
successfully updated your publicKey
`,
		map[string]interface{}{
			"result": printUser(newUserResponseData(pc.proxy.Registry, userData)),
		},
	)
	if err != nil {
		channel.Write([]byte(err.Error()))
		return
	}

	channel.Write([]byte(result))
	return
}
