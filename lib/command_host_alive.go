package sault

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spikeekips/sault/ssh"
)

var hostAliveOptionsTemplate = OptionsTemplate{
	Name: "alive",
	Help: "check the connectivity to host",
	Description: `
If you omit the <hostName>, try to check the all the available hosts.
	`,
	Usage:     "[flags] [<hostName>...]",
	ParseFunc: parsehostAliveOptions,
}

func parsehostAliveOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	hostNames := op.FlagSet.Args()
	for _, h := range hostNames {
		if !CheckHostName(h) {
			return &InvalidHostName{name: h}
		}
	}

	op.Extra["Hosts"] = hostNames

	return nil
}

func requesthostAlive(options OptionsValues, globalOptions OptionsValues) (exitStatus int) {
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

	hostNames := ov["Hosts"].([]string)

	var output []byte
	{
		var err error
		msg, err := newCommandMsg(
			"host.alive",
			hostAliveRequestData{Hosts: hostNames},
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

	var data []hostAliveResponseData
	if err := json.Unmarshal(rm.Result, &data); err != nil {
		log.Errorf("failed to unmarshal responseMsg: %v", err)
		exitStatus = 1
		return
	}

	jsoned, _ := json.MarshalIndent(data, "", "  ")
	log.Debugf("received data %v", string(jsoned))

	var maxHostNameLength int
	for _, result := range data {
		if maxHostNameLength < len(result.Host) {
			maxHostNameLength = len(result.Host)
		}
	}

	if len(data) < 1 {
		fmt.Println("no hosts found")
	} else {
		t, err := ExecuteCommonTemplate(`
{{ $format := .nameFormat }}{{ $length := len .data }}{{ if ne $length 0 }}Checked the hosts can be accessible or not.{{ range $result := .data }}
{{ if $result.Alive }}{{ $result.Host | align_format $format | green }}{{ else }}{{ $result.Host | align_format $format | red }}{{ end }} : {{ if $result.Alive }}-{{ else }}{{ $result.Error }}{{ end }}{{ end }}
{{ .line }}{{ end }}
The unavailable host is {{ "red" | red }}.
`,
			map[string]interface{}{
				"data":       data,
				"nameFormat": fmt.Sprintf("%%%ds", maxHostNameLength),
			},
		)
		if err != nil {
			log.Error(err)
		}
		fmt.Println(strings.TrimSpace(t))
	}

	return
}

func responsehostAlive(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostAliveRequestData
	json.Unmarshal(msg.Data, &data)

	var targets []hostRegistryData
	if len(data.Hosts) > 0 {
		for _, h := range data.Hosts {
			if hostData, err := pc.proxy.Registry.GetHostByHostName(h); err != nil {
				continue
			} else {
				targets = append(targets, hostData)
			}
		}
	} else {
		for _, hostData := range pc.proxy.Registry.GetHosts(activeFilterAll) {
			targets = append(targets, hostData)
		}
	}

	var wg sync.WaitGroup

	var results []hostAliveResponseData
	for _, hostData := range targets {
		wg.Add(1)

		go func(hostData hostRegistryData) {
			defer wg.Done()

			sc := newsshClient(hostData.DefaultAccount, hostData.GetFullAddress())
			sc.addAuthMethod(saultSsh.PublicKeys(pc.proxy.Config.Server.globalClientKeySigner))
			sc.setTimeout(time.Second * 3)

			r := hostAliveResponseData{Host: hostData.Host}
			if err = sc.connect(); err != nil {
				r.Alive = false
				r.Error = err.Error()
				log.Errorf("dead, `%s`: %v", hostData.Host, err)
			} else {
				r.Alive = true
				log.Debugf("alive, `%s`", hostData.Host)
			}

			results = append(results, r)
		}(hostData)
	}
	wg.Wait()

	channel.Write(toResponse(results, nil))
	return
}
