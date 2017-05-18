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

func requesthostAlive(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)

	var clientPublicKey saultSsh.PublicKey
	if gov["ClientPublicKey"] != nil {
		clientPublicKey = gov["ClientPublicKey"].(saultSsh.PublicKey)
	}

	var response *responseMsg
	var data []hostAliveResponseData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		gov["SaultServerAddress"].(string),
		clientPublicKey,
		"host.alive",
		hostAliveRequestData{Hosts: ov["Hosts"].([]string)},
		&data,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	var maxHostNameLength int
	for _, result := range data {
		if maxHostNameLength < len(result.Host) {
			maxHostNameLength = len(result.Host)
		}
	}

	var maxUriLength int
	for _, result := range data {
		if maxUriLength < len(result.Uri) {
			maxUriLength = len(result.Uri)
		}
	}

	if len(data) < 1 {
		CommandOut.Println("no hosts found")
	} else {
		var t string
		t, err = ExecuteCommonTemplate(`
{{ $hostNameFormat := .hostNameFormat }}
{{ $uriFormat := .uriFormat }}
{{ $length := len .data }}{{ if ne $length 0 }}Checked the hosts can be accessible or not.{{ range $result := .data }}
{{ if $result.Alive }}{{ $result.Host | align_format $hostNameFormat | green }}{{ else }}{{ $result.Host | align_format $hostNameFormat | red }}{{ end }}: {{ $result.Uri | align_format $uriFormat }} - {{ if $result.Alive }}{{ else }}{{ $result.Error }}{{ end }}{{ end }}
{{ .line }}{{ end }}
The unavailable host is {{ "red" | red }}.
`,
			map[string]interface{}{
				"data":           data,
				"hostNameFormat": fmt.Sprintf("%%%ds", maxHostNameLength),
				"uriFormat":      fmt.Sprintf("%%-%ds", maxUriLength),
			},
		)
		if err != nil {
			return
		}
		CommandOut.Println(strings.TrimSpace(t))
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
			defer sc.close()

			r := hostAliveResponseData{
				Host: hostData.Host,
				Uri:  fmt.Sprintf("%s@%s", hostData.DefaultAccount, hostData.GetFullAddress()),
			}
			if err = sc.connect(); err != nil {
				r.Alive = false
				r.Error = err.Error()
			} else {
				r.Alive = true
			}

			results = append(results, r)
		}(hostData)
	}
	wg.Wait()

	var response []byte
	response, err = newResponseMsg(
		results,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)
	return
}
