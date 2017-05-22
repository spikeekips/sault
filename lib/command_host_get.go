package sault

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

var hostGetOptionsTemplate = OptionsTemplate{
	Name:  "get",
	Help:  "get host",
	Usage: "[flags] [<hostName>...]",
	Options: []OptionTemplate{
		OptionTemplate{
			Name:         "Filter",
			Help:         "filter hosts by state, [ active deactivated ]",
			DefaultValue: "",
		},
	},
	ParseFunc:   parseHostGetOptions,
	Description: descriptionHostGet,
}

func parseHostGetOptions(op *Options, args []string) error {
	err := parseBaseCommandOptions(op, args)
	if err != nil {
		return err
	}

	hostNames := op.FlagSet.Args()

	op.Extra["HostNames"] = []string{}
	{
		for _, h := range hostNames {
			if !CheckHostName(h) {
				return fmt.Errorf("invalid hostName, '%s' found", h)
			}
		}

		op.Extra["HostNames"] = hostNames
	}

	{
		var filter activeFilter
		f := *op.Vars["Filter"].(*string)
		if f != "" {
			switch f {
			case "active":
				filter = activeFilterActive
			case "deactivated":
				filter = activeFilterDeactivated
			default:
				return fmt.Errorf("invalid filter, '%s' found", f)

			}

			op.Extra["ActiveFilter"] = filter
		}
	}

	return nil
}

func requestHostGet(options OptionsValues, globalOptions OptionsValues) (err error) {
	ov := options["Commands"].(OptionsValues)["Options"].(OptionsValues)
	gov := globalOptions["Options"].(OptionsValues)
	address := gov["SaultServerAddress"].(string)

	var signer saultSsh.Signer
	if gov["Signer"] != nil {
		signer = gov["Signer"].(saultSsh.Signer)
	}

	req := hostGetRequestData{
		Hosts: ov["HostNames"].([]string),
	}
	if v, ok := ov["ActiveFilter"]; ok {
		req.Filter = v.(activeFilter)
	}

	var response *responseMsg
	var hosts []hostRegistryData
	response, err = runCommand(
		gov["SaultServerName"].(string),
		address,
		signer,
		"host.get",
		req,
		&hosts,
	)
	if err != nil {
		return
	}

	if response.Error != nil {
		err = response.Error
		return
	}

	_, saultServerPort, _ := SplitHostPort(address, uint64(22))
	saultServerHostName := gov["SaultServerHostName"].(string)

	CommandOut.Println(printHosts(hosts, saultServerHostName, saultServerPort))
	return
}

func responseHostGet(pc *proxyConnection, channel saultSsh.Channel, msg commandMsg) (exitStatus uint32, err error) {
	var data hostGetRequestData
	json.Unmarshal(msg.Data, &data)

	var list []hostRegistryData
	if len(data.Hosts) < 1 {
		for _, hostData := range pc.proxy.Registry.GetHosts(activeFilterAll) {
			list = append(list, hostData)
		}
	} else {
		for _, hostName := range data.Hosts {
			hostData, err := pc.proxy.Registry.GetHostByHostName(hostName)
			if err != nil {
				continue
			}
			list = append(list, hostData)
		}
	}

	var filtered []hostRegistryData
	switch data.Filter {
	case activeFilterActive:
		for _, hostData := range list {
			if hostData.Deactivated {
				continue
			}
			filtered = append(filtered, hostData)
		}
	case activeFilterDeactivated:
		for _, hostData := range list {
			if !hostData.Deactivated {
				continue
			}
			filtered = append(filtered, hostData)
		}
	default:
		filtered = list
	}

	var response []byte
	response, err = newResponseMsg(
		filtered,
		commandErrorNone,
		nil,
	).ToJSON()
	if err != nil {
		return
	}

	channel.Write(response)

	return
}

func printHost(saultServerHostName string, saultServerPort uint64, hostData hostRegistryData) string {
	result, err := ExecuteCommonTemplate(`
{{ "Host:"|green }}      {{ .host.Host | green }} {{ if .host.Deactivated }}{{ "(deactivated)" | red }}{{ end }}
Address:   {{ .host.DefaultAccount }}@{{ .host.Address }}:{{ .host.Port }}
Accounts:  [ {{ .accounts }} ]
Connect:   {{ .Connect | magenta }}
`,
		map[string]interface{}{
			"host":     hostData,
			"accounts": strings.Join(hostData.Accounts, " "),
			"Connect": fmt.Sprintf(
				`$ ssh -p %d %s+%s@%s`,
				saultServerPort,
				hostData.DefaultAccount,
				hostData.Host,
				saultServerHostName,
			),
		},
	)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(result)
}

func printHosts(hosts []hostRegistryData, saultServerHostName string, saultServerPort uint64) string {
	hostsPrinted := []string{}
	for _, hostData := range hosts {
		hostsPrinted = append(
			hostsPrinted,
			printHost(saultServerHostName, saultServerPort, hostData),
		)
	}

	result, err := ExecuteCommonTemplate(`
{{ $length := len .hosts }}
{{ if ne $length 0 }}{{ .line}}
{{ .hostsPrinted | escape }}
{{ .line}}
found {{ $length }} hosts
{{ else }}
no hosts
{{ end }}
`,
		map[string]interface{}{
			"hosts":        hosts,
			"hostsPrinted": strings.Join(hostsPrinted, "\n\n"),
		},
	)

	if err != nil {
		return ""
	}

	return strings.TrimSpace(result)
}
