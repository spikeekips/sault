package saultcommands

import (
	"strings"

	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/registry"
)

var maxConnectionString = 3

var PrintUsersDataTemplate = `{{ define "block-user" }}{{ $maxConnectionString := .maxConnectionString }}{{ $saultServerAddress := splitHostPort .saultServerAddress 22 }}{{ $lenlinks := len .user.Links }}            User ID: {{ .user.User.ID | colorUserID }}
              Admin: {{ if .user.User.IsAdmin }}{{ print .user.User.IsAdmin | green }}{{ else }}{{ print .user.User.IsAdmin | dim }}{{ end }}
             Active: {{ if .user.User.IsActive }}{{ print .user.User.IsActive | green }}{{ else }}{{ print .user.User.IsActive | dim }}{{ end }}
         Public Key: {{ .user.User.PublicKey |stringify | bold }}
 Fingerprint(sha256): {{ publicKeyFingerprintSha256 .user.User.GetPublicKey | dim }}
 Fingerprint(md5)   : {{ publicKeyFingerprintMd5 .user.User.GetPublicKey | dim }}
     Registered Time: {{ sprintf "%v" .user.User.DateAdded | dim }}
   Last Updated Time: {{ sprintf "%v" .user.User.DateUpdated | dim }}
        Linked Hosts: {{ if eq $lenlinks 0 }}{{ "not yet linked" | yellow }}{{ else }}{{ range .user.Links }}
{{ .HostID | sprintf "%14s" | colorHostID }}: {{ if .All }}{{ "open to all acocunts" | yellow }}{{ else }}{{ join .Accounts " " }}{{ end }}
{{ $lenaccounts := len .Accounts }}{{ $hostID := .HostID }}{{ $saultPort := index $saultServerAddress "Port" }}{{ $saultHostName := index $saultServerAddress "HostName" }}{{ range $i, $_ := .Accounts }}{{ if lt $i $maxConnectionString }}{{ sprintf "%15s" "" }}{{ print "$ ssh -p " $saultPort " " . "+" $hostID "@" $saultHostName | magenta }}
{{ end }}{{ end }}{{ sprintf "%20s" "" }}{{ if gt $lenaccounts $maxConnectionString }}... {{ minus $lenaccounts $maxConnectionString }} more{{ end }}{{ end }}{{ end }}{{ end }}


{{ define "block-users" }}{{ $maxConnectionString := .maxConnectionString }}{{ $saultServerAddress := .saultServerAddress }}{{ $len := len .users }}{{ range $_, $user := .users }}
{{ template "block-user" dict "user" $user "saultServerAddress" $saultServerAddress "maxConnectionString" $maxConnectionString }}
{{ line "- " }}{{end}}
{{ if eq $len 1 }}1 user found{{ end }}{{ if gt $len 1 }}{{ $len }} users found{{ end }}{{ end }}


{{ define "user-list" }}
{{ $len := len .users }}
{{ line "=" }}{{ template "block-users" dict "users" .users "saultServerAddress" .saultServerAddress "maxConnectionString" .maxConnectionString }}
{{ line "=" }}
{{ end }}


{{ define "one-user" }}
{{ line "=" }}{{ template "block-user" dict "user" .user "saultServerAddress" .saultServerAddress "maxConnectionString" .maxConnectionString }}
{{ line "=" }}{{ end }}


{{ define "one-user-updated" }}
{{ line "=" }}{{ template "block-user" dict "user" .user "saultServerAddress" .saultServerAddress "maxConnectionString" .maxConnectionString }}
{{line "- " }}
{{ if not .error }}successfully updated{{ else }}{{ "error" | red }} {{ .error.Error }}{{ end }}
{{ line "=" }}{{ end }}
	`

func PrintUsersData(saultServerAddress string, usersdata []UserListResponseUserData) string {
	if len(usersdata) < 1 {
		return "no users found\n"
	}

	t, err := saultcommon.Templating(
		PrintUsersDataTemplate,
		"user-list",
		map[string]interface{}{
			"maxConnectionString": maxConnectionString,
			"saultServerAddress":  saultServerAddress,
			"users":               usersdata,
		},
	)

	if err != nil {
		log.Errorf("failed to render, 'PrintUsersData', '%s': %v", saultcommon.SprintInstance(usersdata), err)
	}

	return strings.TrimSpace(t) + "\n"
}

func PrintUserData(templateName, saultServerAddress string, userdata UserListResponseUserData, err error) string {
	t, err := saultcommon.Templating(
		PrintUsersDataTemplate,
		templateName,
		map[string]interface{}{
			"maxConnectionString": maxConnectionString,
			"saultServerAddress":  saultServerAddress,
			"user":                userdata,
			"error":               err,
		},
	)

	if err != nil {
		log.Errorf("failed to render, 'PrintUserData', '%s': %v", saultcommon.SprintInstance(userdata), err)
	}

	return strings.TrimSpace(t) + "\n"
}

var PrintHostDataTemplate = `
{{ define "block-host" }}{{ $maxConnectionString := .maxConnectionString }}{{ $saultServerAddress := splitHostPort .saultServerAddress 22 }}{{ $lenaccounts := len .host.Accounts }}{{ $hostID := .host.ID }}{{ $saultPort := index $saultServerAddress "Port" }}{{ $saultHostName := index $saultServerAddress "HostName" }} host ID: {{ .host.ID | blue }}
  Active: {{ if .host.IsActive }}{{ print .host.IsActive | green }}{{ else }}{{ print .host.IsActive | dim }}{{ end }}
 Address: {{ .host.HostName }}{{ .host.Port }}
Accounts: {{ join .host.Accounts " " }}
{{ range $i, $_ := .host.Accounts }}{{ if lt $i $maxConnectionString }}{{ sprintf "%9s" "" }} {{ print "$ ssh -p " $saultPort " " . "+" $hostID "@" $saultHostName | magenta }}
{{ end }}{{ end }} {{ if gt $lenaccounts $maxConnectionString }}{{ sprintf "%9s" "" }}... {{ minus $lenaccounts $maxConnectionString }} more{{ end }}{{ end }}


{{ define "one-host" }}
{{ line "=" }}{{ template "block-host" dict "host" .host "saultServerAddress" .saultServerAddress "maxConnectionString" .maxConnectionString }}
{{ line "=" }}{{ end }}


{{ define "host-added" }}
{{ line "=" }}{{ template "block-host" dict "host" .host "saultServerAddress" .saultServerAddress "maxConnectionString" .maxConnectionString }}
{{ line "- " }}
host was successfully added
{{ line "=" }}{{ end }}


{{ define "host-updated" }}
{{ line "=" }}{{ template "block-host" dict "host" .host "saultServerAddress" .saultServerAddress "maxConnectionString" .maxConnectionString }}
{{ line "- " }}
{{ if not .error }}successfully updated{{ else }}{{ "error" | red }} {{ .error.Error }}{{ end }}
{{ line "=" }}{{ end }}


{{ define "host-list" }}{{ $maxConnectionString := .maxConnectionString }}{{ $saultServerAddress := .saultServerAddress }}{{ $len := len .hosts }}{{ line "=" }}
{{ range $_, $host := .hosts }}{{ template "block-host" dict "host" $host "saultServerAddress" $saultServerAddress "maxConnectionString" $maxConnectionString }}
{{ line "- " }}
{{end}}{{ if eq $len 1 }}1 host found{{ end }}{{ if gt $len 1 }}{{ $len }} hosts found{{ end }}
{{ line "=" }}{{ end }}

`

func PrintHostData(templateName, saultServerAddress string, host saultregistry.HostRegistry, err error) string {
	t, err := saultcommon.Templating(
		PrintHostDataTemplate,
		templateName,
		map[string]interface{}{
			"maxConnectionString": maxConnectionString,
			"saultServerAddress":  saultServerAddress,
			"host":                host,
			"error":               err,
		},
	)

	if err != nil {
		log.Errorf("failed to render, 'PrintHostData', '%s': %v", saultcommon.SprintInstance(host), err)
	}

	return strings.TrimSpace(t) + "\n"
}

func PrintHostsData(templateName, saultServerAddress string, hosts []saultregistry.HostRegistry, err error) string {
	if len(hosts) < 1 {
		return "no hosts found\n"
	}

	t, err := saultcommon.Templating(
		PrintHostDataTemplate,
		templateName,
		map[string]interface{}{
			"maxConnectionString": maxConnectionString,
			"saultServerAddress":  saultServerAddress,
			"hosts":               hosts,
			"error":               err,
		},
	)

	if err != nil {
		log.Errorf("failed to render, 'PrintHostData', '%s': %v", saultcommon.SprintInstance(hosts), err)
	}

	return strings.TrimSpace(t) + "\n"
}

var printServerKindTemplate = `
{{ define "default" }}
{{ .key | yellow }}:
{{ .value }}
{{ end }}
`

func printServerKind(templateName, key string, value string) string {
	t, err := saultcommon.Templating(
		printServerKindTemplate,
		templateName,
		map[string]interface{}{
			"key":   key,
			"value": value,
		},
	)

	if err != nil {
		log.Errorf("failed to render, 'printServerKind', '%s': %v", key, value)
	}

	return strings.TrimSpace(t) + "\n"
}
