package saultcommands

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/core"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var maxConnectionString = 3

var PrintUsersDataTemplate = `{{ define "block-user" }}{{ $maxConnectionString := .maxConnectionString }}{{ $saultServerAddress := splitHostPort .saultServerAddress 22 }}{{ $lenlinks := len .user.Links }}            User ID: {{ .user.User.ID | colorUserID }}
              Admin: {{ if .user.User.IsAdmin }}{{ print .user.User.IsAdmin | green }}{{ else }}{{ print .user.User.IsAdmin | dim }}{{ end }}
             Active: {{ if .user.User.IsActive }}{{ print .user.User.IsActive | green }}{{ else }}{{ print .user.User.IsActive | dim }}{{ end }}
         Public Key: {{ .user.User.PublicKey |stringify | bold }}
 Fingerprint(sha256): {{ publicKeyFingerprintSha256 .user.User.GetPublicKey | dim }}
 Fingerprint(md5)   : {{ publicKeyFingerprintMd5 .user.User.GetPublicKey | dim }}
     Registered Time: {{ .user.User.DateAdded | timeToLocal | sprintf "%v" | dim }}
   Last Updated Time: {{ .user.User.DateUpdated | timeToLocal | sprintf "%v" | dim }}
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
{{ define "block-host" }}{{ $maxConnectionString := .maxConnectionString }}{{ $saultServerAddress := splitHostPort .saultServerAddress 22 }}{{ $lenaccounts := len .host.Accounts }}{{ $hostID := .host.ID }}{{ $saultPort := index $saultServerAddress "Port" }}{{ $saultHostName := index $saultServerAddress "HostName" }}           host ID: {{ .host.ID | blue }}
            Active: {{ if .host.IsActive }}{{ print .host.IsActive | green }}{{ else }}{{ print .host.IsActive | dim }}{{ end }}
           Address: {{ .host.HostName }}{{ .host.Port }}
          Accounts: {{ join .host.Accounts " " }}
   Registered Time: {{ .host.DateAdded | timeToLocal | sprintf "%v" | dim }}
 Last Updated Time: {{ .host.DateUpdated | timeToLocal | sprintf "%v" | dim }}
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

func injectClientKeyToHost(sc *saultcommon.SSHClient, publicKey saultssh.PublicKey) (err error) {
	log.Debugf("trying to inject client public key to host")

	checkCmd := fmt.Sprintf("sh -c '[ -d %s ] && echo 1 || echo 0'", sault.SSHDirectory)
	output, err := sc.Run(checkCmd)
	if err != nil {
		log.Errorf("failed to check ssh directory, %s: %v", sault.SSHDirectory, err)
		return
	}

	if strings.TrimSpace(string(output)) == "0" {
		log.Debugf("ssh directory, '%s' does not exist, create new", sault.SSHDirectory)
		if err = sc.MakeDir(sault.SSHDirectory, 0700, true); err != nil {
			log.Debugf("failed to create ssh directory, '%s': %v", sault.SSHDirectory, err)
			return
		}
		err = sc.PutFile(saultcommon.GetAuthorizedKey(publicKey)+"\n", sault.AuthorizedKeyFile, 0600)
		if err != nil {
			log.Debugf("failed to create new authorized_keys file, '%s': %v", sault.AuthorizedKeyFile, err)
			return
		}
		log.Debugf("created new authorized_keys file, '%s'", sault.AuthorizedKeyFile)

		return nil
	}

	log.Debugf("check file exists, '%s'", sault.AuthorizedKeyFile)
	authorizedPublicKey := saultcommon.GetAuthorizedKey(publicKey)
	output, err = sc.GetFile(sault.AuthorizedKeyFile)
	if err != nil {
		log.Debugf("'%s' does not exist, create new", sault.AuthorizedKeyFile)
		err = sc.PutFile(authorizedPublicKey+"\n", sault.AuthorizedKeyFile, 0600)
		if err != nil {
			return
		}

		return
	}

	log.Debugf("found '%s', check the same record", sault.AuthorizedKeyFile)

	var foundSame bool
	r := bufio.NewReader(bytes.NewBuffer(output))
	for {
		c, err := r.ReadString(10)
		if err == io.EOF {
			break
		} else if err != nil {
			break
		}
		if len(strings.TrimSpace(c)) < 1 {
			continue
		}

		p, err := saultcommon.ParsePublicKey([]byte(c))
		if err != nil {
			continue
		}
		if saultcommon.GetAuthorizedKey(p) == authorizedPublicKey {
			foundSame = true
			break
		}
	}

	if foundSame {
		log.Debugf("found same record in '%s', client public key already added.", sault.AuthorizedKeyFile)
		err = nil
		return
	}

	content := fmt.Sprintf(`%s

# from sault ###################################################################
%s
################################################################################
`,
		strings.TrimSpace(string(output)),
		authorizedPublicKey,
	)

	err = sc.PutFile(content, sault.AuthorizedKeyFile, 0600)
	if err != nil {
		return
	}

	return nil
}

func passphraseChallenge(run func(passphrase string) error, firstMessage, nextMessage string, maxTries int) (err error) {
	var passphrase string
	var passphraseTried int

	for {
		err = run(passphrase)
		if err == nil {
			return nil
		}

		var responseMsgErr *saultcommon.ResponseMsgError
		var ok bool
		if responseMsgErr, ok = err.(*saultcommon.ResponseMsgError); !ok {
			return
		}

		if responseMsgErr.IsError(saultcommon.CommandErrorAuthFailed) {
			passphraseTried++
			if passphraseTried > maxTries {
				return
			}

			var helpMessage string
			if passphraseTried < 2 {
				helpMessage, _ = saultcommon.SimpleTemplating(firstMessage, nil)
			} else {
				helpMessage, _ = saultcommon.SimpleTemplating(nextMessage, nil)
			}
			fmt.Fprint(os.Stdout, strings.TrimSpace(helpMessage)+"\n")
			passphrase, err = saultcommon.ReadPassword(3)
			if err != nil {
				log.Error(err)
				err = nil
				return
			}

			continue
		}

		return err
	}

	return nil
}

func checkConnectivity(account, address string, signer saultssh.Signer, timeout time.Duration) (err error) {
	slog := log.WithFields(logrus.Fields{
		"Address": fmt.Sprintf("%s@%s", account, address),
	})

	slog.Debugf("trying to connect")

	sc := saultcommon.NewSSHClient(account, address)
	sc.AddAuthMethod(saultssh.PublicKeys(signer))
	sc.SetTimeout(timeout)
	defer sc.Close()

	if err = sc.Connect(); err != nil {
		slog.Errorf("%T: %v", err, err)

		var errType saultcommon.CommandErrorType
		if _, ok := err.(*net.OpError); ok {
			errType = saultcommon.CommandErrorDialError
		} else {
			errType = saultcommon.CommandErrorAuthFailed
		}

		// NOTE only check the connectivity, not authentication
		if errType == saultcommon.CommandErrorDialError {
			err = &saultcommon.ResponseMsgError{ErrorType: errType, Message: err.Error()}
			return
		}

		err = nil
	}

	slog.Debugf("successfully connected")

	return
}
