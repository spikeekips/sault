package sault

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/Sirupsen/logrus"
)

func TestParseLogLevel(t *testing.T) {
	{
		level, _ := ParseLogLevel("quiet")
		if level != logrus.FatalLevel {
			t.Errorf("quite level must be logrus.FatalLevel")
		}
	}

	{
		level, _ := ParseLogLevel("debug")
		if level != logrus.DebugLevel {
			t.Errorf("debug level must be logrus.DebugLevel")
		}
	}
	{
		levelName := "debug000"
		_, err := ParseLogLevel(levelName)
		if err == nil {
			t.Errorf("invalid level, `%s` name must ocurr error", levelName)
		}
	}
}

func TestParseLogOutput(t *testing.T) {
	outputFile, _ := ioutil.TempFile("/tmp/", "sault-test")
	defer os.Remove(outputFile.Name())

	os.Remove(outputFile.Name())

	{
		writer, err := ParseLogOutput(outputFile.Name(), "quiet")
		if writer != ioutil.Discard {
			t.Errorf("quiet level will have `ioutil.Discard` output")
		}
		if err != nil {
			t.Error(err)
		}
		os.Remove(outputFile.Name())
	}
	{
		writer, err := ParseLogOutput("stdout", "info")
		if writer != os.Stdout {
			t.Errorf("'stdout' represents `os.Stdout`")
		}
		if err != nil {
			t.Error(err)
		}
	}
	{
		writer, err := ParseLogOutput("stderr", "info")
		if writer != os.Stderr {
			t.Errorf("'stderr' represents `os.Stderr`")
		}
		if err != nil {
			t.Error(err)
		}
	}

	// check permission of output file
	{
		writer, _ := ParseLogOutput(outputFile.Name(), "info")
		outFile := writer.(*os.File)
		if outFile.Name() != outputFile.Name() {
			t.Errorf("weird output file was generated, `%s`", outFile.Name())
		}
		stat, _ := outFile.Stat()
		if octalPerm := fmt.Sprintf("%04o", stat.Mode()); octalPerm != "0600" {
			t.Errorf("output file has wrong permission, `%v`", octalPerm)
		}
	}
}

func TestParseHostAccount(t *testing.T) {
	{
		a := ""
		_, _, err := ParseHostAccount(a)
		if err == nil {
			t.Errorf("empty string must have error")
		}
	}
	{
		userName := "dir"
		hostName := "sault"
		a := fmt.Sprintf("%s@%s", userName, hostName)
		pUserName, pHostName, err := ParseHostAccount(a)
		if err != nil {
			t.Error(err)
		}

		if userName != pUserName {
			t.Errorf("userName != pUserName, `%s` != `%s`", userName, pUserName)
		}
		if hostName != pHostName {
			t.Errorf("hostName != pHostName, `%s` != `%s`", hostName, pHostName)
		}
	}
	{
		hostName := "sault"
		pUserName, pHostName, err := ParseHostAccount(hostName)
		if err != nil {
			t.Error(err)
		}

		if pUserName != "" {
			t.Errorf("userName must be empty")
		}
		if hostName != pHostName {
			t.Errorf("hostName != pHostName, `%s` != `%s`", hostName, pHostName)
		}
	}
	{
		userName := "dir@dir"
		hostName := "sault"
		a := fmt.Sprintf("%s@%s", userName, hostName)
		pUserName, pHostName, err := ParseHostAccount(a)
		if err != nil {
			t.Error(err)
		}

		if userName != pUserName {
			t.Errorf("userName != pUserName, `%s` != `%s`", userName, pUserName)
		}
		if hostName != pHostName {
			t.Errorf("hostName != pHostName, `%s` != `%s`", hostName, pHostName)
		}
	}
	{
		userName := "dir"
		hostName := "sault:22"
		a := fmt.Sprintf("%s@%s", userName, hostName)
		pUserName, pHostName, err := ParseHostAccount(a)
		if err != nil {
			t.Error(err)
		}

		if userName != pUserName {
			t.Errorf("userName != pUserName, `%s` != `%s`", userName, pUserName)
		}
		if hostName != pHostName {
			t.Errorf("hostName != pHostName, `%s` != `%s`", hostName, pHostName)
		}
	}
}

func TestParseAccountName(t *testing.T) {
	{
		a := ""
		_, _, err := ParseAccountName(a)
		if err == nil {
			t.Errorf("empty string must have error")
		}
	}
	{
		a := "server0"
		userName, hostName, err := ParseAccountName(a)
		if err != nil {
			t.Error(err)
		}
		if userName != "" {
			t.Errorf("userName != \"\", `%s` != ``", userName)
		}
		if hostName != a {
			t.Errorf("hostName != a, `%s` != `%s`", hostName, a)
		}
	}
	{
		u := "spikeekips"
		h := "server0"
		userName, hostName, err := ParseAccountName(fmt.Sprintf("%s+%s", u, h))
		if err != nil {
			t.Error(err)
		}
		if userName != u {
			t.Errorf("userName != u, `%s` != `%s`", userName, u)
		}
		if hostName != h {
			t.Errorf("hostName != h, `%s` != `%s`", hostName, h)
		}
	}
	{
		u := "spikeekips"
		h := "server0+server1"
		userName, hostName, err := ParseAccountName(fmt.Sprintf("%s+%s", u, h))
		if err != nil {
			t.Error(err)
		}
		if userName != u {
			t.Errorf("userName != u, `%s` != `%s`", userName, u)
		}
		if hostName != h {
			t.Errorf("hostName != h, `%s` != `%s`", hostName, h)
		}
	}
}

func TestCheckUserName(t *testing.T) {
	{
		a := "this-is-new"
		if !CheckUserName(a) {
			t.Errorf("must be valid: %s", a)
		}
	}
	{
		a := "this-is@new"
		if CheckUserName(a) {
			t.Errorf("must be invalid: %s", a)
		}
	}
	{
		a := "this-is+new"
		if CheckUserName(a) {
			t.Errorf("must be invalid: %s", a)
		}
	}
	{
		a := "123this-is-new"
		if !CheckUserName(a) {
			t.Errorf("must be valid: %s", a)
		}
	}
	{
		a := "123this-$is-new"
		if CheckUserName(a) {
			t.Errorf("must be invalid: %s", a)
		}
	}
	{
		a := "123this-_is-new"
		if !CheckUserName(a) {
			t.Errorf("must be valid: %s", a)
		}
	}
	{
		a := "우리나라"
		if CheckUserName(a) {
			t.Errorf("must be invalid: %s", a)
		}
	}
	{
		a := "!findme"
		if CheckUserName(a) {
			t.Errorf("must be invalid: %s", a)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	{
		host := "localhost"

		var port uint64
		port = 90
		pHost, pPort, err := SplitHostPort(fmt.Sprintf("%s:%d", host, port), 80)
		if err != nil {
			t.Errorf("failed: %v", err)
		}

		if host != pHost {
			t.Errorf("host != pHost, `%s` != `%s`", host, pHost)
		}
		if port != pPort {
			t.Errorf("port != pPort, `%s` != `%s`", port, pPort)
		}
	}
	{
		host := "localhost"

		var port uint64
		port = 90
		pHost, pPort, err := SplitHostPort(host, port)
		if err != nil {
			t.Errorf("failed: %v", err)
		}

		if host != pHost {
			t.Errorf("host != pHost, `%s` != `%s`", host, pHost)
		}
		if port != pPort {
			t.Errorf("port != pPort, `%s` != `%s`", port, pPort)
		}
	}
	{
		host := "localhost:"

		var port uint64
		port = 90
		_, _, err := SplitHostPort(host, port)
		if err == nil {
			t.Error("must be failed")
		}
	}
}

func TestLoadPublicKeyFromPrivateKeyFile(t *testing.T) {
	publicKeyString := strings.TrimSpace(`
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxbgqxA6IQO8ieZEGQAyZuOCe+ds7LSbjjCnUBzFAyVLJZKlxv+t1JdY+iLi/x/Q3tBHccr7Ueiy+I38AouwOUn81UiViAU6IquNFlOMYMB/IoS5tVYEbHxoYpsZTUi/CuRNOLDfKG0avAXDSdQ9mp2ln1Ovv3pHQLeUuWni5ecslVC36vxpL49eLxr6uXaMnhDyyl9PbMnoudMeiyyyZVNIKK+QEonPLkxgYPk9l1baAtEAph/zDsOwHfwo0DYgt8cPwyO6nzI9BoifVYWavCQoRsGtotf4AktTfL2AArJQc9jLLlzYsPwXK8g2QTLCHm7FED+Wm3T42Tsmn31eYGw==
	`)
	publicKey, _ := ParsePublicKeyFromString(publicKeyString)
	authorizedKey := GetAuthorizedKey(publicKey)

	{
		key, _ := ioutil.TempFile("/tmp/", "sault-test")
		defer key.Close()

		ioutil.WriteFile(key.Name()+".pub", []byte(publicKeyString), 0600)

		pf, err := LoadPublicKeyFromPrivateKeyFile(key.Name())
		if err != nil {
			t.Error(err)
		}

		if GetAuthorizedKey(pf) != authorizedKey {
			t.Errorf("LoadPublicKeyFromPrivateKeyFile(f) == '%s', but '%s'", publicKeyString, GetAuthorizedKey(pf))
		}
	}
	{
		// if public file not present
		key, _ := ioutil.TempFile("/tmp/", "sault-test")
		defer key.Close()

		_, err := LoadPublicKeyFromPrivateKeyFile(key.Name())
		if err == nil {
			t.Error("error must be occured")
		}
	}
	{
		// private key file with extension
		key, _ := ioutil.TempFile("/tmp/", "sault-test")
		key.Close()
		ioutil.WriteFile(key.Name()+".key", []byte{}, 0600)
		ioutil.WriteFile(key.Name()+".pub", []byte(publicKeyString), 0600)

		pf, err := LoadPublicKeyFromPrivateKeyFile(key.Name())
		if err != nil {
			t.Error(err)
		}

		if GetAuthorizedKey(pf) != authorizedKey {
			t.Errorf("LoadPublicKeyFromPrivateKeyFile(f) == '%s', but '%s'", publicKeyString, GetAuthorizedKey(pf))
		}
	}
	{
		// with invalid public key
		key, _ := ioutil.TempFile("/tmp/", "sault-test")
		key.Close()
		ioutil.WriteFile(key.Name()+".key", []byte{}, 0600)
		ioutil.WriteFile(key.Name()+".pub", []byte(publicKeyString+"findme"), 0600)

		_, err := LoadPublicKeyFromPrivateKeyFile(key.Name())
		if err == nil {
			t.Error("error must be occured")
		}
	}
}
