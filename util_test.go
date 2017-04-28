package sault

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	log "github.com/Sirupsen/logrus"
)

func TestParseLogLevel(t *testing.T) {
	{
		level, _ := ParseLogLevel("quiet")
		if level != log.FatalLevel {
			t.Errorf("quite level must be log.FatalLevel")
		}
	}

	{
		level, _ := ParseLogLevel("debug")
		if level != log.DebugLevel {
			t.Errorf("quite level must be log.FatalLevel")
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
