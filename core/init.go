package sault

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spikeekips/sault/common"
	"github.com/spikeekips/sault/flags"
	"github.com/spikeekips/sault/registry"
	"github.com/spikeekips/sault/saultssh"
)

var (
	BuildVersion = "v0.0"
	BuildDate    = "0000-00-00T00:00:00+0000"
	BuildCommit  = "XXXX"
	BuildBranch  = "XXXX"
	BuildRepo    = "XXXX"
	BuildEnv     = "XXXX"
)

var log *logrus.Logger

var SSHDirectory = "~/.ssh"
var AuthorizedKeyFile = "~/.ssh/authorized_keys"
var DefaultTimeoutProxyClient = 3 * time.Second
var DefaultSaultServerName = "sault"
var ConfigFileExt = ".conf"
var DefaultHostKey = "./sault-host.key"
var DefaultSaultHostID = "sault-host"
var DefaultClientKey = "./sault-client.key"
var DefaultServerPort = uint64(2222)
var DefaultServerBind = fmt.Sprintf(":%d", DefaultServerPort)
var MaxPassphraseChallenge = 3

type Command interface {
	Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) error
	Response(channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *Config) error
}

var Commands = map[string]Command{}

func init() {
	saultssh.PackageVersion = fmt.Sprintf("%s-sault-%s", saultssh.PackageVersion, BuildVersion)

	log = logrus.New()

	SetupLog(logrus.ErrorLevel, os.Stdout, nil)
}

func SetupLog(level logrus.Level, out io.Writer, formatter logrus.Formatter) {
	log.Level = level

	if formatter == nil {
		formatter = &logrus.TextFormatter{
			DisableTimestamp: true,
		}
	}
	log.Formatter = formatter
	log.Out = out
}
