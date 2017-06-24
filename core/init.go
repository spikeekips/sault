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
	// BuildVersion is the build version
	BuildVersion = "v0.0"
	// BuildDate is the build date
	BuildDate = "0000-00-00T00:00:00+0000"
	// BuildCommit is the commit id of source
	BuildCommit = "XXXX"
	// BuildBranch is the branch name
	BuildBranch = "XXXX"
	// BuildRepo is the repository url
	BuildRepo = "XXXX"
	// BuildEnv is the build environment information
	BuildEnv = "XXXX"
)

var log *logrus.Logger

var defaultTimeoutProxyClient = 3 * time.Second

// DefaultSaultServerName is the name of sault server, it will be use to connect
// to the sault server directly.
var DefaultSaultServerName = "sault"

// ConfigFileExt is the file extension of config file
var ConfigFileExt = ".conf"

// DefaultHostKey is the default host key file path
var DefaultHostKey = "./sault-host.key"

// DefaultClientKey is the default internal client key file path
var DefaultClientKey = "./sault-client.key"

// DefaultSaultHostID is the default host name, which is running the sault server
var DefaultSaultHostID = "sault-host"

// DefaultServerPort is the default bind address of sault server
var DefaultServerPort = uint64(2222)
var defaultServerBind = fmt.Sprintf(":%d", DefaultServerPort)

// Command is the command interface for sault server
type Command interface {
	Request(allFlags []*saultflags.Flags, thisFlags *saultflags.Flags) error
	Response(user saultregistry.UserRegistry, channel saultssh.Channel, msg saultcommon.CommandMsg, registry *saultregistry.Registry, config *Config) error
}

// Commands is the collection of sault commands
var Commands = map[string]Command{}

func init() {
	saultssh.PackageVersion = fmt.Sprintf("%s-sault-%s", saultssh.PackageVersion, BuildVersion)

	log = logrus.New()

	SetupLog(logrus.ErrorLevel, os.Stdout, nil)
}

// SetupLog will set up the logging
func SetupLog(level logrus.Level, out io.Writer, formatter logrus.Formatter) {
	log.Level = level

	if formatter == nil {
		formatter = saultcommon.GetDefaultLogrusFormatter()
	}
	log.Formatter = formatter
	log.Out = out
}
