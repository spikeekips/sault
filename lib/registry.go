package sault

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/spikeekips/sault/ssh"
)

type activeFilter int

const (
	_                            = iota
	activeFilterAll activeFilter = 1 << (10 * iota)
	activeFilterActive
	activeFilterDeactivated
)

// UserRegistryData is the user data of registry
type UserRegistryData struct {
	User        string // must be unique
	PublicKey   string
	IsAdmin     bool
	Deactivated bool

	parsedPublicKey saultSsh.PublicKey
}

// GetPublicKey parses the public key string
func (u *UserRegistryData) GetPublicKey() saultSsh.PublicKey {
	if u.parsedPublicKey == nil {
		parsed, err := ParsePublicKeyFromString(u.PublicKey)
		if err != nil {
			return nil
		}
		u.parsedPublicKey = parsed
	}
	return u.parsedPublicKey
}

// GetAuthorizedKey strips the public key string
func (u *UserRegistryData) GetAuthorizedKey() string {
	if u.GetPublicKey() == nil {
		return ""
	}

	return GetAuthorizedKey(u.parsedPublicKey)
}

func (u UserRegistryData) String() string {
	a := ""
	if u.IsAdmin {
		a = "*"
	}
	return fmt.Sprintf("{%s%s %s}", u.User, a, "...")
}

// Base64ClientPrivateKey is the toml field to handle ClientPrivateKey
type Base64ClientPrivateKey string

// UnmarshalText encode pem-encoded private key to base64
func (d *Base64ClientPrivateKey) UnmarshalText(data []byte) error {
	decodedClientPrivateKey, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	*d = Base64ClientPrivateKey(string(decodedClientPrivateKey))
	return nil
}

// MarshalText returns the private key string
func (d Base64ClientPrivateKey) MarshalText() ([]byte, error) {
	encodedClientPrivateKey := base64.StdEncoding.EncodeToString([]byte(d))
	return []byte(encodedClientPrivateKey), nil
}

func (d Base64ClientPrivateKey) getSigner() (saultSsh.Signer, error) {
	if string(d) == "" {
		return nil, nil
	}

	signer, err := GetPrivateKeySignerFromString(strings.TrimSpace(string(d)))
	if err != nil {
		log.Errorf("failed to load client private key: %v", err)
		return nil, err
	}

	return signer, nil
}

type hostRegistryData struct {
	Host             string // must be unique
	DefaultAccount   string
	Accounts         []string
	Address          string
	Port             uint64
	ClientPrivateKey Base64ClientPrivateKey
	Deactivated      bool
}

func (p hostRegistryData) String() string {
	return fmt.Sprintf("{%s %s %s %d %s}", p.Host, p.DefaultAccount, p.Address, p.Port, "...")
}

func (p hostRegistryData) GetPort() uint64 {
	port := p.Port
	if p.Port < 1 {
		port = 22
	}

	return port
}

func (p hostRegistryData) GetFullAddress() string {
	return fmt.Sprintf("%s:%d", p.Address, p.GetPort())
}

// Registry handles the users, hosts data
type Registry interface {
	GetType() string
	String() string
	Save(w io.Writer) error
	Sync() error

	AddUser(userName, publicKey string) (UserRegistryData, error)
	RemoveUser(userName string) error
	GetUserCount(f activeFilter) int
	GetUsers(f activeFilter) map[string]UserRegistryData
	GetUserByUserName(userName string) (UserRegistryData, error)
	GetUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error)
	GetActiveUserByUserName(userName string) (UserRegistryData, error)
	GetActiveUserByPublicKey(publicKey saultSsh.PublicKey) (UserRegistryData, error)
	SetAdmin(userName string, set bool) error
	IsUserActive(userName string) (bool, error)
	SetUserActive(userName string, active bool) error
	UpdateUserName(userName, newUserName string) (UserRegistryData, error)
	UpdateUserPublicKey(userName, publicKey string) (UserRegistryData, error)

	AddHost(
		hostName,
		defaultAccount,
		address string,
		port uint64,
		clientPrivateKey string,
		accounts []string,
	) (hostRegistryData, error)
	GetHostCount(f activeFilter) int
	GetHosts(f activeFilter) map[string]hostRegistryData
	GetHostByHostName(hostName string) (hostRegistryData, error)
	GetActiveHostByHostName(hostName string) (hostRegistryData, error)
	IsHostActive(hostName string) (bool, error)
	SetHostActive(hostName string, active bool) error
	RemoveHost(hostName string) error
	UpdateHostName(hostName, newHostName string) (hostRegistryData, error)
	UpdateHostDefaultAccount(hostName, defaultAccount string) (hostRegistryData, error)
	UpdateHostAccounts(hostName string, accounts []string) (hostRegistryData, error)
	UpdateHostAddress(hostName, address string) (hostRegistryData, error)
	UpdateHostPort(hostName string, port uint64) (hostRegistryData, error)
	UpdateHostClientPrivateKey(hostName, clientPrivateKey string) (hostRegistryData, error)

	Connect(hostName, userName string, targetAccounts []string) error
	Disconnect(hostName, userName string, targetAccounts []string) error
	ConnectAll(hostName, userName string) error
	DisconnectAll(hostName, userName string) error
	IsConnectedAll(hostName, userName string) bool
	IsConnected(hostName, userName, targetAccount string) bool
	GetConnectedHosts(userName string) map[string][]string
}

// NewRegistry makes the new Registry
func NewRegistry(sourceType string, config configSourceRegistry, initialize bool) (Registry, error) {
	switch t := sourceType; t {
	case "toml":
		return newTOMLRegistry(config.(configTOMLRegistry), initialize)
	default:
		return nil, fmt.Errorf("registry source type, `%s` not found", t)
	}
}
