package saultcommon

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/ScaleFT/sshkeys"
	"github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	uuid "github.com/nu7hatch/gouuid"
	"github.com/spikeekips/sault/saultssh"
	"github.com/spikeekips/sault/saultssh/agent"
)

// TermSize contains the terminal dimension information
type TermSize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// MakeUUID generates the uuid version5 string
func MakeUUID() string {
	s, _ := uuid.NewV5(uuid.NamespaceURL, []byte(time.Now().Format("Jan _2 15:04:05.000000000")))
	return s.String()
}

// MakeRandomString makes random string, based on md5 and uuid
func MakeRandomString() string {
	m := md5.New()
	m.Write([]byte(MakeUUID()))
	return fmt.Sprintf("%x", m.Sum(nil))
}

// MakeFirstLowerCase replace the first char to lower case
func MakeFirstLowerCase(s string) string {
	if len(s) < 2 {
		return strings.ToLower(s)
	}

	bts := []byte(s)

	lc := bytes.ToLower([]byte{bts[0]})
	rest := bts[1:]

	return string(bytes.Join([][]byte{lc, rest}, nil))
}

// MakeFirstUpperCase replace the first char to upper case
func MakeFirstUpperCase(s string) string {
	if len(s) < 2 {
		return strings.ToUpper(s)
	}

	bts := []byte(s)

	lc := bytes.ToUpper([]byte{bts[0]})
	rest := bts[1:]

	return string(bytes.Join([][]byte{lc, rest}, nil))
}

// MakePascalCase make the underscore connected string, 'pascal_case' to
// 'PascalCase'
func MakePascalCase(s string) string {
	ss := strings.Split(s, "_")
	if len(ss) < 2 {
		return MakeFirstUpperCase(s)
	}

	var new []string
	for _, i := range ss {
		new = append(new, MakeFirstUpperCase(i))
	}

	return strings.Join(new, "")
}

// MakeOutputString makes output string for sault client
func MakeOutputString(log *logrus.Logger, s string, level logrus.Level) string {
	entry := logrus.NewEntry(log)
	entry.Level = level
	entry.Message = s

	b, _ := (&logrus.TextFormatter{DisableTimestamp: true}).Format(entry)
	return strings.TrimSpace(string(b))
}

var flagTempalteFMap = template.FuncMap{
	"center": func(s string) string {
		return fmt.Sprintf(
			"%s %s",
			strings.Repeat(" ", (int(termSize.Col)-len(s))/2),
			s,
		)
	},
	"right": func(s string) string {
		return fmt.Sprintf(
			"%s %s",
			strings.Repeat(" ", (int(termSize.Col)-len(s)-1)),
			s,
		)
	},
	"bold": terminalFormat(1, 0),
	//"italic":    terminalFormat(3),
	"underline": terminalFormat(4, 24),
	//"strike":    terminalFormat(9),
	"invert": terminalFormat(7, 27),
	"dim":    terminalFormat(2, 22),
	//"hide":   terminalFormat(8, 28),

	"red":     ColorFunc(color.FgRed),
	"green":   ColorFunc(color.FgGreen),
	"yellow":  ColorFunc(color.FgYellow),
	"blue":    ColorFunc(color.FgBlue),
	"magenta": ColorFunc(color.FgMagenta),
	"cyan":    ColorFunc(color.FgCyan),
	"note":    ColorFunc(color.FgRed, color.BgYellow),
	"colorUserID": func(s string) string {
		return ColorFunc(color.FgCyan)(terminalFormat(1, 0)(s))
	},
	"colorHostID": func(s string) string {
		return ColorFunc(color.FgBlue)(terminalFormat(1, 0)(s))
	},

	"name": func(s string) string {
		return MakeFirstLowerCase(s)
	},
	"join": func(a []string, needle string) string {
		return strings.Join(a, needle)
	},
	"slice": func(a []string) string {
		return fmt.Sprintf("[ %s ]", strings.Join(a, " "))
	},
	"sprintf": func(format string, s ...interface{}) string {
		return fmt.Sprintf(format, s...)
	},
	"minus": func(a, b int) int {
		return a - b
	},
	"plus": func(a, b int) int {
		return a + b
	},
	"line": func(m ...string) string {
		var prefix string
		var body string
		if len(m) < 2 {
			prefix = ""
			body = m[0]
		} else {
			prefix = m[0]
			body = m[1]
		}

		return fmt.Sprintf(
			"%s%s",
			prefix,
			strings.Repeat(
				body,
				int(termSize.Col-uint16(len(prefix)))/len(body),
			),
		)
	},
	"trimSpace": strings.TrimSpace,
	"dict": func(s ...interface{}) (m map[string]interface{}) {
		if len(s)%2 != 0 {
			log.Errorf("%v is not valid", s...)
			return
		}

		m = map[string]interface{}{}
		for i := 0; i < len(s)/2; i++ {
			m[s[i*2].(string)] = s[(i*2)+1]
		}

		return
	},
	"splitHostPort": func(s string, defaultPort int) (m map[string]interface{}) {
		hostName, port, err := SplitHostPort(s, uint64(defaultPort))
		if err != nil {
			hostName = ""
			port = 0
		}

		return map[string]interface{}{
			"HostName": hostName,
			"Port":     port,
		}
	},
	"publicKeyFingerprintMd5": func(s saultssh.PublicKey) string {
		return FingerprintMD5PublicKey(s)
	},
	"publicKeyFingerprintSha256": func(s saultssh.PublicKey) string {
		return FingerprintSHA256PublicKey(s)
	},
	"stringify": func(s interface{}) string {
		switch s.(type) {
		case string:
			return s.(string)
		case []byte:
			return string(s.([]byte))
		default:
			return fmt.Sprintf("%s", s)
		}
	},
	"timeToLocal": func(s time.Time) time.Time {
		return s.In(time.Local)
	},
}

func terminalFormat(code, reset int) func(string) string {
	var terminalEscape = "\x1b"

	return func(s string) string {
		return fmt.Sprintf("%s%s%s",
			fmt.Sprintf("%s[%dm", terminalEscape, code),
			s,
			fmt.Sprintf("%s[%dm", terminalEscape, reset),
		)
	}
}

// ColorFunc is the wrapper for colorizing string
func ColorFunc(attr ...color.Attribute) func(string) string {
	return func(s string) string {
		return color.New(attr...).SprintFunc()(s)
	}
}

// SimpleTemplating help to apply string to template
func SimpleTemplating(t string, values interface{}) (string, error) {
	tmpl, err := template.New(MakeRandomString()).Funcs(flagTempalteFMap).Parse(t)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	tmpl.Execute(&b, values)

	return b.String(), nil
}

// Templating help to apply string to template
func Templating(t, name string, values interface{}) (string, error) {
	tmpl, err := template.New(MakeRandomString()).Funcs(flagTempalteFMap).Parse(t)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	tmpl.ExecuteTemplate(&b, name, values)

	return b.String(), nil
}

// StringFilter was from https://gobyexample.com/collection-functions
func StringFilter(vs []string, f func(string) bool) []string {
	vsf := make([]string, 0)
	for _, v := range vs {
		if f(v) {
			vsf = append(vsf, v)
		}
	}
	return vsf
}

// GetSignerFromPrivateKey loads private key signer from string
func GetSignerFromPrivateKey(s []byte) (saultssh.Signer, error) {
	signer, err := saultssh.ParsePrivateKey(s)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// BaseJoin joins the path
func BaseJoin(base string, paths ...string) string {
	merged := base
	for _, p := range paths {
		if string([]rune(p)[0]) == "/" {
			merged = p
			continue
		}
		merged = filepath.Join(merged, p)
	}

	return merged
}

// SplitHostPort is similar to net.SplitHostPort, but it can parse without
// ":port"
func SplitHostPort(s string, defaultPort uint64) (host string, port uint64, err error) {
	if regexp.MustCompile(`\:$`).MatchString(s) {
		s = fmt.Sprintf("%s%d", s, defaultPort)
	} else if !regexp.MustCompile(`\:[0-9]+$`).MatchString(s) {
		s = fmt.Sprintf("%s:%d", s, defaultPort)
	}

	var portString string
	host, portString, err = net.SplitHostPort(s)
	if err != nil {
		return
	}
	if portString == "0" {
		port = defaultPort
		return
	}

	port, err = strconv.ParseUint(portString, 10, 32)
	if err != nil {
		return
	}

	return
}

// CreateRSAPrivateKey makes RSA private key
func CreateRSAPrivateKey(bits int) (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	return
}

// EncodePrivateKey encode private key as pem format
func EncodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	out := bytes.NewBuffer([]byte{})
	if err := pem.Encode(out, privateKeyPEM); err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}

// EncodePublicKey generates public key string
func EncodePublicKey(publicKey interface{}) (b []byte, err error) {
	var converted saultssh.PublicKey
	if _, ok := publicKey.(saultssh.PublicKey); ok {
		converted = publicKey.(saultssh.PublicKey)
	} else {
		converted, err = saultssh.NewPublicKey(publicKey)
		if err != nil {
			return
		}
	}

	return saultssh.MarshalAuthorizedKey(converted), nil
}

// GetAuthorizedKey strips the public key string
func GetAuthorizedKey(publicKey saultssh.PublicKey) string {
	return strings.TrimSpace(string(saultssh.MarshalAuthorizedKey(publicKey)))
}

// ParsePublicKey parses string and makes PublicKey
func ParsePublicKey(b []byte) (saultssh.PublicKey, error) {
	body := string(b)
	f := strings.Fields(body)
	if len(f) < 1 {
		return nil, fmt.Errorf("empty key string")
	} else if len(f) < 2 {
		body = f[0]
	} else {
		body = f[1]
	}

	key, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("invalid ssh publicKey: %v", err)
	}

	return saultssh.ParsePublicKey([]byte(key))
}

var reUserID = `^(?i)[\p{L}\d]+[\w\-]*[\p{L}\d]+$`
var reUserIDOneChar = `^(?i)[\p{L}\d]$`
var reAccountName = `^(?i)[0-9a-z]+[\w\-]*[0-9a-z]+$`
var reAccountNameOneChar = `^(?i)[0-9a-z]$`

// MaxLengthUserID is the maximum length of user id
var MaxLengthUserID = 32

// CheckUserID checkes whether UserRegistry.ID is valid or not
func CheckUserID(s string) bool {
	if utf8.RuneCountInString(s) == 1 {
		return regexp.MustCompile(reUserIDOneChar).MatchString(s)
	}

	if utf8.RuneCountInString(s) > MaxLengthUserID { // see `man useradd`
		return false
	}

	return regexp.MustCompile(reUserID).MatchString(s)
}

// CheckAccountName checkes whether user name is valid or not
func CheckAccountName(s string) bool {
	if len(s) == 1 {
		return regexp.MustCompile(reAccountNameOneChar).MatchString(s)
	}

	if len(s) > MaxLengthUserID { // see `man useradd`
		return false
	}

	return regexp.MustCompile(reAccountName).MatchString(s)
}

var reHostID = `^(?i)[\p{L}\d]+[\w\-]*[\p{L}\d]+$`
var reHostIDOneChar = `^(?i)[\p{L}\d]$`

// MaxLengthHostID is the maximum length of host id
var MaxLengthHostID = 64

// CheckHostID checkes whether HostRegistry.ID is valid or not
func CheckHostID(s string) bool {
	if utf8.RuneCountInString(s) == 1 {
		return regexp.MustCompile(reHostIDOneChar).MatchString(s)
	}

	if utf8.RuneCountInString(s) > MaxLengthHostID { // see `$ getconf HOST_NAME_MAX`, in osx it will be 255
		return false
	}

	return regexp.MustCompile(reHostID).MatchString(s)
}

// ParseSaultAccountName splits the `+` connected account and host name
func ParseSaultAccountName(s string) (account, hostID string, err error) {
	account, hostID, err = parseSaultAccountName(s)
	if err != nil {
		return
	}

	if len(account) > 0 && !CheckAccountName(account) {
		err = &InvalidAccountNameError{Name: account}
		return
	}
	if len(hostID) > 0 && !CheckHostID(hostID) {
		err = &InvalidHostIDError{ID: hostID}
		return
	}
	return
}

func parseSaultAccountName(s string) (account, hostID string, err error) {
	n := StringFilter(
		strings.SplitN(s, "+", 2),
		func(n string) bool {
			return len(strings.TrimSpace(n)) > 0
		},
	)
	if len(n) < 1 {
		err = errors.New("failed to parse sault account, empty")
		return
	}
	if len(n) < 2 {
		if strings.Contains(s, "+") {
			account = n[0]
		} else {
			hostID = n[0]
		}
		return
	}

	account = n[0]
	hostID = n[1]

	return
}

// FingerprintSHA256PublicKey makes the sha256 fingerprint string of ssh public
// key; from https://github.com/golang/go/issues/12292#issuecomment-255588529
func FingerprintSHA256PublicKey(key saultssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])

	return strings.TrimRight(b64hash, "=")
}

// FingerprintMD5PublicKey makes md5 finterprint string of ssh public key; from https://github.com/golang/go/issues/12292#issuecomment-255588529 //
func FingerprintMD5PublicKey(key saultssh.PublicKey) string {
	hash := md5.Sum(key.Marshal())
	out := ""
	for i := 0; i < 16; i++ {
		if i > 0 {
			out += ":"
		}
		out += fmt.Sprintf("%02x", hash[i])
	}
	return out
}

var warnSSHAgentNotRunning bool

// CheckSSHAgent checkes ssh agent is running
func CheckSSHAgent() {
	if warnSSHAgentNotRunning {
		return
	}

	_, err := GetSSHAgent()
	if err != nil {
		if agentErr, ok := err.(*SSHAgentNotRunning); ok {
			agentErr.PrintWarning()
		}
	}
	warnSSHAgentNotRunning = true
}

// SSHAgentNotRunning means ssh agent is not running
type SSHAgentNotRunning struct {
	E error
}

func (e *SSHAgentNotRunning) Error() string {
	if e.E == nil {
		return `'ssh-agent' is not running`
	}

	return fmt.Sprintf("'ssh-agent' has some problem: %v", e.Error)
}

// PrintWarning prints warning message
func (e *SSHAgentNotRunning) PrintWarning() {
	if e.E != nil {
		return
	}

	errString, _ := SimpleTemplating(`
{{ .err.Error() | escape }}
{{ "Without 'ssh-agent', you must enter the passphrase in every time you run sault. For details, see 'Using SSH Agent to Automate Login'(https://code.snipcademy.com/tutorials/linux-command-line/ssh-secure-shell-access/ssh-agent-add)." | yellow }}

`,
		map[string]interface{}{
			"err": e,
		},
	)

	fmt.Fprintf(os.Stdout, errString)
}

var envSSHAuthSock = "SSH_AUTH_SOCK"

// GetSSHAgent returns ssh agent
func GetSSHAgent() (saultsshAgent.Agent, error) {
	sock := os.Getenv(envSSHAuthSock)
	if sock == "" {
		return nil, &SSHAgentNotRunning{}
	}

	sa, err := net.Dial("unix", sock)
	if err != nil {
		return nil, &SSHAgentNotRunning{E: err}
	}

	return saultsshAgent.NewClient(sa), nil
}

// LoadPublicKeyFromPrivateKeyFile loads public key from private key with
// passpharase
func LoadPublicKeyFromPrivateKeyFile(f string) (publicKey saultssh.PublicKey, err error) {
	e := filepath.Ext(f)

	var base = f
	if e != "" {
		base = f[:len(e)]
	}

	pubFile := fmt.Sprintf("%s.pub", base)

	var b []byte
	b, err = ioutil.ReadFile(pubFile)
	if err != nil {
		return
	}
	publicKey, err = ParsePublicKey(b)

	return
}

// FindSignerInSSHAgentFromPublicKey will find signer from ssh agent with public
// key
func FindSignerInSSHAgentFromPublicKey(publicKey saultssh.PublicKey) (
	signer saultssh.Signer, err error,
) {
	authorizedKey := GetAuthorizedKey(publicKey)

	var agent saultsshAgent.Agent
	agent, err = GetSSHAgent()
	if err != nil {
		return
	}

	var signers []saultssh.Signer
	signers, err = agent.Signers()
	if err != nil {
		return
	}

	for _, s := range signers {
		if GetAuthorizedKey(s.PublicKey()) == authorizedKey {
			signer = s
			return
		}
	}

	err = errors.New("failed to find publicKey in ssh-agent")
	return
}

// FindSignerInSSHAgentFromFile will find signer from ssh agent with public key
// file
func FindSignerInSSHAgentFromFile(file string) (signer saultssh.Signer, err error) {
	file, _ = filepath.Abs(file)

	var agent saultsshAgent.Agent
	agent, err = GetSSHAgent()
	if err != nil {
		return
	}

	var keys []*saultsshAgent.Key
	keys, err = agent.List()
	if err != nil {
		return
	}

	var fi os.FileInfo
	fi, err = os.Stat(file)
	if err != nil {
		return
	}

	var foundAuthorizedKey string
	for _, key := range keys {
		var loadedFi os.FileInfo
		loadedFi, err = os.Stat(key.Comment)
		if err != nil {
			return
		}

		if os.SameFile(fi, loadedFi) {
			pubKey, _ := ParsePublicKey([]byte(key.String()))
			foundAuthorizedKey = GetAuthorizedKey(pubKey)
			break
		}
	}

	var signers []saultssh.Signer
	signers, err = agent.Signers()
	if err != nil {
		return
	}
	for _, signer = range signers {
		if GetAuthorizedKey(signer.PublicKey()) == foundAuthorizedKey {
			return
		}
	}

	signer = nil
	err = errors.New("failed to find publicKey in ssh-agent")

	return
}

var maxAuthTries = 3

// LoadPrivateKeySignerWithPasspharaseTrial load private key with passphrase
func LoadPrivateKeySignerWithPasspharaseTrial(privateKeyFile string) (signer saultssh.Signer, err error) {
	b, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return
	}

	// if private key does not have passphrase,
	{
		signer, err = GetSignerFromPrivateKey(b)
		if err == nil {
			return
		}

		err = nil
	}

	// read passphrase, try to decrypt private key
	fmt.Fprintf(os.Stdout, "Enter passphrase for key '%s'\n", privateKeyFile)
	var maxTries = 3
	var tries int
	for {
		if tries > (maxTries - 1) {
			break
		}

		var passphrase string
		passphrase, err = ReadPassword(maxAuthTries)
		if err != nil {
			log.Error(err)
			return
		}
		fmt.Fprint(os.Stdout, "")

		if len(passphrase) < 1 {
			err = errors.New("cancel passphrase authentication")
			log.Error(err)
			return
		}

		var key interface{}
		key, err = sshkeys.ParseEncryptedRawPrivateKey(b, []byte(passphrase))
		if err == nil {
			signer, err = saultssh.NewSignerFromKey(key)
			if err == nil {
				break
			} else {
				log.Error(err)
			}
		}
		tries++
		fmt.Fprintf(
			os.Stderr,
			"%s failed to parse private key, will try again: %v",
			ColorFunc(color.FgRed)("error"),
			err,
		)
	}

	if signer == nil {
		return
	}

	err = nil
	log.Debugf("successfully load client private key, '%s'", privateKeyFile)

	return
}

// ReadPassword read password from terminal
func ReadPassword(maxTries int) (password string, err error) {
	if maxTries < 1 {
		maxTries = 1
	}

	var tries int
	for {
		if tries > (maxTries - 1) {
			err = fmt.Errorf("stopped")
			return
		}

		fmt.Fprint(os.Stdout, "Password: ")

		var b []byte
		b, err = terminal.ReadPassword(terminalStateFD)
		fmt.Fprintln(os.Stdout, "")
		if err != nil {
			return
		}

		p := strings.TrimSpace(string(b))
		if len(p) < 1 {
			tries++
			continue
		}

		password = p
		break
	}

	return
}

// ParseHostAccount splits the `@` connected account and host name
func ParseHostAccount(s string) (userName, hostName string, err error) {
	s = strings.TrimSpace(s)
	if len(s) < 1 {
		err = errors.New("empty string")
		return
	}

	n := StringFilter(
		strings.Split(s, "@"),
		func(n string) bool {
			return len(strings.TrimSpace(n)) > 0
		},
	)
	if len(n) < 1 {
		err = errors.New("empty string")
		return
	}
	if len(n) == 1 {
		hostName = n[0]
		return
	}

	userName = strings.Join(n[:len(n)-1], "@")
	hostName = n[len(n)-1]

	return
}

// SprintInstance will make instance to string
func SprintInstance(data interface{}) string {
	jsoned, _ := json.MarshalIndent(data, "", "  ")
	return fmt.Sprintf("%s", jsoned)
}

// PrintInstance prints instance
func PrintInstance(data interface{}) {
	fmt.Println(SprintInstance(data))
}

// SprintfInstance will format instance
func SprintfInstance(format string, data ...interface{}) string {
	var datum []interface{}
	for _, d := range data {
		jsoned, _ := json.MarshalIndent(d, "", "  ")
		datum = append(datum, jsoned)
	}
	return fmt.Sprintf(format, datum...)
}

// PrintfInstance will format and print instance
func PrintfInstance(format string, data ...interface{}) {
	fmt.Println(SprintfInstance(format, data...))
}

// ParseBooleanString parse the boolean string to bool
func ParseBooleanString(s string) (v bool, err error) {
	if s == "true" {
		return true, nil
	}
	if s == "false" {
		return false, nil
	}

	err = fmt.Errorf("invalid boolean string, '%s'", s)
	return
}

// ParseMinusName parse the minus string to bool
func ParseMinusName(s string) (name string, minus bool) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "-") {
		return s, false
	}

	r := []rune(s)
	return string(r[:len(r)-1]), true
}

// DefaultLogrusFormatter is the default logrus formatter
type DefaultLogrusFormatter struct {
	logrus.Formatter
}

// Format is the method for logrus formatter
func (d DefaultLogrusFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC() // set to UTC by force
	return d.Formatter.Format(e)
}

// GetDefaultLogrusFormatter return the default logrus formatter
func GetDefaultLogrusFormatter() logrus.Formatter {
	return &logrus.TextFormatter{
		DisableTimestamp: true,
	}
}

// GetServerLogrusFormatter return the server logrus formatter
func GetServerLogrusFormatter() logrus.Formatter {
	return &DefaultLogrusFormatter{
		&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.999999999Z07:00",
		},
	}
}
