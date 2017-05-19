package sault

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/nu7hatch/gouuid"
	"github.com/spikeekips/sault/ssh"
	"github.com/spikeekips/sault/ssh/agent"
)

var currentTermSize TermSize
var terminalStateFD = 0

func init() {
	termSize, err := GetTermSize()
	if err == nil {
		currentTermSize = *termSize
	}

	// terminal.ReadPassword was hanged after interruped with 'control-c'
	oldState, _ := terminal.GetState(terminalStateFD)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			syscall.Syscall6(
				syscall.SYS_IOCTL,
				uintptr(terminalStateFD),
				syscall.TIOCSETA,
				uintptr(unsafe.Pointer(oldState)),
				0,
				0,
				0,
			)
			os.Exit(1)
		}
	}()
}

// GetPrivateKeySigner loads private key signer from file
func GetPrivateKeySigner(keyFilePath string) (saultSsh.Signer, error) {
	b, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	return GetPrivateKeySignerFromString(string(b))
}

// GetPrivateKeySignerFromString loads private key signer from string
func GetPrivateKeySignerFromString(s string) (saultSsh.Signer, error) {
	signer, err := saultSsh.ParsePrivateKey([]byte(s))
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// FingerprintMD5PublicKey makes md5 finterprint string of ssh public key; from https://github.com/golang/go/issues/12292#issuecomment-255588529 //
func FingerprintMD5PublicKey(key saultSsh.PublicKey) string {
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

// FingerprintSHA256PublicKey makes the sha256 fingerprint string of ssh public
// key; from https://github.com/golang/go/issues/12292#issuecomment-255588529 //
func FingerprintSHA256PublicKey(key saultSsh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return strings.TrimRight(b64hash, "=")
}

// ParseLogLevel parses log level string
func ParseLogLevel(v string) (logrus.Level, error) {
	if v == "quiet" {
		return logrus.FatalLevel, nil
	}

	level, err := logrus.ParseLevel(v)
	if err != nil {
		return logrus.FatalLevel, err
	}

	return level, err
}

// ParseLogOutput parses log output string
func ParseLogOutput(output string, level string) (io.Writer, error) {
	if output == "" {
		return os.Stdout, nil
	}

	if level == "quiet" {
		return ioutil.Discard, nil
	}

	switch output {
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		f, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
}

// ParsePublicKeyFromString parses string and makes PublicKey
func ParsePublicKeyFromString(s string) (saultSsh.PublicKey, error) {
	body := s
	f := strings.Fields(s)
	if len(f) < 2 {
		body = f[0]
	} else {
		body = f[1]
	}

	key, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("invalid ssh publicKey: %v", err)
	}

	return saultSsh.ParsePublicKey([]byte(key))
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

// ParseAccountName splits the `+` connected account and host name
func ParseAccountName(s string) (userName, hostName string, err error) {
	userName = ""
	hostName = ""
	err = nil
	n := StringFilter(
		strings.SplitN(s, "+", 2),
		func(n string) bool {
			return len(strings.TrimSpace(n)) > 0
		},
	)
	if len(n) < 1 {
		err = errors.New("empty userName")
		return
	}
	if len(n) < 2 {
		hostName = s
		return
	}

	userName = n[0]
	hostName = n[1]
	return
}

// GetAuthorizedKey strips the public key string
func GetAuthorizedKey(publicKey saultSsh.PublicKey) string {
	return strings.TrimSpace(string(saultSsh.MarshalAuthorizedKey(publicKey)))
}

// GetUUID generates the uuid version5 string
func GetUUID() string {
	s, _ := uuid.NewV5(uuid.NamespaceURL, []byte(time.Now().Format("Jan _2 15:04:05.000000000")))
	return s.String()
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
func EncodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	pub, err := saultSsh.NewPublicKey(publicKey)
	if err != nil {
		return []byte{}, err
	}

	return saultSsh.MarshalAuthorizedKey(pub), nil
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

// StringMap was from https://gobyexample.com/collection-functions
func StringMap(vs []string, f func(string) string) []string {
	vsm := make([]string, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}

// ParseTolerateFilePath parse the tolerate marked string, the tolerated
// string(`@`prefixed path) means that if directory or file does not exit, skip
// it instead of occuring error.
func ParseTolerateFilePath(path string) (isTolerated bool, realPath string) {
	realPath = path
	if string([]rune(path)[0]) != "@" {
		return
	}

	isTolerated = true
	realPath = string([]rune(path)[1:])
	return
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

// TermSize contains the terminal dimension information
type TermSize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// GetTermSize returns the TermSize
func GetTermSize() (*TermSize, error) {
	ts := &TermSize{}
	retCode, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ts)))

	if int(retCode) == -1 {
		return nil, fmt.Errorf("unable to get term size: %v", errno)
	}

	return ts, nil
}

// CheckUserName checkes whether user name is valid or not
func CheckUserName(s string) bool {
	if len(s) > 32 { // see `man useradd`
		return false
	}

	return regexp.MustCompile(`^(?i)[0-9a-z]+[\w\-]*[0-9a-z]+$`).MatchString(s)
}

var reHostName = `^(?i)[0-9a-z]+[\w\-]*[0-9a-z]+$`
var maxLengthHostName = 64

// CheckHostName checkes whether host name is valid or not
func CheckHostName(s string) bool {
	if len(s) > maxLengthHostName { // see `$ getconf HOST_NAME_MAX`, in osx it will be 255
		return false
	}

	return regexp.MustCompile(reHostName).MatchString(s)
}

func colorFunc(attr color.Attribute) func(string) template.HTML {
	return func(s string) template.HTML {
		return template.HTML(color.New(attr).SprintFunc()(s))
	}
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

var commonTempalteFMap = template.FuncMap{
	"center": func(s string) string {
		return fmt.Sprintf(
			"%s %s",
			strings.Repeat(" ", (int(currentTermSize.Col)-len(s))/2),
			s,
		)
	},
	"right": func(s string) string {
		return fmt.Sprintf(
			"%s %s",
			strings.Repeat(" ", (int(currentTermSize.Col)-len(s))),
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

	"red":     colorFunc(color.FgRed),
	"green":   colorFunc(color.FgGreen),
	"yellow":  colorFunc(color.FgYellow),
	"blue":    colorFunc(color.FgBlue),
	"magenta": colorFunc(color.FgMagenta),
	"cyan":    colorFunc(color.FgCyan),

	"escape": func(s string) template.HTML {
		return template.HTML(s)
	},
	"join": func(a []string) string {
		return fmt.Sprintf("[ %s ]", strings.Join(a, " "))
	},
	"align_format": func(format, s string) string {
		return fmt.Sprintf(format, s)
	},
	"line": func(m string) string {
		return strings.Repeat(m, int(currentTermSize.Col)/len(m))
	},
}

// ExecuteCommonTemplate templates with commonTempalteFMap
func ExecuteCommonTemplate(t string, values map[string]interface{}) (string, error) {
	tmpl, err := template.New("t").Funcs(commonTempalteFMap).Parse(t)
	if err != nil {
		return "", err
	}

	if values == nil {
		values = map[string]interface{}{}
	}
	//values["line"] = strings.Repeat("-", int(currentTermSize.Col))
	//values["line"] = strings.Repeat(" * ", int(currentTermSize.Col)/3)

	bw := bytes.NewBuffer([]byte{})
	tmpl.Execute(bw, values)

	return bw.String(), nil
}

func isSameByteSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, c := range a {
		if c != b[i] {
			return false
		}
	}

	return true
}

// SplitHostPort is similar to net.SplitHostPort, but it can parse without
// ":port"
func SplitHostPort(s string, defaultPort uint64) (host string, port uint64, err error) {
	port = defaultPort
	if !regexp.MustCompile(`\:[1-9][0-9]+$`).MatchString(s) {
		s = fmt.Sprintf("%s:%d", s, defaultPort)
	}

	var portString string
	host, portString, err = net.SplitHostPort(s)
	if err != nil {
		return
	}

	port, err = strconv.ParseUint(portString, 10, 32)
	if err != nil {
		return
	}

	return
}

func ReadPassword(maxTries int) (password string, err error) {
	if maxTries < 1 {
		maxTries = 1
	}

	var tries int
	for {
		if tries > (maxTries - 1) {
			break
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

func loadPublicKeyFromPrivateKeyFile(f string) (saultSsh.PublicKey, error) {
	e := filepath.Ext(f)

	var base = f
	if e != "" {
		base = f[:len(e)]
	}

	pubFile := fmt.Sprintf("%s.pub", base)
	b, err := ioutil.ReadFile(pubFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}

		return nil, err
	}
	publicKey, err := ParsePublicKeyFromString(string(b))
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func findSignerInSSHAgent(publicKey saultSsh.PublicKey) (
	signer saultSsh.Signer, err error,
) {
	authorizedKey := GetAuthorizedKey(publicKey)

	var agent sshAgent.Agent
	agent, err = getSshAgent()
	if err != nil {
		return
	}

	var signers []saultSsh.Signer
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

func getSshAgent() (sshAgent.Agent, error) {
	sock := os.Getenv(envSSHAuthSock)
	if sock == "" {
		return nil, &SSHAgentNotRunning{}
	}

	sa, err := net.Dial("unix", sock)
	if err != nil {
		return nil, &SSHAgentNotRunning{E: err}
	}

	return sshAgent.NewClient(sa), nil
}

func parseNameActive(s string) (string, bool) {
	name := s
	var active bool
	if regexp.MustCompile(`\-$`).FindString(name) == "" {
		active = true
	} else {
		name = name[0 : len(name)-1]
		active = false
	}

	return name, active
}

func sshPublicKeyToSault(p ssh.PublicKey) saultSsh.PublicKey {
	return nil
}

var warnSSHAgentNotRunning bool

func checkSSHAgent() {
	if warnSSHAgentNotRunning {
		return
	}

	_, err := getSshAgent()
	if err != nil {
		if agentErr, ok := err.(*SSHAgentNotRunning); ok {
			agentErr.PrintWarning()
		}
	}
	warnSSHAgentNotRunning = true
}
