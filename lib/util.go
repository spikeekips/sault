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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/nu7hatch/gouuid"
	"github.com/spikeekips/sault/ssh"
)

func GetPrivateKeySigner(keyFilePath string) (saultSsh.Signer, error) {
	b, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	return GetPrivateKeySignerFromString(string(b))
}

func GetPrivateKeySignerFromString(s string) (saultSsh.Signer, error) {
	signer, err := saultSsh.ParsePrivateKey([]byte(s))
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// FingerprintMD5 from https://github.com/golang/go/issues/12292#issuecomment-255588529 //
func FingerprintMD5(key saultSsh.PublicKey) string {
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

// FingerprintSHA256 from https://github.com/golang/go/issues/12292#issuecomment-255588529 //
func FingerprintSHA256(key saultSsh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return strings.TrimRight(b64hash, "=")
}

func ParseLogLevel(v string) (log.Level, error) {
	if v == "quiet" {
		return log.FatalLevel, nil
	}

	level, err := log.ParseLevel(v)
	if err != nil {
		return log.FatalLevel, err
	}

	return level, err
}

func ParseLogOutput(output string, level string) (io.Writer, error) {
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

func GetAuthorizedKeyFromString(publicKey string) (string, error) {
	parsed, err := ParsePublicKeyFromString(publicKey)
	if err != nil {
		return "", nil
	}
	return GetAuthorizedKeyFromPublicKey(parsed), nil
}

func GetAuthorizedKeyFromPublicKey(publicKey saultSsh.PublicKey) string {
	return strings.TrimSpace(string(saultSsh.MarshalAuthorizedKey(publicKey)))
}

func GetUUID() string {
	s, _ := uuid.NewV5(uuid.NamespaceURL, []byte(time.Now().Format("Jan _2 15:04:05.000000000")))
	return s.String()
}

func CreateRSAPrivateKey(bits int) (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	return
}

func EncodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	out := bytes.NewBuffer([]byte{})
	if err := pem.Encode(out, privateKeyPEM); err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}

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

func ParseTolerateFilePath(path string) (isTolerated bool, realPath string) {
	realPath = path
	if string([]rune(path)[0]) != "@" {
		return
	}

	isTolerated = true
	realPath = string([]rune(path)[1:])
	return
}

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

func MakeFirstLowerCase(s string) string {
	if len(s) < 2 {
		return strings.ToLower(s)
	}

	bts := []byte(s)

	lc := bytes.ToLower([]byte{bts[0]})
	rest := bts[1:]

	return string(bytes.Join([][]byte{lc, rest}, nil))
}

type TermSize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

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

func CheckUserName(s string) bool {
	if len(s) > 32 { // see `man useradd`
		return false
	}

	return regexp.MustCompile(`^(?i)[0-9a-z]+[\w\-]*[0-9a-z]+$`).MatchString(s)
}

func CheckHostName(s string) bool {
	if len(s) > 64 { // see `$ getconf HOST_NAME_MAX`, in osx it will be 255
		return false
	}

	return regexp.MustCompile(`^(?i)[0-9a-z]+[\w\-]*[0-9a-z]+$`).MatchString(s)
}

var CommonTempalteFMap template.FuncMap

func FormatResponse(t string, values map[string]interface{}) string {
	tmpl, _ := template.New("t").Funcs(CommonTempalteFMap).Parse(t)

	values["line"] = strings.Repeat("-", int(CurrentTermSize.Col))

	bw := bytes.NewBuffer([]byte{})
	tmpl.Execute(bw, values)

	return strings.TrimSpace(bw.String())
}

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

var CurrentTermSize TermSize

func init() {
	CommonTempalteFMap = template.FuncMap{
		"red":     color.New(color.FgRed).SprintFunc(),
		"green":   color.New(color.FgGreen).SprintFunc(),
		"yellow":  color.New(color.FgYellow).SprintFunc(),
		"blue":    color.New(color.FgBlue).SprintFunc(),
		"magenta": color.New(color.FgMagenta).SprintFunc(),
		"cyan":    color.New(color.FgCyan).SprintFunc(),
		"escape": func(s string) template.HTML {
			return template.HTML(s)
		},
	}

	termSize, err := GetTermSize()
	if err == nil {
		CurrentTermSize = *termSize
	}
}
