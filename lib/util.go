package sault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/nu7hatch/gouuid"
	"github.com/spikeekips/sault/ssh"
)

func GetPrivateKeySigner(keyFilePath string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	return GetPrivateKeySignerFromString(string(b))
}

func GetPrivateKeySignerFromString(s string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey([]byte(s))
	if err != nil {
		return nil, err
	}

	return signer, nil
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

func ParsePublicKeyFromString(s string) (ssh.PublicKey, error) {
	body := s
	f := strings.Fields(s)
	if len(f) < 2 {
		body = f[0]
	} else {
		body = f[1]
	}

	key, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePublicKey([]byte(key))
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

func GetAuthorizedKeyFromPublicKey(publicKey ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
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
	pub, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return []byte{}, err
	}

	return ssh.MarshalAuthorizedKey(pub), nil
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
