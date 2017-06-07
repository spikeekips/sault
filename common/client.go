package saultcommon

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spikeekips/sault/sssh"
)

type SSHClient struct {
	Client       *sssh.Client
	clientConfig *sssh.ClientConfig
	address      string
}

func NewSSHClient(account, address string) *SSHClient {
	clientConfig := &sssh.ClientConfig{
		User:            account,
		HostKeyCallback: sssh.InsecureIgnoreHostKey(),
	}

	return &SSHClient{
		address:      address,
		clientConfig: clientConfig,
	}
}

func (s *SSHClient) Close() {
	if s.Client == nil {
		return
	}
	s.Client.Close()
}

func (s *SSHClient) SetTimeout(t time.Duration) {
	s.clientConfig.Timeout = t
}

func (s *SSHClient) AddAuthMethod(auths ...sssh.AuthMethod) {
	s.clientConfig.Auth = append(
		s.clientConfig.Auth,
		auths...,
	)
}

func (s *SSHClient) Connect() error {
	client, err := sssh.Dial("tcp", s.address, s.clientConfig)
	if err != nil {
		return err
	}

	s.Client = client

	return nil
}

func (s *SSHClient) newSession() (*sssh.Session, error) {
	session, err := s.Client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *SSHClient) Run(cmd string) (output []byte, err error) {
	var session *sssh.Session
	session, err = s.newSession()
	if err != nil {
		return
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	if err != nil {
		return
	}

	output = b.Bytes()
	return
}

func (s *SSHClient) PutFile(content string, dest string, perm os.FileMode) error {
	dest = s.expandUserDir(dest)
	base, name := s.splitPath(dest)

	s.MakeDir(base, 0700, true)

	session, err := s.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()

		fmt.Fprintln(w, fmt.Sprintf("C0%o", perm), len(content), name)
		fmt.Fprint(w, content)
		fmt.Fprint(w, "\x00")
	}()

	if err = session.Run(fmt.Sprintf("scp -rqt %s", base)); err != nil {
		return err
	}

	return nil
}

func (s *SSHClient) GetFile(dest string) (content []byte, err error) {
	var session *sssh.Session
	session, err = s.newSession()
	if err != nil {
		return
	}
	defer session.Close()

	dest = s.expandUserDir(dest)

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()

		fmt.Fprintln(w, "\x00\x00\x00\x00\x00\x00\x00")
	}()

	var b bytes.Buffer
	session.Stdout = &b
	if err = session.Run(fmt.Sprintf("scp -qf %s", dest)); err != nil {
		return
	}

	_, err = b.ReadString('\n')
	if err != nil && err != io.EOF {
		return
	}
	err = nil

	var c bytes.Buffer
	io.Copy(&c, &b)

	content = c.Bytes()
	return content[:len(content)-1], nil // remove the last "\x00"
	return
}

func (s *SSHClient) Remove(dest string) error {
	var session *sssh.Session
	{
		var err error
		session, err = s.newSession()
		if err != nil {
			return nil
		}
	}
	defer session.Close()

	if err := session.Run(fmt.Sprintf("rm -rf %s", dest)); err != nil {
		return err
	}

	return nil
}

func (s *SSHClient) expandUserDir(d string) string {
	d = filepath.Clean(d)

	if strings.HasPrefix(d, "~/") {
		d = strings.TrimPrefix(d, "~/")
	}

	return d
}

func (s *SSHClient) splitPath(d string) (string, string) {
	base, name := filepath.Split(filepath.Clean(d))
	if base == "" {
		base = "./"
	}

	return base, name
}

func (s *SSHClient) MakeDir(dest string, perm os.FileMode, recursive bool) error {
	dest = s.expandUserDir(dest)

	if recursive {
		paths := StringFilter(
			strings.Split(dest, "/"),
			func(n string) bool {
				return len(strings.TrimSpace(n)) > 0
			},
		)
		for i, _ := range paths {
			var parent string
			if strings.HasPrefix(dest, "/") {
				parent = fmt.Sprintf("/%s", strings.Join(paths[:i+1], "/"))
			} else {
				parent = strings.Join(paths[:i+1], "/")
			}
			if err := s.MakeDir(parent, perm, false); err != nil {
				log.Debugf("SSHClient.Mkdir: failed to create directory, '%s': %v", parent, err)
			} else {
				log.Debugf("SSHClient.Mkdir: successfully created directory, '%s'", parent)
			}
		}

		return nil
	}

	session, err := s.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	base, name := s.splitPath(dest)

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()

		fmt.Fprintln(w, fmt.Sprintf("D0%o", perm), 0, name)
	}()

	if err := session.Run(fmt.Sprintf("scp -qtr %s", base)); err != nil {
		return err
	}

	return nil
}
