package sault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spikeekips/sault/ssh"
)

type sshClient struct {
	client       *saultSsh.Client
	clientConfig *saultSsh.ClientConfig
	address      string
}

func newsshClient(account, address string) *sshClient {
	clientConfig := &saultSsh.ClientConfig{
		User:            account,
		HostKeyCallback: saultSsh.InsecureIgnoreHostKey(),
	}

	return &sshClient{
		address:      address,
		clientConfig: clientConfig,
	}
}

func (s *sshClient) close() {
	if s.client == nil {
		return
	}
	s.client.Close()
}

func (s *sshClient) setTimeout(t time.Duration) {
	s.clientConfig.Timeout = t
}

func (s *sshClient) addAuthMethod(auths ...saultSsh.AuthMethod) {
	s.clientConfig.Auth = append(
		s.clientConfig.Auth,
		auths...,
	)
}

func (s *sshClient) connect() error {
	client, err := saultSsh.Dial("tcp", s.address, s.clientConfig)
	if err != nil {
		return err
	}

	s.client = client

	return nil
}

func (s *sshClient) newSession() (*saultSsh.Session, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *sshClient) Run(cmd string) (output []byte, err error) {
	var session *saultSsh.Session
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

func (s *sshClient) PutFile(content string, dest string, perm os.FileMode) error {
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

func (s *sshClient) GetFile(dest string) (content []byte, err error) {
	var session *saultSsh.Session
	session, err = s.newSession()
	if err != nil {
		return
	}
	defer session.Close()

	dest = s.expandUserDir(dest)

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprint(w, "\x00\x00\x00\x00\x00\x00\x00")
	}()

	var b bytes.Buffer
	session.Stdout = &b
	if err = session.Run(fmt.Sprintf("scp -qf %s", dest)); err != nil {
		return
	}

	content = b.Bytes()
	return
}

func (s *sshClient) Remove(dest string) error {
	var session *saultSsh.Session
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

func (s *sshClient) expandUserDir(d string) string {
	d = filepath.Clean(d)

	if strings.HasPrefix(d, "~/") {
		d = strings.TrimPrefix(d, "~/")
	}

	return d
}

func (s *sshClient) splitPath(d string) (string, string) {
	base, name := filepath.Split(filepath.Clean(d))
	if base == "" {
		base = "./"
	}

	return base, name
}

func (s *sshClient) MakeDir(dest string, perm os.FileMode, recursive bool) error {
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
				log.Debugf("sshClient.Mkdir: failed to create directory, '%s': %v", parent, err)
			} else {
				log.Debugf("sshClient.Mkdir: successfully created directory, '%s'", parent)
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
