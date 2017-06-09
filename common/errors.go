package saultcommon

import (
	"fmt"
	"strings"

	"github.com/spikeekips/sault/saultssh"
)

type InvalidAccountNameError struct {
	Name string
}

func (e *InvalidAccountNameError) Error() string {
	return fmt.Sprintf("invalid account name, '%s'", e.Name)
}

type InvalidHostIDError struct {
	ID string
}

func (e *InvalidHostIDError) Error() string {
	return fmt.Sprintf("invalid host.ID, '%s'", e.ID)
}

type InvalidUserIDError struct {
	ID string
}

func (e *InvalidUserIDError) Error() string {
	return fmt.Sprintf("invalid user id, '%s'", e.ID)
}

type InvalidHostAddressError struct {
	Address string
	Err     error
}

func (e *InvalidHostAddressError) Error() string {
	return fmt.Sprintf("invalid host address, '%s': %v", e.Address, e.Err)
}

type UserDoesNotExistError struct {
	ID        string
	PublicKey saultssh.PublicKey
	Message   string
}

func (e *UserDoesNotExistError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	var v []string
	if e.ID != "" {
		v = append(v, fmt.Sprintf("'%s'", e.ID))
	}
	if e.PublicKey != nil {
		v = append(v, fmt.Sprintf("'%s'", FingerprintSHA256PublicKey(e.PublicKey)))
	}

	return fmt.Sprintf("user, %s does not exist", strings.Join(v, " "))
}

type HostDoesNotExistError struct {
	ID      string
	Message string
}

func (e *HostDoesNotExistError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return fmt.Sprintf("host, '%s' does not exist", e.ID)
}

type UserExistsError struct {
	ID        string
	PublicKey []byte
}

func (e *UserExistsError) Error() string {
	var v []string
	if e.ID != "" {
		v = append(v, fmt.Sprintf("id, '%s'", e.ID))
	}
	if len(e.PublicKey) > 0 {
		v = append(v, fmt.Sprintf("publicKey, '%s'", strings.TrimSpace(string(e.PublicKey))))
	}

	return fmt.Sprintf("user with %s already exists", strings.Join(v, " and "))
}

type HostExistError struct {
	ID string
}

func (e *HostExistError) Error() string {
	return fmt.Sprintf("host, '%s' already exists", e.ID)
}

type LinkedAllError struct {
}

func (e *LinkedAllError) Error() string {
	return "Linked all"
}
