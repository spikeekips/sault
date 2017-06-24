package saultcommon

import (
	"fmt"
	"strings"

	"github.com/spikeekips/sault/saultssh"
)

// InvalidAccountNameError means wrong accout name
type InvalidAccountNameError struct {
	Name string
}

func (e *InvalidAccountNameError) Error() string {
	return fmt.Sprintf("invalid account name, '%s'", e.Name)
}

// InvalidHostIDError means wrong host id
type InvalidHostIDError struct {
	ID string
}

func (e *InvalidHostIDError) Error() string {
	return fmt.Sprintf("invalid host.ID, '%s'", e.ID)
}

// InvalidUserIDError means wrong user id
type InvalidUserIDError struct {
	ID string
}

func (e *InvalidUserIDError) Error() string {
	return fmt.Sprintf("invalid user id, '%s'", e.ID)
}

// InvalidHostAddressError means wrong host address
type InvalidHostAddressError struct {
	Address string
	Err     error
}

func (e *InvalidHostAddressError) Error() string {
	return fmt.Sprintf("invalid host address, '%s': %v", e.Address, e.Err)
}

// UserDoesNotExistError means user does not exists
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
		v = append(v, fmt.Sprintf("id='%s'", e.ID))
	}
	if e.PublicKey != nil {
		v = append(v, fmt.Sprintf("publickey='%s'", FingerprintSHA256PublicKey(e.PublicKey)))
	}

	return fmt.Sprintf("user, %s does not exist", strings.Join(v, ", "))
}

// HostDoesNotExistError means host does not exist
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

// UserExistsError means user exist
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

// HostExistError means host exist
type HostExistError struct {
	ID string
}

func (e *HostExistError) Error() string {
	return fmt.Sprintf("host, '%s' already exists", e.ID)
}

// LinkedAllError means failed to link
type LinkedAllError struct {
}

func (e *LinkedAllError) Error() string {
	return "Linked all"
}

// UserNothingToUpdate means almost same with the target user
type UserNothingToUpdate struct {
	ID string
}

func (e *UserNothingToUpdate) Error() string {
	return fmt.Sprintf("nothing to be updated for user, '%s'", e.ID)
}

// HostNothingToUpdate means almost same with the target host
type HostNothingToUpdate struct {
	ID string
}

func (e *HostNothingToUpdate) Error() string {
	return fmt.Sprintf("nothing to be updated for host, '%s'", e.ID)
}

// HostAndUserNotLinked means host and user is not linked
type HostAndUserNotLinked struct {
	UserID string
	HostID string
}

func (e *HostAndUserNotLinked) Error() string {
	return fmt.Sprintf("user, '%s' and host, '%s' was not linked", e.UserID, e.HostID)
}
