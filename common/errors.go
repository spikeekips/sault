package saultcommon

import "fmt"

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
