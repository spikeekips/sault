package saultcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPascalCase(t *testing.T) {
	{
		s := "this-is-normal"
		e := "This-is-normal"

		assert.Equal(t, e, MakePascalCase(s))
	}

	{
		s := "ThisIsNormal"
		e := s
		assert.Equal(t, e, MakePascalCase(s))
	}

	{
		s := "thisIsNormal"
		e := "ThisIsNormal"
		assert.Equal(t, e, MakePascalCase(s))
	}

	{
		s := "this_is_normal"
		e := "ThisIsNormal"
		assert.Equal(t, e, MakePascalCase(s))
	}

	{
		s := "This_is_normal"
		e := "ThisIsNormal"
		assert.Equal(t, e, MakePascalCase(s))
	}
}

func TestParseSaultAccountName(t *testing.T) {
	{
		// empty
		s := ""
		_, _, err := ParseSaultAccountName(s)
		assert.NotNil(t, err)
		assert.Error(t, &InvalidAccountNameError{}, err)
	}

	{
		// + empty
		s := "+"
		_, _, err := ParseSaultAccountName(s)
		assert.NotNil(t, err)
		assert.Error(t, &InvalidAccountNameError{}, err)
	}

	{
		// empty hostID
		s := "account+"
		account, hostID, err := ParseSaultAccountName(s)
		assert.Nil(t, err)
		assert.Equal(t, "account", account)
		assert.True(t, len(hostID) < 1)
	}

	{
		// empty account
		s := "host"
		account, hostID, err := ParseSaultAccountName(s)

		assert.Nil(t, err)
		assert.Equal(t, hostID, s)
		assert.True(t, len(account) < 1)
	}

	{
		// ++
		s := "account++host"
		_, _, err := ParseSaultAccountName(s)

		assert.NotNil(t, err)
		assert.Error(t, &InvalidHostIDError{}, err)
	}

	{
		// + prefixed
		s := "+account++host"
		_, _, err := ParseSaultAccountName(s)

		assert.NotNil(t, err)
		assert.Error(t, &InvalidAccountNameError{}, err)
	}

	{
		// valid
		s := "account+host"
		account, hostID, err := ParseSaultAccountName(s)

		assert.Nil(t, err)
		assert.Equal(t, "account", account)
		assert.Equal(t, "host", hostID)
	}
}

func TestParseMinusName(t *testing.T) {
	{
		s := "shoem"
		a, minus := ParseMinusName(s)

		assert.Equal(t, s, a)
		assert.False(t, minus)
	}
	{
		s := "shoem"
		a, minus := ParseMinusName(s + "-")

		assert.Equal(t, s, a)
		assert.True(t, minus)
	}
	{
		// with blank
		s := "shoem"
		a, minus := ParseMinusName(s + "- ")

		assert.Equal(t, s, a)
		assert.True(t, minus)
	}
}
