package saultcommon

import (
	"testing"
)

func TestPascalCase(t *testing.T) {
	{
		s := "this-is-normal"
		e := "This-is-normal"
		if MakePascalCase(s) != e {
			t.Errorf("MakePascalCase(s) != e; '%s' != '%s'", MakePascalCase(s), e)
		}
	}

	{
		s := "ThisIsNormal"
		e := s
		if MakePascalCase(s) != e {
			t.Errorf("MakePascalCase(s) != e; '%s' != '%s'", MakePascalCase(s), e)
		}
	}

	{
		s := "thisIsNormal"
		e := "ThisIsNormal"
		if MakePascalCase(s) != e {
			t.Errorf("MakePascalCase(s) != e; '%s' != '%s'", MakePascalCase(s), e)
		}
	}

	{
		s := "this_is_normal"
		e := "ThisIsNormal"
		if MakePascalCase(s) != e {
			t.Errorf("MakePascalCase(s) != e; '%s' != '%s'", MakePascalCase(s), e)
		}
	}

	{
		s := "This_is_normal"
		e := "ThisIsNormal"
		if MakePascalCase(s) != e {
			t.Errorf("MakePascalCase(s) != e; '%s' != '%s'", MakePascalCase(s), e)
		}
	}
}

func TestParseSaultAccountName(t *testing.T) {
	{
		// empty
		s := ""
		_, _, err := ParseSaultAccountName(s)
		if err == nil {
			t.Errorf("error must be occurred")
		}
	}

	{
		// + empty
		s := "+"
		_, _, err := ParseSaultAccountName(s)
		if err == nil {
			t.Errorf("error must be occurred")
		}
	}

	{
		// empty hostID
		s := "account+"
		account, hostID, err := ParseSaultAccountName(s)
		if err != nil {
			t.Error(err)
		}
		if account != "account" {
			t.Errorf(`account != "account"; '%s' != 'account'`, account)
		}
		if len(hostID) > 0 {
			t.Error("hostID must be zero")
		}
	}

	{
		// empty account
		s := "host"
		account, hostID, err := ParseSaultAccountName(s)
		if err != nil {
			t.Error(err)
		}
		if hostID != "host" {
			t.Errorf(`hostID != "host"; '%s' != 'host'`, hostID)
		}
		if len(account) > 0 {
			t.Error("account must be zero")
		}
	}

	{
		// ++
		s := "account++host"
		_, _, err := ParseSaultAccountName(s)
		if err == nil {
			t.Error("'InvalidHostIDError' must be occurred")
		}
		if _, ok := err.(*InvalidHostIDError); !ok {
			t.Error("'InvalidHostIDError' must be occurred: %v", err)
		}
	}

	{
		// + prefixed
		s := "+account++host"
		_, _, err := ParseSaultAccountName(s)
		if err == nil {
			t.Error("'InvalidHostIDError' must be occurred")
		}
		if _, ok := err.(*InvalidAccountNameError); !ok {
			t.Error("'InvalidAccountNameError' must be occurred: %v", err)
		}
	}

	{
		// valid
		s := "account+host"
		account, hostID, err := ParseSaultAccountName(s)
		if err != nil {
			t.Error(err)
		}
		if account != "account" {
			t.Errorf(`account != "account"; '%s' != 'account'`, account)
		}
		if hostID != "host" {
			t.Errorf(`hostID != "host"; '%s' != 'host'`, hostID)
		}
	}
}

func TestParseMinusName(t *testing.T) {
	{
		s := "shoem"
		a, minus := ParseMinusName(s)
		if a != s {
			t.Errorf("a != s; '%s' != '%s'", a, s)
		}
		if minus {
			t.Errorf("minus must be false")
		}
	}
	{
		s := "shoem"
		a, minus := ParseMinusName(s + "-")
		if a != s {
			t.Errorf("a != s; '%s' != '%s'", a, s)
		}
		if !minus {
			t.Errorf("minus must be true")
		}
	}
	{
		// with blank
		s := "shoem"
		a, minus := ParseMinusName(s + "- ")
		if a != s {
			t.Errorf("a != s; '%s' != '%s'", a, s)
		}
		if !minus {
			t.Errorf("minus must be true")
		}
	}
}
