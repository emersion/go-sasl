package sasl_test

import (
	"bytes"
	"testing"

	"github.com/emersion/go-sasl"
)

func TestNewXOAuth2Client(t *testing.T) {
	c := sasl.NewXOAuth2Client(&sasl.XOAuth2Options{
		Username: "user@example.com",
		Token:    "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==",
	})
	mech, ir, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "XOAUTH2" {
		t.Error("Invalid mechanism name:", mech)
	}

	expected := []byte{117, 115, 101, 114, 61, 117, 115, 101, 114,
		64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111,
		109, 1,
		97, 117, 116, 104, 61, 66, 101, 97, 114, 101,
		114, 32, 118, 70, 57, 100, 102, 116, 52, 113, 109,
		84, 99, 50, 78, 118, 98, 51, 82, 108, 99, 107, 66,
		104, 98, 72, 82, 104, 100, 109, 108, 122, 100, 71,
		69, 117, 89, 50, 57, 116, 67, 103, 61, 61, 1, 1}
	if bytes.Compare(ir, expected) != 0 {
		t.Error("Invalid initial response:", ir)
	}
}

func TestXOAuth2ServerAndClient(t *testing.T) {
	oauthErr := sasl.XOAuth2Error{
		Status:  "invalid_token",
		Scope:   "email",
		Schemes: "bearer",
	}
	authenticator := func(opts sasl.XOAuth2Options) *sasl.XOAuth2Error {
		if opts.Username == "fxcp" && opts.Token == "VkIvciKi9ijpiKNWrQmYCJrzgd9QYCMB" {
			return nil
		}
		return &oauthErr
	}

	t.Run("valid token", func(t *testing.T) {
		s := sasl.NewXOAuth2Server(authenticator)
		c := sasl.NewXOAuth2Client(&sasl.XOAuth2Options{
			Username: "fxcp",
			Token:    "VkIvciKi9ijpiKNWrQmYCJrzgd9QYCMB",
		})
		_, ir, err := c.Start()
		if err != nil {
			t.Fatal(err)
		}
		_, done, err := s.Next(ir)
		if err != nil {
			t.Fatal("Unexpected error")
		}
		if !done {
			t.Fatal("Exchange is not complete")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		s := sasl.NewXOAuth2Server(authenticator)
		c := sasl.NewXOAuth2Client(&sasl.XOAuth2Options{
			Username: "fxcp",
			Token:    "adiffrentone",
		})
		_, ir, err := c.Start()
		if err != nil {
			t.Fatal(err)
		}
		val, done, err := s.Next(ir)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			t.Fatal("Exchange is marked complete")
		}

		_, err = c.Next(val)
		if err == nil {
			t.Fatal("Expected an error")
		}
		authzErr, ok := err.(*sasl.XOAuth2Error)
		if !ok {
			t.Fatal("Not XOAuth2Error")
		}
		if authzErr.Status != "invalid_token" {
			t.Fatal("Wrong status:", authzErr.Status)
		}
		if authzErr.Scope != "email" {
			t.Fatal("Wrong scope:", authzErr.Scope)
		}
	})

	authenticator = func(opts sasl.XOAuth2Options) *sasl.XOAuth2Error {
		if opts.Username == "" && opts.Token == "VkIvciKi9ijpiKNWrQmYCJrzgd9QYCMB" {
			return nil
		}
		return &oauthErr
	}
	t.Run("valid token, no username", func(t *testing.T) {
		s := sasl.NewXOAuth2Server(authenticator)
		c := sasl.NewXOAuth2Client(&sasl.XOAuth2Options{
			Token: "VkIvciKi9ijpiKNWrQmYCJrzgd9QYCMB",
		})
		_, ir, err := c.Start()
		if err != nil {
			t.Fatal(err)
		}
		_, done, err := s.Next(ir)
		if err != nil {
			t.Fatal("Unexpected error")
		}
		if !done {
			t.Fatal("Exchange is not complete")
		}
	})
}
