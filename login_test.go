package sasl_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/emersion/go-sasl"
)

func TestNewLoginClient(t *testing.T) {
	c := sasl.NewLoginClient("username", "Password:")

	mech, resp, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "LOGIN" {
		t.Error("Invalid mechanism name:", mech)
	}

	expected := []byte{117, 115, 101, 114, 110, 97, 109, 101}
	if bytes.Compare(resp, expected) != 0 {
		t.Error("Invalid initial response:", resp)
	}

	resp, err = c.Next(expected)
	if err != sasl.ErrUnexpectedServerChallenge {
		t.Error("Invalid chalange")
	}

	expected = []byte("Password:")
	resp, err = c.Next(expected)
	if bytes.Compare(resp, expected) != 0 {
		t.Error("Invalid initial response:", resp)
	}
}

func TestNewLoginServer(t *testing.T) {
	var authenticated = false
	s := sasl.NewLoginServer(func(username, password string) error {
		if username != "tim" {
			return errors.New("Invalid username: " + username)
		}
		if password != "tanstaaftanstaaf" {
			return errors.New("Invalid password: " + password)
		}

		authenticated = true
		return nil
	})

	challenge, done, err := s.Next(nil)
	if err != nil {
		t.Fatal("Error while starting server:", err)
	}
	if done {
		t.Fatal("Done after starting server")
	}
	if string(challenge) != "Username:" {
		t.Error("Invalid first challenge:", challenge)
	}

	challenge, done, err = s.Next([]byte("tim"))
	if err != nil {
		t.Fatal("Error while sending username:", err)
	}
	if done {
		t.Fatal("Done after sending username")
	}
	if string(challenge) != "Password:" {
		t.Error("Invalid challenge after sending username:", challenge)
	}

	challenge, done, err = s.Next([]byte("tanstaaftanstaaf"))
	if err != nil {
		t.Fatal("Error while sending password:", err)
	}
	if !done {
		t.Fatal("Authentication not finished after sending password")
	}
	if len(challenge) > 0 {
		t.Error("Invalid non-empty final challenge:", challenge)
	}

	if !authenticated {
		t.Error("Not authenticated")
	}

	// Tests with initial response field, as per RFC4422 section 3
	authenticated = false
	s = sasl.NewLoginServer(func(username, password string) error {
		if username != "tim" {
			return errors.New("Invalid username: " + username)
		}
		if password != "tanstaaftanstaaf" {
			return errors.New("Invalid password: " + password)
		}

		authenticated = true
		return nil
	})

	challenge, done, err = s.Next([]byte("tim"))
	if err != nil {
		t.Fatal("Error while sending username:", err)
	}
	if done {
		t.Fatal("Done after sending username")
	}
	if string(challenge) != "Password:" {
		t.Error("Invalid challenge after sending username:", string(challenge))
	}

	challenge, done, err = s.Next([]byte("tanstaaftanstaaf"))
	if err != nil {
		t.Fatal("Error while sending password:", err)
	}
	if !done {
		t.Fatal("Authentication not finished after sending password")
	}
	if len(challenge) > 0 {
		t.Error("Invalid non-empty final challenge:", challenge)
	}

	if !authenticated {
		t.Error("Not authenticated")
	}
}
