package sasl_test

import (
	"bytes"
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
