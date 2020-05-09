package sasl_test

import (
	"bytes"
	"testing"

	"github.com/emersion/go-sasl"
)

func TestNewOAuthBearerClientNoHostOrPort(t *testing.T) {
	c := sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
		Username: "user@example.com",
		Token:    "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==",
	})
	mech, ir, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "OAUTHBEARER" {
		t.Error("Invalid mechanism name:", mech)
	}
	expected := []byte{110, 44, 97, 61, 117, 115, 101, 114,
		64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111,
		109, 44, 1,
		97, 117, 116, 104, 61, 66, 101, 97, 114, 101,
		114, 32, 118, 70, 57, 100, 102, 116, 52, 113, 109,
		84, 99, 50, 78, 118, 98, 51, 82, 108, 99, 107, 66,
		104, 98, 72, 82, 104, 100, 109, 108, 122, 100, 71,
		69, 117, 89, 50, 57, 116, 67, 103, 61, 61, 1, 1}
	if bytes.Compare(ir, expected) != 0 {
		t.Error("Invalid initial response:", ir)
	}
}

func TestNewOAuthBearerClient(t *testing.T) {
	c := sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
		Username: "user@example.com",
		Token:    "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==",
		Host:     "server.example.com",
		Port:     143,
	})

	mech, ir, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "OAUTHBEARER" {
		t.Error("Invalid mechanism name:", mech)
	}

	expected := []byte{110, 44, 97, 61, 117, 115, 101, 114,
		64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111,
		109, 44, 1, 104, 111, 115, 116, 61, 115, 101, 114,
		118, 101, 114, 46, 101, 120, 97, 109, 112, 108, 101,
		46, 99, 111, 109, 1, 112, 111, 114, 116, 61, 49, 52,
		51, 1, 97, 117, 116, 104, 61, 66, 101, 97, 114, 101,
		114, 32, 118, 70, 57, 100, 102, 116, 52, 113, 109,
		84, 99, 50, 78, 118, 98, 51, 82, 108, 99, 107, 66,
		104, 98, 72, 82, 104, 100, 109, 108, 122, 100, 71,
		69, 117, 89, 50, 57, 116, 67, 103, 61, 61, 1, 1}
	if bytes.Compare(ir, expected) != 0 {
		t.Error("Invalid initial response:", ir)
	}

	challenge := []byte("eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIiwic2NvcGUiOiJleGFt" +
		"cGxlX3Njb3BlIiwib3BlbmlkLWNvbmZpZ3VyYXRpb24iOiJodHRwczovL2V4YW1wbGUu" +
		"Y29tLy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uIn0=")

	if _, err := c.Next(challenge); err == nil {
		t.Fatal("Expected error from handling challenge")
	}

	if _, err := c.Next([]byte("")); err == nil {
		t.Fatal("Expected error from handling challenge")
	}

}

func TestOAuthBearerServerAndClient(t *testing.T) {
	oauthErr := sasl.OAuthBearerError{
		Status:  "invalid_token",
		Scope:   "email",
		Schemes: "bearer",
	}
	authenticator := func(opts sasl.OAuthBearerOptions) *sasl.OAuthBearerError {
		if opts.Username == "fxcp" && opts.Token == "VkIvciKi9ijpiKNWrQmYCJrzgd9QYCMB" {
			return nil
		}
		return &oauthErr
	}

	t.Run("valid token", func(t *testing.T) {
		s := sasl.NewOAuthBearerServer(authenticator)
		c := sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
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
		s := sasl.NewOAuthBearerServer(authenticator)
		c := sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
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
		authzErr, ok := err.(*sasl.OAuthBearerError)
		if !ok {
			t.Fatal("Not OAuthBearerError")
		}
		if authzErr.Status != "invalid_token" {
			t.Fatal("Wrong status:", authzErr.Status)
		}
		if authzErr.Scope != "email" {
			t.Fatal("Wrong scope:", authzErr.Scope)
		}
	})
}
