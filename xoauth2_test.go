package sasl_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
)

func TestNewXoauth2Client(t *testing.T) {
	c := sasl.NewXoauth2Client("user@example.com", "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==")

	mech, ir, err := c.Start()
	if err != nil {
		t.Fatal("Error while starting client:", err)
	}
	if mech != "XOAUTH2" {
		t.Error("Invalid mechanism name:", mech)
	}

	expected := "user=user@example.com\u0001auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\u0001\u0001"
	if strings.Compare(string(ir), expected) != 0 {
		t.Error("Invalid initial response:", string(ir))
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
