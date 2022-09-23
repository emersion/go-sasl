package sasl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The XOAUTH2 mechanism name.
const XOAuth2 = "XOAUTH2"

type XOAuth2Error struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

type XOAuth2Options struct {
	Username string
	Token    string
}

// Implements error
func (err *XOAuth2Error) Error() string {
	return fmt.Sprintf("XOAUTH2 authentication error (%v)", err.Status)
}

type xoauth2Client struct {
	XOAuth2Options
}

func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	ir = []byte(`user=`)
	ir = append(ir, a.Username...)
	ir = append(ir, '\x01')
	ir = append(ir, []byte(`auth=Bearer `)...)
	ir = append(ir, a.Token...)
	ir = append(ir, '\x01', '\x01')

	return XOAuth2, ir, nil
}

func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	authErr := &XOAuth2Error{}
	if err := json.Unmarshal(challenge, authErr); err != nil {
		return nil, err
	} else {
		return nil, authErr
	}
}

// NewXOAuth2Client An implementation of the XOAUTH2 authentication mechanism, as
// described in Google / Microsoft docs, example
// https://developers.google.com/gmail/imap/xoauth2-protocol
func NewXOAuth2Client(opt *XOAuth2Options) Client {
	return &xoauth2Client{*opt}
}

type XOAuth2Authenticator func(opts XOAuth2Options) *XOAuth2Error

type xoauth2Server struct {
	done         bool
	failErr      error
	authenticate XOAuth2Authenticator
}

func (a *xoauth2Server) fail(descr string) ([]byte, bool, error) {
	blob, err := json.Marshal(XOAuth2Error{
		Status:  "invalid_request",
		Schemes: "bearer",
	})
	if err != nil {
		panic(err) // wtf
	}
	a.failErr = errors.New(descr)
	return blob, false, nil
}

func (a *xoauth2Server) Next(response []byte) (challenge []byte, done bool, err error) {
	if a.failErr != nil {
		if len(response) != 1 && response[0] != 0x01 {
			return nil, true, errors.New("unexpected response")
		}
		return nil, true, a.failErr
	}

	if a.done {
		err = ErrUnexpectedClientResponse
		return
	}

	// Generate empty challenge.
	if response == nil {
		return []byte{}, false, nil
	}

	a.done = true

	// Cut user=username\x01auth=...\x01\x01
	// into
	// user=username
	// auth=...
	// <blank>
	// <blank>
	parts := bytes.Split(response, []byte{0x01})
	if len(parts) != 4 {
		return a.fail("Invalid response")
	}
	user := parts[0]
	auth := parts[1]

	opts := XOAuth2Options{}
	if len(user) > 0 {
		if !bytes.HasPrefix(user, []byte("user=")) {
			return a.fail("Invalid response, missing 'user=' in gs2-authzid")
		}
		opts.Username = string(bytes.TrimPrefix(user, []byte("user=")))
	}
	if len(auth) > 0 {
		pParts := bytes.SplitN(auth, []byte{'='}, 2)
		if len(pParts) != 2 {
			return a.fail("Invalid response, missing '='")
		}

		switch string(pParts[0]) {
		case "auth":
			const prefix = "bearer "
			strValue := string(pParts[1])
			// Token type is case-insensitive.
			if !strings.HasPrefix(strings.ToLower(strValue), prefix) {
				return a.fail("Unsupported token type")
			}
			opts.Token = strValue[len(prefix):]
		default:
			return a.fail("Invalid response, unknown parameter: " + string(pParts[0]))
		}
	}

	authzErr := a.authenticate(opts)
	if authzErr != nil {
		blob, err := json.Marshal(authzErr)
		if err != nil {
			panic(err) // wtf
		}
		a.failErr = authzErr
		return blob, false, nil
	}

	return nil, true, nil
}

func NewXOAuth2Server(auth XOAuth2Authenticator) Server {
	return &xoauth2Server{authenticate: auth}
}
