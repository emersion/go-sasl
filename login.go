package sasl

import (
	"bytes"
)

// The LOGIN mechanism name.
const Login = "LOGIN"

var expectedChallenge = []byte{80, 97, 115, 115, 119, 111, 114, 100, 58}

type loginClient struct {
	Username string
	Password string
}

func (a *loginClient) Start() (mech string, ir []byte, err error) {
	mech = "LOGIN"
	ir = []byte(a.Username)
	return
}

func (a *loginClient) Next(challenge []byte) (response []byte, err error) {
	if bytes.Compare(challenge, expectedChallenge) != 0 {
		return nil, ErrUnexpectedServerChallenge
	} else {
		return []byte(a.Password), nil
	}
}

// A client implementation of the LOGIN authentication mechanism for SMTP,
// as described in
// https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-xlogin/
//
// This mechanism is used by Microsoft Exchange SMTP servers. It is considered
// obsolete, and should not be used when other mechanisms are available.
func NewLoginClient(username, password string) Client {
	return &loginClient{username, password}
}

// Authenticates users with an username and a password.
type LoginAuthenticator func(username, password string) error

type loginState int

const (
	loginNotStarted loginState = iota
	loginWaitingUsername
	loginWaitingPassword
)

type loginServer struct {
	state              loginState
	username, password string
	authenticate       LoginAuthenticator
}

// A server implementation of the LOGIN authentication mechanism, as described
// in https://tools.ietf.org/html/draft-murchison-sasl-login-00.
//
// LOGIN is obsolete and should only be enabled for legacy clients that cannot
// be updated to use PLAIN.
func NewLoginServer(authenticator LoginAuthenticator) Server {
	return &loginServer{authenticate: authenticator}
}

func (a *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch a.state {
	case loginNotStarted:
		// Check for initial response field, as per RFC4422 section 3
		if response == nil {
			challenge = []byte("Username:")
			break
		}
		a.state++
		fallthrough
	case loginWaitingUsername:
		a.username = string(response)
		challenge = []byte("Password:")
	case loginWaitingPassword:
		a.password = string(response)
		err = a.authenticate(a.username, a.password)
		done = true
	default:
		err = ErrUnexpectedClientResponse
	}

	a.state++
	return
}
