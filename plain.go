package sasl

import (
	"bytes"
	"errors"
)

type plainClient struct {
	Username string
	Password string
	Identity string
}

func (a *plainClient) Start() (mech string, ir []byte, err error) {
	mech = "PLAIN"
	ir = []byte(a.Identity + "\x00" + a.Username + "\x00" + a.Password)
	return
}

func (a *plainClient) Next(challenge []byte) (response []byte, err error) {
	return nil, errors.New("Unexpected server challenge")
}

// An implementation of the PLAIN authentication mechanism, as described in
// RFC 4616. Authorization identity may be left blank to indicate that it is the
// same as the username.
func NewPlainClient(username, password, identity string) Client {
	return &plainClient{username, password, identity}
}

// Authenticates users with a username and a password.
type PlainAuthenticator func(username, password string) error

type plainServer struct {
	done bool
	authenticate PlainAuthenticator
}

func (a *plainServer) Start() (ir []byte, err error) {
	ir = []byte{}
	return
}

func (a *plainServer) Next(challenge []byte) (response []byte, err error) {
	if a.done {
		err = errors.New("Unexpected client challenge")
		return
	}
	a.done = true

	parts := bytes.Split(challenge, []byte("\x00"))
	if len(parts) != 3 {
		err = errors.New("Invalid challenge")
		return
	}

	// TODO: support identity
	identity := string(parts[0])
	if identity != "" {
		err = errors.New("SASL identity is not supported")
		return
	}

	username := string(parts[1])
	password := string(parts[2])

	err = a.authenticate(username, password)
	return
}

func NewPlainServer(authenticator PlainAuthenticator) Server {
	return &plainServer{authenticate: authenticator}
}
