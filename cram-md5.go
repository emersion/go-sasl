package sasl

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"
)

// The CRAM-MD5 mechanism name.
const CramMD5 = "CRAM-MD5"

type carmmd5Client struct {
	Username string
	Password string
}

func (a *carmmd5Client) Start() (mech string, ir []byte, err error) {
	mech = CramMD5
	return
}

// Adapted method of the net/smtp package
// https://golang.org/src/net/smtp/auth.go
func (a *carmmd5Client) Next(challenge []byte) (response []byte, err error) {
	d := hmac.New(md5.New, []byte(a.Password))
	d.Write(challenge)
	s := make([]byte, 0, d.Size())
	return []byte(fmt.Sprintf("%s %x", a.Username, d.Sum(s))), nil
}

// A client implementation of the CRAM-MD5 authentication mechanism, as described in RFC 2195.
// The returned Client uses the given username and password to authenticate
// to the server using the challenge-response mechanism.
func NewCramMD5Client(username, password string) Client {
	return &carmmd5Client{username, password}
}
