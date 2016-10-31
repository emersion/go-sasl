package srp

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"strings"
)

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

type Client struct {
	Username string
	Identity string
	SID string
	Nonce []byte
	Password string
}

func NewClient(username, password string) *Client {
	return &Client{
		Username: username,
		Password: password,
	}
}

func (c *Client) Start() (mech string, ir []byte, err error) {
	mech = "SRP"

	ci := &ClientIdentity{
		Username: c.Username,
		Identity: c.Identity,
		SID: c.SID,
		Nonce: c.Nonce,
	}

	var b bytes.Buffer
	ci.WriteTo(&b)
	ir = b.Bytes()

	return
}

func (c *Client) Next(challenge []byte) (response []byte, err error) {
	// ErrUnexpectedServerChallenge
	r := bytes.NewReader(challenge)

	var reused bool
	if reused, err = ReadServerReuse(r); err != nil {
		return
	} else if reused {
		ch := &ServerNonce{}
		if err = ch.ReadFrom(r); err != nil {
			return
		}
		c.Nonce = ch.Nonce
		return
	} else {
		// See https://tools.ietf.org/html/draft-burdis-cat-srp-sasl-08#section-4.4
		ch := &ServerProtocolElements{}
		if err = ch.ReadFrom(r); err != nil {
			return
		}

		// TODO: choose hash
		var hash func([]byte) []byte

		// TODO: implement these
		var xor func(_, _ []byte) []byte
		var itoa func(*big.Int) []byte
		var atoi func([]byte) *big.Int

		var clientSecret *big.Int
		modulusMinusOne := big.NewInt(0).Sub(ch.Modulus, big.NewInt(1))
		if clientSecret, err = rand.Int(rand.Reader, modulusMinusOne); err != nil {
			return
		}

		clientEphemeral := big.NewInt(0).Exp(ch.Generator, clientSecret, ch.Modulus)

		x := atoi(hash(concat(ch.Salt, hash([]byte(c.Username + ":" + c.Password)))))
		u := atoi(hash(concat(itoa(clientEphemeral), itoa(ch.Ephemeral))))
		S := big.NewInt(0).Exp(
			big.NewInt(0).Sub(
				ch.Ephemeral,
				big.NewInt(0).Mul(
					big.NewInt(3),
					big.NewInt(0).Exp(ch.Generator, x, nil),
				),
			),
			big.NewInt(0).Add(
				clientSecret,
				big.NewInt(0).Mul(u, x),
			),
			ch.Modulus,
		)
		K := hash(itoa(S))

		M1 := hash(concat(
			xor(hash(itoa(ch.Modulus)), hash(itoa(ch.Generator))),
			hash([]byte(c.Username)),
			ch.Salt,
			itoa(clientEphemeral),
			itoa(ch.Ephemeral),
			K,
			hash([]byte(c.Identity)),
			hash([]byte(strings.Join(ch.Options, ","))),
		))

		ce := &ClientEvidence{
			Ephemeral: clientEphemeral,
			Evidence: M1,
			Options: nil,
		}

		var b bytes.Buffer
		ce.WriteTo(&b)
		response = b.Bytes()
	}

	return
}
