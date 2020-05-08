package sasl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The OAUTHBEARER mechanism name.
const OAuthBearer = "OAUTHBEARER"

type OAuthBearerError struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

type OAuthBearerOptions struct {
	Username string
	Token    string
	Host     string
	Port     int
}

// Implements error
func (err *OAuthBearerError) Error() string {
	return fmt.Sprintf("OAUTHBEARER authentication error (%v)", err.Status)
}

type oauthBearerClient struct {
	OAuthBearerOptions
}

func (a *oauthBearerClient) Start() (mech string, ir []byte, err error) {
	mech = OAuthBearer
	var str = "n,a=" + a.Username + ","

	if a.Host != "" {
		str += "\x01host=" + a.Host
	}

	if a.Port != 0 {
		str += "\x01port=" + strconv.Itoa(a.Port)
	}
	str += "\x01auth=Bearer " + a.Token + "\x01\x01"
	ir = []byte(str)
	return
}

func (a *oauthBearerClient) Next(challenge []byte) ([]byte, error) {
	authBearerErr := &OAuthBearerError{}
	if err := json.Unmarshal(challenge, authBearerErr); err != nil {
		return nil, err
	} else {
		return nil, authBearerErr
	}
}

// An implementation of the OAUTHBEARER authentication mechanism, as
// described in RFC 7628.
func NewOAuthBearerClient(opt *OAuthBearerOptions) Client {
	return &oauthBearerClient{*opt}
}

type OAuthBearerAuthenticator func(opts OAuthBearerOptions) *OAuthBearerError

type oauthBearerServer struct {
	done         bool
	fail         error
	authenticate OAuthBearerAuthenticator
}

func (a *oauthBearerServer) Next(response []byte) (challenge []byte, done bool, err error) {
	// Per RFC, we cannot just send an error, we need to return JSON-structured
	// value as a challenge and then after getting dummy response from the
	// client stop the exchange.
	if a.fail != nil {
		if len(response) != 1 && response[0] != 0x01 {
			return nil, true, errors.New("unexpected response")
		}
		return nil, true, a.fail
	}
	fail := func(descr string) ([]byte, bool, error) {
		blob, err := json.Marshal(OAuthBearerError{
			Status:  "invalid_request",
			Schemes: "bearer",
		})
		if err != nil {
			panic(err) // wtf
		}
		a.fail = errors.New(descr)
		return blob, false, nil
	}

	if a.done {
		err = ErrUnexpectedClientResponse
		return
	}
	if response == nil {
		return []byte{}, false, nil
	}

	a.done = true

	// Cut n,a=username,\x01host=...\x01auth=...
	// into
	//   n
	//   a=username
	//   \x01host=...\x01auth=...\x01\x01
	parts := bytes.SplitN(response, []byte{','}, 3)
	if len(parts) != 3 {
		return fail("Invalid response")
	}
	if !bytes.Equal(parts[0], []byte{'n'}) {
		return fail("Invalid response, missing 'n'")
	}
	opts := OAuthBearerOptions{}
	if !bytes.HasPrefix(parts[1], []byte("a=")) {
		return fail("Invalid response, missing 'a'")
	}
	opts.Username = string(bytes.TrimPrefix(parts[1], []byte("a=")))

	// Cut \x01host=...\x01auth=...\x01\x01
	// into
	//   *empty*
	//   host=...
	//   auth=...
	//   *empty*
	//
	// Note that this code does not do a lot of checks to make sure the input
	// follows the exact format specified by RFC.
	params := bytes.Split(parts[2], []byte{0x01})
	for _, p := range params {
		// Skip empty fields (one at start and end).
		if len(p) == 0 {
			continue
		}

		pParts := bytes.SplitN(p, []byte{'='}, 2)
		if len(pParts) != 2 {
			return fail("Invalid response, missing '='")
		}

		switch string(pParts[0]) {
		case "host":
			opts.Host = string(pParts[1])
		case "port":
			port, err := strconv.ParseUint(string(pParts[1]), 10, 16)
			if err != nil {
				return fail("Invalid response, malformed 'port' value")
			}
			opts.Port = int(port)
		case "auth":
			const prefix = "bearer "
			strValue := string(pParts[1])

			if !strings.HasPrefix(strings.ToLower(strValue), prefix) {
				return fail("Unsupported token type")
			}
			opts.Token = strValue[len(prefix):]
		default:
			return fail("Invalid response, unknown parameter: " + string(pParts[0]))
		}
	}

	authzErr := a.authenticate(opts)
	if authzErr != nil {
		blob, err := json.Marshal(authzErr)
		if err != nil {
			panic(err) // wtf
		}
		a.fail = authzErr
		return blob, false, nil
	}

	return nil, true, nil
}

func NewOAuthBearerServer(auth OAuthBearerAuthenticator) Server {
	return &oauthBearerServer{authenticate: auth}
}
