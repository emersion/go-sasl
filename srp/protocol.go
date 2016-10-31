package srp

import (
	"io"
	"math/big"
	"strings"
)

type ClientIdentity struct {
	Username string
	Identity string
	SID string
	Nonce []byte
}

func (ci *ClientIdentity) ReadFrom(r io.Reader) error {
	var err error
	if ci.Username, err = readText(r); err != nil {
		return err
	}
	if ci.Identity, err = readText(r); err != nil {
		return err
	}
	if ci.SID, err = readText(r); err != nil {
		return err
	}
	if ci.Nonce, err = readOS(r); err != nil {
		return err
	}
	return nil
}

func (ci *ClientIdentity) WriteTo(w io.Writer) error {
	if err := writeText(w, ci.Username); err != nil {
		return err
	}
	if err := writeText(w, ci.Identity); err != nil {
		return err
	}
	if err := writeText(w, ci.SID); err != nil {
		return err
	}
	if err := writeOS(w, ci.Nonce); err != nil {
		return err
	}
	return nil
}

type ServerNonce struct {
	Nonce []byte
}

func (sn *ServerNonce) ReadFrom(r io.Reader) error {
	var err error
	sn.Nonce, err = readOS(r)
	return err
}

func (sn *ServerNonce) WriteTo(w io.Writer) error {
	return writeOS(w, sn.Nonce)
}

type ServerProtocolElements struct {
	Modulus *big.Int
	Generator *big.Int
	Salt []byte
	Ephemeral *big.Int
	Options []string
}

func (spe *ServerProtocolElements) ReadFrom(r io.Reader) error {
	var err error
	if spe.Modulus, err = readMPI(r); err != nil {
		return err
	}
	if spe.Generator, err = readMPI(r); err != nil {
		return err
	}
	if spe.Salt, err = readOS(r); err != nil {
		return err
	}
	if spe.Ephemeral, err = readMPI(r); err != nil {
		return err
	}
	if options, err := readText(r); err != nil {
		return err
	} else {
		spe.Options = strings.Split(options, ",")
	}
	return nil
}

func (spe *ServerProtocolElements) WriteTo(w io.Writer) error {
	if err := writeMPI(w, spe.Modulus); err != nil {
		return err
	}
	if err := writeMPI(w, spe.Generator); err != nil {
		return err
	}
	if err := writeOS(w, spe.Salt); err != nil {
		return err
	}
	if err := writeMPI(w, spe.Ephemeral); err != nil {
		return err
	}
	if err := writeText(w, strings.Join(spe.Options, ",")); err != nil {
		return err
	}
	return nil
}

func ReadServerReuse(r io.Reader) (bool, error) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return false, err
	}

	return buf[0] != 0, nil
}

func WriteServerReuse(w io.Writer, v bool) error {
	buf := make([]byte, 1)
	if v {
		buf[0] = 0xFF
	}
	_, err := w.Write(buf)
	return err
}

type ClientEvidence struct {
	Ephemeral *big.Int
	Evidence []byte
	Options []string
	IV []byte
}

func (ce *ClientEvidence) ReadFrom(r io.Reader) error {
	var err error
	if ce.Ephemeral, err = readMPI(r); err != nil {
		return err
	}
	if ce.Evidence, err = readOS(r); err != nil {
		return err
	}
	if options, err := readText(r); err != nil {
		return err
	} else {
		ce.Options = strings.Split(options, ",")
	}
	if ce.IV, err = readOS(r); err != nil {
		return err
	}
	return nil
}

func (ce *ClientEvidence) WriteTo(w io.Writer) error {
	if err := writeMPI(w, ce.Ephemeral); err != nil {
		return err
	}
	if err := writeOS(w, ce.Evidence); err != nil {
		return err
	}
	if err := writeText(w, strings.Join(ce.Options, ",")); err != nil {
		return err
	}
	if err := writeOS(w, ce.IV); err != nil {
		return err
	}
	return nil
}

type ServerEvidence struct {
	Evidence []byte
	IV []byte
	SID string
	TTL uint16
}

func (se *ServerEvidence) ReadFrom(r io.Reader) error {
	var err error
	if se.Evidence, err = readOS(r); err != nil {
		return err
	}
	if se.IV, err = readOS(r); err != nil {
		return err
	}
	if se.SID, err = readText(r); err != nil {
		return err
	}
	if se.TTL, err = readUint(r); err != nil {
		return err
	}
	return nil
}

func (se *ServerEvidence) WriteTo(w io.Writer) error {
	if err := writeOS(w, se.Evidence); err != nil {
		return err
	}
	if err := writeOS(w, se.IV); err != nil {
		return err
	}
	if err := writeText(w, se.SID); err != nil {
		return err
	}
	if err := writeUint(w, se.TTL); err != nil {
		return err
	}
	return nil
}
