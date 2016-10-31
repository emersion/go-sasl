package srp

import (
	"io"
	"encoding/binary"
	"math/big"
)

func readMPI(r io.Reader) (*big.Int, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(buf), nil
}

func writeMPI(w io.Writer, i *big.Int) error {
	buf := i.Bytes()
	if err := binary.Write(w, binary.BigEndian, uint16(len(buf))); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func readOS(r io.Reader) ([]byte, error) {
	var n uint8
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeOS(w io.Writer, buf []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint8(len(buf))); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func readEOS(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeEOS(w io.Writer, buf []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(buf))); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func readText(r io.Reader) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func writeText(w io.Writer, s string) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(s))); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

func readUint(r io.Reader) (uint16, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	return n, err
}

func writeUint(w io.Writer, i uint16) error {
	return binary.Write(w, binary.BigEndian, i)
}
