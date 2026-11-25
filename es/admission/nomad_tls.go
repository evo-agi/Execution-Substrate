package admission

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode"

	esconfig "execution-substrate/es/config"
)

// Nomad HTTPS contract for the current submit path.
//
// ES reaches Nomad's API only over TLS 1.3, at the loopback address that
// nomad.base_url names. It verifies Nomad's server certificate against the CA
// in nomad.root_ca_file for the name nomad.server_name, and then requires the
// certificate's public key to be the one that nomad.server_spki_sha256 pins:
// another certificate, even one the same CA signed, is refused. ES's token is
// sent only inside a connection that passed both checks.

// nomadRootCAFileMaxBytes bounds the PEM file ES reads at startup.
const nomadRootCAFileMaxBytes = 1 << 20

var errNomadServerKeyNotPinned = errors.New("nomad server certificate key does not match nomad.server_spki_sha256")

// newNomadTLSConfig builds the client TLS configuration for every Nomad
// connection from the validated config.
func newNomadTLSConfig(cfg esconfig.NomadConfig) (*tls.Config, error) {
	roots, err := loadNomadRootCAs(cfg.RootCAFile)
	if err != nil {
		return nil, err
	}
	pin, err := decodeNomadServerSPKIPin(cfg.ServerSPKISHA256)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
		RootCAs:    roots,
		// VerifyConnection runs after the chain and name are verified, so
		// VerifiedChains is set whenever the handshake got this far.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errNomadServerKeyNotPinned
			}
			if sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != pin {
				return errNomadServerKeyNotPinned
			}
			return nil
		},
	}, nil
}

// loadNomadRootCAs reads nomad.root_ca_file: a regular file of at most
// nomadRootCAFileMaxBytes holding one or more PEM CERTIFICATE blocks and
// nothing else but white space.
func loadNomadRootCAs(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("nomad root CA file could not be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("nomad root CA file must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, nomadRootCAFileMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nomad root CA file could not be read")
	}
	if len(data) > nomadRootCAFileMaxBytes {
		return nil, fmt.Errorf("nomad root CA file is larger than %d bytes", nomadRootCAFileMaxBytes)
	}
	pool := x509.NewCertPool()
	count := 0
	rest := bytes.TrimLeftFunc(data, unicode.IsSpace)
	for len(rest) != 0 {
		// pem.Decode skips any text before a block, and any block it cannot
		// decode, to return a later one. So each block has to start where
		// the white space ends, and the call may consume only that block.
		if !bytes.HasPrefix(rest, nomadPEMCertificateBegin) {
			return nil, errNomadRootCAFileNotOnlyCertificates
		}
		block, after := pem.Decode(rest)
		if block == nil || bytes.Count(rest[:len(rest)-len(after)], nomadPEMBegin) != 1 {
			return nil, errNomadRootCAFileNotOnlyCertificates
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errNomadRootCAFileNotOnlyCertificates
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("nomad root CA file contains a certificate that does not parse")
		}
		pool.AddCert(certificate)
		count++
		rest = bytes.TrimLeftFunc(after, unicode.IsSpace)
	}
	if count == 0 {
		return nil, errNomadRootCAFileNotOnlyCertificates
	}
	return pool, nil
}

var (
	nomadPEMBegin            = []byte("-----BEGIN")
	nomadPEMCertificateBegin = []byte("-----BEGIN CERTIFICATE-----")

	errNomadRootCAFileNotOnlyCertificates = errors.New("nomad root CA file must contain only PEM CERTIFICATE blocks")
)

func decodeNomadServerSPKIPin(value string) ([32]byte, error) {
	var pin [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(pin) || hex.EncodeToString(decoded) != value {
		return pin, fmt.Errorf("nomad.server_spki_sha256 must be 64 lowercase hex characters")
	}
	copy(pin[:], decoded)
	return pin, nil
}
