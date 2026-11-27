// Command signingkeygen generates a fresh Ed25519 signing key for AGS or EGS
// and writes it as the "signer" object their configurations take.
//
// Usage: signingkeygen <ags|egs> <absolute path of a new file>
//
// It creates the file with mode 0600 and refuses to replace or follow
// anything already at that path. The file holds one JSON object:
//
//	{"algorithm":"ed25519","key_id":"<role>-<16 hex>","private_key_hex":"<64 hex>","public_key_hex":"<64 hex>"}
//
// The key comes from crypto/rand, the source Go's own Ed25519 key generation
// uses. The key ID is the role followed by the first 16 hex digits of the
// SHA-256 of the public key, so each host's key has its own ID and a new key
// gets a new ID. The key ID is a name, not a secret: ES verifies the key
// itself. On stdout it prints only the public part, as one JSON object with
// algorithm, key_id and public_key_hex, which callers use for ES
// verification, the EGS signer allow list and workload grants. The private
// key never reaches stdout, stderr, argv or the environment.
//
// The rule that each host has its own key is in
// .docs/system_overview/configuration.md, "Signing keys"; the keys AGS, EGS
// and ES refuse are in .docs/system_overview/contracts.md, section 3B.
//
// Exit status: 0 written, 1 refused or failed (the reason is on stderr), 2
// usage.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"execution-substrate/internal/knownkeys"
)

type signer struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PrivateKeyHex string `json:"private_key_hex,omitempty"`
	PublicKeyHex  string `json:"public_key_hex"`
}

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "ags" && os.Args[1] != "egs") || !filepath.IsAbs(os.Args[2]) {
		fmt.Fprintln(os.Stderr, "usage: signingkeygen <ags|egs> <absolute path of a new file>")
		os.Exit(2)
	}
	public, err := generate(os.Args[1], os.Args[2], rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signingkeygen: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(public); err != nil {
		fmt.Fprintf(os.Stderr, "signingkeygen: write the public part: %v\n", err)
		os.Exit(1)
	}
}

// KeyID is the key ID of public for role.
func KeyID(role string, public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return role + "-" + hex.EncodeToString(sum[:8])
}

// generate writes a new key for role to path and returns its public part.
func generate(role, path string, random io.Reader) (signer, error) {
	public, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return signer{}, fmt.Errorf("generate an Ed25519 key: %w", err)
	}
	// A random seed is a known key with probability 2^-248; the check keeps
	// a broken random source from writing one.
	if err := knownkeys.Check("the generated key", public); err != nil {
		return signer{}, err
	}
	full := signer{
		Algorithm:     "ed25519",
		KeyID:         KeyID(role, public),
		PrivateKeyHex: hex.EncodeToString(private.Seed()),
		PublicKeyHex:  hex.EncodeToString(public),
	}
	data, err := json.Marshal(full)
	if err != nil {
		return signer{}, err
	}
	data = append(data, '\n')
	// O_EXCL with O_CREAT refuses any existing entry, a symbolic link
	// included; O_NOFOLLOW also refuses a link as the last component.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return signer{}, fmt.Errorf("create %s: %w", path, err)
	}
	// The process umask can only clear bits, so 0600 stands; Chmod makes
	// the mode exact whatever the umask.
	if err := file.Chmod(0o600); err != nil {
		return signer{}, errors.Join(fmt.Errorf("set the mode of %s: %w", path, err), file.Close(), os.Remove(path))
	}
	if _, err := file.Write(data); err != nil {
		return signer{}, errors.Join(fmt.Errorf("write %s: %w", path, err), file.Close(), os.Remove(path))
	}
	if err := file.Sync(); err != nil {
		return signer{}, errors.Join(fmt.Errorf("sync %s: %w", path, err), file.Close(), os.Remove(path))
	}
	if err := file.Close(); err != nil {
		return signer{}, errors.Join(fmt.Errorf("close %s: %w", path, err), os.Remove(path))
	}
	full.PrivateKeyHex = ""
	return full, nil
}
