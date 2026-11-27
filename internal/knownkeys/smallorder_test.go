package knownkeys_test

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"execution-substrate/internal/knownkeys"
	"execution-substrate/internal/testutil"
)

// The curve edwards25519: -x^2 + y^2 = 1 + d*x^2*y^2 over the field of p
// elements, whose points of small order form a group of 8 (red-team RT75-1
// of ES PR #75).
var (
	fieldP     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	groupOrder = mustBig("7237005577332262213973186563042994240857116359379907606001950938285454250989")
	curveD     = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()
)

func mustBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return n
}

func fieldMod(n *big.Int) *big.Int { return n.Mod(n, fieldP) }

// fieldSqrt returns a square root of a mod p, or nil when a is not a square.
// p = 5 mod 8, so a^((p+3)/8) is a root of a or of -a, and in the second case
// multiplying by a root of -1 gives a root of a.
func fieldSqrt(a *big.Int) *big.Int {
	a = fieldMod(new(big.Int).Set(a))
	exp := new(big.Int).Add(fieldP, big.NewInt(3))
	exp.Rsh(exp, 3)
	r := new(big.Int).Exp(a, exp, fieldP)
	if fieldMod(new(big.Int).Mul(r, r)).Cmp(a) == 0 {
		return r
	}
	sqrtM1 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 2), fieldP)
	r = fieldMod(r.Mul(r, sqrtM1))
	if fieldMod(new(big.Int).Mul(r, r)).Cmp(a) == 0 {
		return r
	}
	return nil
}

// smallOrderPoints derives the eight points of small order from the curve
// equation: the identity (0, 1); (0, -1), of order 2; the two points with
// y = 0, of order 4; and the four points whose double has y = 0, of order 8.
// Doubling gives y(2P) = (x^2 + y^2) / (2 + x^2 - y^2), which is 0 when
// x^2 = -y^2, and with the curve equation that is d*y^4 + 2*y^2 - 1 = 0, so
// y^2 = (-1 +- sqrt(1 + d)) / d.
func smallOrderPoints(t *testing.T) [][2]*big.Int {
	t.Helper()
	var ys []*big.Int
	ys = append(ys, big.NewInt(1), new(big.Int).Sub(fieldP, big.NewInt(1)), big.NewInt(0))
	root := fieldSqrt(new(big.Int).Add(big.NewInt(1), curveD))
	if root == nil {
		t.Fatal("1 + d is not a square")
	}
	dInv := new(big.Int).ModInverse(curveD, fieldP)
	for _, sign := range []int64{1, -1} {
		y2 := new(big.Int).Mul(big.NewInt(sign), root)
		y2.Sub(y2, big.NewInt(1))
		y2 = fieldMod(y2.Mul(y2, dInv))
		y := fieldSqrt(y2)
		if y == nil {
			continue
		}
		ys = append(ys, y, fieldMod(new(big.Int).Neg(y)))
	}
	var points [][2]*big.Int
	for _, y := range ys {
		// x^2 = (y^2 - 1) / (d*y^2 + 1)
		y2 := fieldMod(new(big.Int).Mul(y, y))
		num := fieldMod(new(big.Int).Sub(y2, big.NewInt(1)))
		den := fieldMod(new(big.Int).Add(new(big.Int).Mul(curveD, y2), big.NewInt(1)))
		x := fieldSqrt(new(big.Int).Mul(num, new(big.Int).ModInverse(den, fieldP)))
		if x == nil {
			t.Fatalf("y = %v has no point", y)
		}
		points = append(points, [2]*big.Int{x, y})
		if x.Sign() != 0 {
			points = append(points, [2]*big.Int{fieldMod(new(big.Int).Neg(x)), y})
		}
	}
	if len(points) != 8 {
		t.Fatalf("derived %d points of small order, want the 8 of the group", len(points))
	}
	return points
}

// everyEncoding returns every 32-byte value whose y part names the y of one of
// points, as y or as y + p where that fits in 255 bits, with either sign bit.
// Any value crypto/ed25519 decodes to one of the points is among them.
func everyEncoding(points [][2]*big.Int) map[string]bool {
	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	out := map[string]bool{}
	for _, point := range points {
		for _, y := range []*big.Int{point[1], new(big.Int).Add(point[1], fieldP)} {
			if y.Cmp(limit) >= 0 {
				continue
			}
			for _, signBit := range []byte{0, 0x80} {
				be := y.FillBytes(make([]byte, 32))
				le := make([]byte, 32)
				for i := range be {
					le[i] = be[31-i]
				}
				le[31] |= signBit
				out[string(le)] = true
			}
		}
	}
	return out
}

func littleEndianInt(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// signWithoutAKey returns a signature of message under public that holds no
// private key for public: R is the public key of a throwaway seed and S that
// seed's scalar, so [S]B = R, and ed25519.Verify, which checks
// [S]B - [k]A = R, accepts it when [k]A is the identity. For a point of order
// dividing 8 that is when the challenge k is a multiple of 8.
func signWithoutAKey(public, message []byte) []byte {
	for try := uint64(1); try < 4096; try++ {
		seed := make([]byte, ed25519.SeedSize)
		binary.LittleEndian.PutUint64(seed, try)
		R := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		h := sha512.Sum512(seed)
		a := h[:32]
		a[0] &= 248
		a[31] &= 127
		a[31] |= 64
		challenge := sha512.New()
		challenge.Write(R)
		challenge.Write(public)
		challenge.Write(message)
		k := new(big.Int).Mod(littleEndianInt(challenge.Sum(nil)), groupOrder)
		if new(big.Int).Mod(k, big.NewInt(8)).Sign() != 0 {
			continue
		}
		s := new(big.Int).Mod(littleEndianInt(a), groupOrder).FillBytes(make([]byte, 32))
		signature := make([]byte, ed25519.SignatureSize)
		copy(signature, R)
		for i := range s {
			signature[32+i] = s[31-i]
		}
		return signature
	}
	return nil
}

// TestCheckRefusesExactlyThePublicKeysAnyoneCanSignFor derives the points of
// small order from the curve, tries a signature made without any private key
// under every encoding of them, and requires the encodings that
// ed25519.Verify accepts it under to be exactly the ones Check refuses as
// points of small order. 32 zero bytes is one of them.
func TestCheckRefusesExactlyThePublicKeysAnyoneCanSignFor(t *testing.T) {
	message := []byte("evidence or a trust policy that nobody signed")
	forgeable := map[string]bool{}
	for encoding := range everyEncoding(smallOrderPoints(t)) {
		if signature := signWithoutAKey([]byte(encoding), message); signature != nil && ed25519.Verify([]byte(encoding), message, signature) {
			forgeable[encoding] = true
		}
	}
	listed := map[string]bool{}
	for _, encoding := range knownkeys.SmallOrderEncodings() {
		listed[string(encoding)] = true
	}
	names := func(set map[string]bool, without map[string]bool) []string {
		var out []string
		for k := range set {
			if !without[k] {
				out = append(out, hex.EncodeToString([]byte(k)))
			}
		}
		sort.Strings(out)
		return out
	}
	if missing := names(forgeable, listed); len(missing) > 0 {
		t.Errorf("anyone can sign for these public keys, and Check does not list them: %v", missing)
	}
	if extra := names(listed, forgeable); len(extra) > 0 {
		t.Errorf("Check lists these as points of small order, but no signature without a key verifies under them: %v", extra)
	}
	if !forgeable[string(make([]byte, 32))] {
		t.Error("32 zero bytes is not among the keys anyone can sign for")
	}
	for encoding := range forgeable {
		err := knownkeys.Check("verification.provenance.public_key_hex", []byte(encoding))
		if err == nil || !strings.Contains(err.Error(), "verification.provenance.public_key_hex is a key anyone can sign for") {
			t.Errorf("Check(%x) = %v, want the small-order refusal", encoding, err)
		}
	}
	// The forgery needs a point of small order: under a generated key the same
	// loop makes nothing ed25519.Verify accepts.
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if signature := signWithoutAKey(public, message); signature != nil && ed25519.Verify(public, message, signature) {
		t.Fatal("a signature without the key verified under a generated key")
	}
}

// TestServicesRefuseAPublicKeyAnyoneCanSignFor puts each point of small order
// into each public key field of an example that otherwise has fresh keys, and
// requires the service to refuse that field at load.
func TestServicesRefuseAPublicKeyAnyoneCanSignFor(t *testing.T) {
	load := map[string]func(string) error{}
	for _, example := range exampleLoaders {
		load[example.name] = example.load
	}
	fields := []struct {
		example string
		path    []string
	}{
		{"ags.json", []string{"signer", "public_key_hex"}},
		{"egs.json", []string{"signer", "public_key_hex"}},
		{"es.json", []string{"verification", "trust_model", "public_key_hex"}},
		{"es.json", []string{"verification", "provenance", "public_key_hex"}},
		{"es.json", []string{"verification", "derivation_attestation", "public_key_hex"}},
		{"es.json", []string{"verification", "workload_identity_binding", "public_key_hex"}},
	}
	for _, encoding := range knownkeys.SmallOrderEncodings() {
		value := hex.EncodeToString(encoding)
		for _, f := range fields {
			field := strings.Join(f.path, ".")
			t.Run(f.example+"/"+field+"/"+value[:8]+value[56:], func(t *testing.T) {
				var doc map[string]any
				if err := json.Unmarshal([]byte(testutil.Read(t, filepath.Join(".examples", "config", f.example))), &doc); err != nil {
					t.Fatal(err)
				}
				testutil.WithFreshSigningKeys(t, doc)
				node := doc
				for _, key := range f.path[:len(f.path)-1] {
					node = node[key].(map[string]any)
				}
				node[f.path[len(f.path)-1]] = value
				data, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), f.example)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := load[f.example](path); err == nil || !strings.Contains(err.Error(), field+" is a key anyone can sign for") {
					t.Fatalf("got %v, want the small-order refusal for %s", err, field)
				}
			})
		}
	}
}
