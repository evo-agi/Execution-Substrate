package knownkeys

// SmallOrderEncodings returns the values Check refuses as points of small
// order, for the tests of package knownkeys_test, which derive the same set
// from the curve.
func SmallOrderEncodings() [][]byte {
	out := make([][]byte, 0, len(smallOrder()))
	for k := range smallOrder() {
		out = append(out, []byte(k))
	}
	return out
}
