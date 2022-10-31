package varint

import (
	"math/big"
	"testing"
)

func FuzzBitsString(f *testing.F) {
	const base = 62
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits from b62 string,
		// then do the same for bigint and compare resulting bits.
		// After that get b62 string back from bits, initialize
		// another bits and compare them with original again.
		tt := newtt(t)
		b, ok := big.NewInt(0).SetString(b62, base)
		bits, err := NewBitsString(b62, base)
		// Skip if error is returned by any of bigint or bits.
		if tt.NoError(err, ErrorStringIsNotValidNumber{String: b62, Base: base}) || !ok {
			return
		}
		tt.Equal(bits, tt.NewBitsBigInt(b))
		b62b, err := bits.Base(base)
		tt.NoError(err)
		bitsb, err := NewBitsString(string(b62b), base)
		tt.NoError(err)
		tt.Equal(bits, bitsb)
	})
}
