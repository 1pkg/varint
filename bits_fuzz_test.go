package varint

import (
	"fmt"
	"math/big"
	"testing"
)

func FuzzBitsString(f *testing.F) {
	const base = maxbase
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits from b62 string,
		// then do the same for bigint and compare resulting bits.
		// Then compare their string formats as well.
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
		tt.Equal(fmt.Sprintf("%d", bits), fmt.Sprintf("%d", b))
		tt.Equal(fmt.Sprintf("%X", bits), fmt.Sprintf("%X", b))
		tt.Equal(fmt.Sprintf("%0b", bits), fmt.Sprintf("%0b", b))
		tt.Equal(fmt.Sprintf("%100O", bits), fmt.Sprintf("%100O", b))
		tt.Equal(bits.String(), fmt.Sprintf("[%d]{%X}", b.BitLen(), b))
		b62b, err := bits.Base(base)
		tt.NoError(err)
		bitsb, err := NewBitsString(string(b62b), base)
		tt.NoError(err)
		tt.Equal(bits, bitsb)
	})
}
