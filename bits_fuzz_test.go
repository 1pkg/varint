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
		bits := NewBitsString(b62, base)
		// Skip on empty bits or bigint error.
		if bits.Empty() || !ok {
			return
		}
		tt.Equal(bits, NewBitsBigInt(b))
		tt.Equal(fmt.Sprintf("%d", bits), fmt.Sprintf("%d", b))
		tt.Equal(fmt.Sprintf("%#X", bits), fmt.Sprintf("%#X", b))
		tt.Equal(fmt.Sprintf("%0b", bits), fmt.Sprintf("%0b", b))
		tt.Equal(fmt.Sprintf("%#b", bits), fmt.Sprintf("%#b", b))
		tt.Equal(fmt.Sprintf("%#o", bits), fmt.Sprintf("%#o", b))
		tt.Equal(fmt.Sprintf("%#x", bits), fmt.Sprintf("%#x", b))
		tt.Equal(fmt.Sprintf("%100O", bits), fmt.Sprintf("%100O", b))
		tt.Equal(fmt.Sprintf("%010x", bits), fmt.Sprintf("%010x", b))
		tt.Equal(bits.String(), fmt.Sprintf("[%d]{%#X}", b.BitLen(), b))
		bitsb := NewBitsString(string(bits.Base(base)), base)
		tt.Equal(bits, bitsb)
	})
}
