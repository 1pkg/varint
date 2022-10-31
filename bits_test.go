package varint

import (
	"math/big"
	"testing"
)

func TestBitsI(t *testing.T) {
	table := map[string]struct {
		b     Bits
		blen  int
		bytes []uint
		empty bool
		ui    uint
		big   *big.Int
		s     string
	}{
		"nil bits should return empty results": {
			empty: true,
			bytes: []uint{0},
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
		},
		"implicit empty bits should return empty results": {
			b:     []uint{0},
			bytes: []uint{0},
			empty: true,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
		},
		"explicit empty bits should return empty results": {
			b:     []uint{0, 0},
			bytes: []uint{0},
			empty: true,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
		},
		"explicit empty bits should return empty results, even if bytes not empty": {
			b:     []uint{0, 10},
			bytes: []uint{0},
			empty: true,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
		},
		"non empty single word bits should return non empty results": {
			b:     []uint{24, 0xFF},
			blen:  24,
			bytes: []uint{0xFF},
			empty: false,
			ui:    0xFF,
			big:   big.NewInt(0xFF),
			s:     "[24]{0XFF}",
		},
		"non empty multi words bits should return non empty results": {
			b:     []uint{128, 0xF, 0xAABBCCDD},
			blen:  128,
			bytes: []uint{0xF, 0xAABBCCDD},
			empty: false,
			ui:    0xF,
			big:   big.NewInt(0).SetBits([]big.Word{0xF, 0xAABBCCDD}),
			s:     "[128]{0XAABBCCDD000000000000000F}",
		},
	}
	for tname, tcase := range table {
		t.Run(tname, func(t *testing.T) {
			tt := newtt(t)
			bits := tcase.b
			tt.Equal(tcase.blen, bits.BitLen())
			tt.Equal(tcase.bytes, bits.Bytes())
			tt.Equal(tcase.empty, bits.Empty())
			tt.Equal(tcase.ui, bits.Uint())
			tt.Equal(tcase.big, bits.BigInt())
			tt.Equal(tcase.s, bits.String())
		})
	}
}
