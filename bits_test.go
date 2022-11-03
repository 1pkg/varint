package varint

import (
	"fmt"
	"math/big"
	"testing"
)

func TestBitsNew(t *testing.T) {
	t.Run("Combined", func(t *testing.T) {
		table := map[string]struct {
			blen  int
			bytes []uint
			n     uint
			big   *big.Int
			s     string
			base  int
			bits  Bits
		}{
			"nil inputs should produce empty bits": {
				blen:  0,
				bytes: nil,
				n:     0,
				big:   nil,
				s:     "0",
				base:  3,
				bits:  Bits{0},
			},
			"empty inputs should produce empty bits": {
				blen:  0,
				bytes: []uint{},
				n:     0,
				big:   big.NewInt(0),
				s:     "0",
				base:  3,
				bits:  Bits{0},
			},
			"empty len inputs should produce empty bits": {
				blen:  0,
				bytes: []uint{100},
				n:     0,
				big:   new(big.Int),
				s:     "0",
				base:  4,
				bits:  Bits{0},
			},
			"non empty inputs should produce non empty bits": {
				blen:  7,
				bytes: []uint{100},
				n:     100,
				big:   big.NewInt(100),
				s:     "100",
				base:  10,
				bits:  Bits{7, 100},
			},
			"non empty long inputs should produce non empty bits": {
				blen:  86,
				bytes: []uint{0x1, 0x3B0000},
				n:     1,
				big:   big.NewInt(0).SetBits([]big.Word{0x1, 0x3B0000}),
				s:     "3B00000000000000000001",
				base:  16,
				bits:  Bits{86, 0x1, 0x3B0000},
			},
		}
		for tname, tcase := range table {
			t.Run(tname, func(t *testing.T) {
				tt := newtt(t)
				b := NewBits(tcase.blen, tcase.bytes)
				bn := NewBitsUint(tcase.n)
				bb := NewBitsBits(tcase.bits)
				bbig := NewBitsBigInt(tcase.big)
				brnd := NewBitsRand(tcase.blen, tt.Rand)
				bs := NewBitsString(tcase.s, tcase.base)
				tt.Equal(tcase.bits, b)
				tt.Equal(tcase.bits.Uint(), bn.Uint())
				tt.Equal(tcase.bits, bb)
				tt.Equal(tcase.bits, bbig)
				tt.Equal(tcase.bits.BitLen(), brnd.BitLen())
				tt.Equal(tcase.bits, bs)
			})
		}
	})
	t.Run("String", func(t *testing.T) {
		table := map[string]struct {
			s    string
			base int
			bits Bits
		}{
			"should produce nil bits for empty string": {
				s:    "",
				base: -1,
			},
			"should produce nil bits for unsupported characters": {
				s:    "ABC@EDF",
				base: 63,
			},
			"should produce nil bits for characters out of provided base": {
				s:    "ABC",
				base: 2,
			},
			"should produce expected bits for long valid string with _": {
				s:    "abc_def_ghi_jkl_mno_pqr_stu_vwx_yz0",
				base: 36,
				bits: NewBits(138, []uint{0x393FAFC0785F4B4C, 0x0FDE01C8C1446C9E, 0x372}),
			},
		}
		for tname, tcase := range table {
			t.Run(tname, func(t *testing.T) {
				tt := newtt(t)
				tt.Equal(tcase.bits, NewBitsString(tcase.s, tcase.base))
			})
		}
	})
}

func TestBits(t *testing.T) {
	table := map[string]struct {
		bits  Bits
		blen  int
		bytes []uint
		empty bool
		n     uint
		big   *big.Int
		s     string
		base  int
		bs    string
	}{
		"nil bits should return empty results": {
			bits:  nil,
			bytes: []uint{0},
			empty: true,
			n:     0,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
			base:  0,
			bs:    "0",
		},
		"implicit empty bits should return empty results": {
			bits:  []uint{0},
			bytes: []uint{0},
			empty: true,
			n:     0,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
			base:  100,
			bs:    "0",
		},
		"explicit empty bits should return empty results": {
			bits:  []uint{0, 0},
			bytes: []uint{0},
			empty: true,
			n:     0,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
			base:  -1,
			bs:    "0",
		},
		"explicit empty bits should return empty results, even if bytes not empty": {
			bits:  []uint{0, 10},
			bytes: []uint{0},
			empty: true,
			n:     0,
			big:   big.NewInt(0),
			s:     "[0]{0X0}",
			base:  0,
			bs:    "0",
		},
		"non empty single small word bits should return non empty results": {
			bits:  []uint{4, 0xF},
			blen:  4,
			bytes: []uint{0xF},
			empty: false,
			n:     0xF,
			big:   big.NewInt(0xF),
			s:     "[4]{0XF}",
			base:  32,
			bs:    "f",
		},
		"non empty single word bits should return non empty results": {
			bits:  []uint{24, 0xFF},
			blen:  24,
			bytes: []uint{0xFF},
			empty: false,
			n:     0xFF,
			big:   big.NewInt(0xFF),
			s:     "[24]{0XFF}",
			base:  32,
			bs:    "7v",
		},
		"non empty multi words bits should return non empty results": {
			bits:  []uint{128, 0xF, 0xAABBCCDD},
			blen:  128,
			bytes: []uint{0xF, 0xAABBCCDD},
			empty: false,
			n:     0xF,
			big:   big.NewInt(0).SetBits([]big.Word{0xF, 0xAABBCCDD}),
			s:     "[128]{0XAABBCCDD000000000000000F}",
			base:  16,
			bs:    "aabbccdd000000000000000f",
		},
	}
	for tname, tcase := range table {
		t.Run(tname, func(t *testing.T) {
			tt := newtt(t)
			tt.Equal(tcase.blen, tcase.bits.BitLen())
			tt.Equal(tcase.bytes, tcase.bits.Bytes())
			tt.Equal(tcase.empty, tcase.bits.Empty())
			tt.Equal(tcase.n, tcase.bits.Uint())
			tt.Equal(tcase.big, tcase.bits.BigInt())
			tt.Equal(tcase.s, tcase.bits.String())
			tt.Equal(tcase.bs, string(tcase.bits.Base(tcase.base)))
		})
	}
}

func FuzzBitsFmt(f *testing.F) {
	const base = 62
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
