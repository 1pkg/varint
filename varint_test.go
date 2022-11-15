package varint

import (
	"math/big"
	"testing"
)

func TestVarIntNew(t *testing.T) {
	table := map[string]struct {
		blen int
		len  int
		err  error
		vint VarInt
	}{
		"zero bits len should resolve in expected error": {
			blen: 0,
			len:  10,
			err:  ErrorBitLengthIsNotPositive,
		},
		"negative len should resolve in expected error": {
			blen: 10,
			len:  -1,
			err:  ErrorLengthIsNotPositive,
		},
		"positive bits len and len resolve in valid vint": {
			blen: 120,
			len:  5,
			vint: VarInt{5, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 0, 0},
		},
		"large bits len should resolve in valid vint but warning": {
			blen: 5000,
			len:  1,
			err:  ErrorBitLengthIsNotEfficient,
			vint: VarInt{1, 5000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		"small len should resolve in valid vint but warning": {
			blen: 10,
			len:  3,
			err:  ErrorLengthIsNotEfficient,
			vint: VarInt{3, 10, 0, 10, 0},
		},
	}
	for tname, tcase := range table {
		test(tname, t, func(h h) {
			vint, err := NewVarInt(tcase.blen, tcase.len)
			h.NoError(tcase.err, err)
			h.Equal(tcase.vint, vint)
		})
	}
}

func TestVarIntOperations(t *testing.T) {
	const len = 10
	test("Common", t, func(th h) {
		table := map[string]struct {
			vint VarInt
			i    int
			bits Bits
			err  error
		}{
			"common operations should return invalid varint error": {
				vint: nil,
				i:    1,
				bits: NewBits(len, nil),
				err:  ErrorVarIntIsInvalid,
			},
			"common operations should return negative index error": {
				vint: th.NewVarInt(len, len),
				i:    -1,
				bits: NewBits(len, nil),
				err:  ErrorIndexIsNegative,
			},
			"common operations should return index is out of range error": {
				vint: th.NewVarInt(len, len),
				i:    2 * len,
				bits: NewBits(len, nil),
				err:  ErrorIndexIsOutOfRange,
			},
			"common operations should return bit len cardinarity error": {
				vint: th.NewVarInt(len, len),
				i:    1,
				bits: NewBits(2*len, nil),
				err:  ErrorUnequalBitLengthCardinality,
			},
			"common operations should return a valid result for empty bits on valid index": {
				vint: th.NewVarInt(len, len),
				i:    1,
				bits: NewBits(len, []uint{1}),
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				h.VarInt = tcase.vint
				if h.VarInt != nil {
					h.VarIntSet(1, NewBits(len, []uint{len}))
				}
				h.Equal(h.VarInt.Get(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Set(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.GetSet(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Add(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Sub(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Mul(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Div(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Mod(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.And(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Or(tcase.i, tcase.bits), tcase.err)
				h.Equal(h.VarInt.Xor(tcase.i, tcase.bits), tcase.err)
				if tcase.err != ErrorUnequalBitLengthCardinality {
					h.Equal(h.VarInt.Not(tcase.i), tcase.err)
				}
			})
		}
	})
	test("Shifts", t, func(th h) {
		table := map[string]struct {
			vint VarInt
			i    int
			n    int
			err  error
		}{
			"shift operations should return invalid varint error": {
				vint: nil,
				i:    1,
				n:    1,
				err:  ErrorVarIntIsInvalid,
			},
			"shift operations should return negative shift error": {
				vint: th.NewVarInt(len, len),
				i:    1,
				n:    -1,
				err:  ErrorShiftIsNegative,
			},
			"shift operations should return negative index error": {
				vint: th.NewVarInt(len, len),
				i:    -1,
				n:    1,
				err:  ErrorIndexIsNegative,
			},
			"shift operations should return index is out of range error": {
				vint: th.NewVarInt(len, len),
				i:    2 * len,
				n:    1,
				err:  ErrorIndexIsOutOfRange,
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				h.VarInt = tcase.vint
				if h.VarInt != nil {
					h.VarIntSet(1, NewBits(len, []uint{len}))
				}
				h.Equal(h.VarInt.Rsh(tcase.i, tcase.n), tcase.err)
				h.Equal(h.VarInt.Lsh(tcase.i, tcase.n), tcase.err)
			})
		}
	})
	test("Arithmetic", t, func(th h) {
		vint := th.NewVarInt(len, len)
		table := map[string]struct {
			op   func(i int, bits Bits) error
			bits Bits
			err  error
		}{
			"addition should return overflow error on bits overflow": {
				op:   vint.Add,
				bits: NewBits(len, []uint{1020}),
				err:  ErrorAdditionOverflow,
			},
			"subtraction should return underflow error on bits underflow": {
				op:   vint.Sub,
				bits: NewBits(len, []uint{16}),
				err:  ErrorSubtractionUnderflow,
			},
			"multiplication should return overflow error on bits overflow": {
				op:   vint.Mul,
				bits: NewBits(len, []uint{299}),
				err:  ErrorMultiplicationOverflow,
			},
			"division should return zero division error on division by zero": {
				op:   vint.Div,
				bits: NewBits(len, nil),
				err:  ErrorDivisionByZero,
			},
			"modulo should return zero division error on division by zero": {
				op:   vint.Mod,
				bits: NewBits(len, nil),
				err:  ErrorDivisionByZero,
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				h.VarInt = vint
				h.VarIntSet(1, NewBits(len, []uint{len}))
				h.Equal(tcase.op(1, tcase.bits), tcase.err)
			})
		}
	})
}

func FuzzVarIntSetAndGet(f *testing.F) {
	const l = 10
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz original bits then randomly set
		// some vint numbers to fuzz original bits. Finally,
		// verify that all numbers in vint are either equal to
		// fuzz original bits or equal to zero.
		bits := h.NewBitsB62(b62)
		_ = h.NewVarInt(bits.BitLen(), l)
		for i := 0; i < l; i++ {
			n := rnd.Int() % l
			h.VarIntSet(n, bits)
			b := h.VarIntGet(n)
			h.Equal(bits, b)
		}
		for i := 0; i < l; i++ {
			// Check for zero or equal.
			if !h.VarIntGet(i).Empty() {
				h.VarIntEqual(i, bits)
			}
		}
	})
}

func FuzzVarIntGetSet(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Swap them
		// two times so result should be the same.
		b1, b2 := h.NewBits2B62(b62)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(1, b1)
		h.VarIntSet(2, b1)
		h.VarIntSet(0, b1)
		// Swap the bits two times.
		h.NoError(vint.GetSet(1, b2))
		h.NoError(vint.GetSet(1, b2))
		h.VarIntEqual(1, b1)
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntAdd(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints sum and compare with
		// calculated bits sum.
		b1, b2 := h.NewBits2B62(b62)
		bsum := NewBitsBigInt(big.NewInt(0).Add(b1.BigInt(), b2.BigInt()))
		bsum = NewBitsBits(b1.BitLen(), bsum)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Add bits first time to zero vint.
		h.NoError(vint.Add(1, b1))
		h.VarIntEqual(1, b1)
		// Add bits to the same vint second time.
		// Allow overflow error, but don't check bits equality then.
		if !h.NoError(vint.Add(1, b2), ErrorAdditionOverflow) {
			h.VarIntEqual(1, bsum)
		}
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints sub and compare with
		// calculated bits delta.
		b1, b2 := h.NewBits2B62(b62)
		bsub := NewBitsBigInt(big.NewInt(0).Sub(b1.BigInt(), b2.BigInt()))
		bsub = NewBitsBits(b1.BitLen(), bsub)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(1, b1)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Subtract the bits.
		// Allow underflow error, but don't check bit equality then.
		if !h.NoError(vint.Sub(1, b2), ErrorSubtractionUnderflow) {
			h.VarIntEqual(1, bsub)
		}
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntMul(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated mul with bits product.
		b1, b2 := h.NewBits2B62(b62)
		bmul := NewBitsBigInt(big.NewInt(1).Mul(b1.BigInt(), b2.BigInt()))
		mblen := b1.BitLen() * 2
		b1, b2, bmul =
			NewBitsBits(mblen, b1),
			NewBitsBits(mblen, b2),
			NewBitsBits(mblen, bmul)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(1, b1)
		h.VarIntSet(2, b1)
		// Multiply vint the bits.
		// Allow overflow error, but don't check bit equality then.
		if !h.NoError(vint.Mul(1, b2), ErrorMultiplicationOverflow) {
			h.VarIntEqual(1, bmul)
		}
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntDiv(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints div and compare to
		// calculated div with bits quotient.
		b1, b2 := h.NewBits2B62(b62)
		bdiv := NewBits(b1.BitLen(), nil)
		if !b2.Empty() {
			bdiv = NewBitsBigInt(big.NewInt(1).Div(b1.BigInt(), b2.BigInt()))
			bdiv = NewBitsBits(b1.BitLen(), bdiv)
		}
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(1, b1)
		h.VarIntSet(2, b1)
		// Divide vint by the bits.
		if !h.NoError(vint.Div(1, b2), ErrorDivisionByZero) {
			h.VarIntEqual(1, bdiv)
		}
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntMod(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints mod and compare to
		// calculated mod with bits reminder.
		b1, b2 := h.NewBits2B62(b62)
		if b2.Empty() {
			h.Skip()
		}
		bmod := NewBitsBigInt(big.NewInt(1).Mod(b1.BigInt(), b2.BigInt()))
		bmod = NewBitsBits(b1.BitLen(), bmod)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(1, b1)
		h.VarIntSet(2, b1)
		// Modulo vint by the bits.
		if !h.NoError(vint.Mod(1, b2)) {
			h.VarIntEqual(1, bmod)
		}
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntNot(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits and apply bit not ^ two times.
		// First resul should be different from the bits.
		// And second result should match the bits.
		bits := h.NewBitsB62(b62)
		vint := h.NewVarInt(bits.BitLen(), l)
		h.VarIntSet(1, bits)
		h.VarIntSet(0, bits)
		h.VarIntSet(2, bits)
		h.VarIntEqual(1, bits)
		// Apply bit not ^ first time.
		h.NoError(vint.Not(1))
		h.VarIntNotEqual(1, bits)
		// Apply bit not ^ second time.
		h.NoError(vint.Not(1))
		h.VarIntEqual(1, bits)
		// Check that others bits were not affected.
		h.VarIntEqual(0, bits)
		h.VarIntEqual(2, bits)
	})
}

func FuzzVarIntAnd(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints bit and & and compare to
		// calculated bit and & with bits result.
		b1, b2 := h.NewBits2B62(b62)
		band := NewBitsBigInt(big.NewInt(0).And(b1.BigInt(), b2.BigInt()))
		band = NewBitsBits(b1.BitLen(), band)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(1, b1)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Apply bit and &.
		h.NoError(vint.And(1, b2))
		h.VarIntEqual(1, band)
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntOr(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints bit or | and compare to
		// calculated bit | or with bits result.
		b1, b2 := h.NewBits2B62(b62)
		bor := NewBitsBigInt(big.NewInt(0).Or(b1.BigInt(), b2.BigInt()))
		bor = NewBitsBits(b1.BitLen(), bor)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(1, b1)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Apply bit and |.
		h.NoError(vint.Or(1, b2))
		h.VarIntEqual(1, bor)
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntXor(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints bit xor ^ and compare to
		// calculated bit ^ xor with bits result.
		b1, b2 := h.NewBits2B62(b62)
		bxor := NewBitsBigInt(big.NewInt(0).Xor(b1.BigInt(), b2.BigInt()))
		bxor = NewBitsBits(b1.BitLen(), bxor)
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(1, b1)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Apply bit xor ^.
		h.NoError(vint.Xor(1, b2))
		h.VarIntEqual(1, bxor)
		// Check that others bits were not affected.
		h.VarIntEqual(0, b1)
		h.VarIntEqual(2, b1)
	})
}

func FuzzVarIntRsh(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits and bootstrap big int,
		// shift them both to the right in range [0, BitLen+1].
		// Finally, compare calculated bit shifts with the bits.
		bits := h.NewBitsB62(b62)
		big, n := bits.BigInt(), rnd.Int()%(bits.BitLen()+1)
		big = big.Rsh(big, uint(n))
		bsh := NewBitsBigInt(big)
		bsh = NewBitsBits(bits.BitLen(), bsh)
		vint := h.NewVarInt(bits.BitLen(), l)
		h.VarIntSet(1, bits)
		h.VarIntSet(0, bits)
		h.VarIntSet(2, bits)
		// Shift bits to the right.
		h.NoError(vint.Rsh(1, n))
		h.VarIntEqual(1, bsh)
		// Check that others bits were not affected.
		h.VarIntEqual(0, bits)
		h.VarIntEqual(2, bits)
	})
}

func FuzzVarIntLsh(f *testing.F) {
	const l = 3
	fuzz(f, func(h h, b62 string) {
		// Initialize fuzz bits and bootstrap big int,
		// shift them both to the left in range [0, BitLen+1].
		// Finally, compare calculated bit shifts with the bits.
		bits := h.NewBitsB62(b62)
		big, n := bits.BigInt(), rnd.Int()%(bits.BitLen()+1)
		big = big.Lsh(big, uint(n))
		bsh := NewBitsBigInt(big)
		bsh = NewBitsBits(bits.BitLen(), bsh)
		vint := h.NewVarInt(bits.BitLen(), l)
		h.VarIntSet(1, bits)
		h.VarIntSet(0, bits)
		h.VarIntSet(2, bits)
		// Shift bits to the left.
		h.NoError(vint.Lsh(1, n))
		h.VarIntEqual(1, bsh)
		// Check that others bits were not affected.
		h.VarIntEqual(0, bits)
		h.VarIntEqual(2, bits)
	})
}

func BenchmarkVarIntOperations(b *testing.B) {
	bench("Benchmark Arithmetic Operations", b, func(b *testing.B) {
		bench("100000000 integers, 4 bits width", b, func(b *testing.B) {
			const len, blen = 100000000, 4
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{10})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Add(i, bits)
					_ = vint.Sub(i, bits)
					_ = vint.Mul(i, bits)
					_ = vint.Add(i, bits)
					_ = vint.Div(i, bits)
					_ = vint.Set(i, bits)
					_ = vint.Mod(i, bits)
					_ = vint.Get(i, bits)
				}
			})
			bench("Uint8 Slice", b, func(b *testing.B) {
				slice := make([]uint8, len)
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					slice[i] += 10
					slice[i] -= 10
					slice[i] *= 10
					slice[i] += 10
					slice[i] /= 10
					slice[i] = 10
					slice[i] %= 10
					_ = slice[i]
				}
			})
		})
		bench("10000000 integers, 64 bits width", b, func(b *testing.B) {
			const len, blen = 10000000, 64
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{1000000000})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Add(i, bits)
					_ = vint.Sub(i, bits)
					_ = vint.Mul(i, bits)
					_ = vint.Add(i, bits)
					_ = vint.Div(i, bits)
					_ = vint.Set(i, bits)
					_ = vint.Mod(i, bits)
					_ = vint.Get(i, bits)
				}
			})
			bench("Uint64 Slice", b, func(b *testing.B) {
				slice := make([]uint64, len)
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					slice[i] += 1000000000
					slice[i] -= 1000000000
					slice[i] *= 1000000000
					slice[i] += 1000000000
					slice[i] /= 1000000000
					slice[i] = 1000000000
					slice[i] %= 1000000000
					_ = slice[i]
				}
			})
		})
		bench("10000000 integers, 100 bits width", b, func(b *testing.B) {
			const len, blen = 10000000, 100
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{0x123, 0x456})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Add(i, bits)
					_ = vint.Sub(i, bits)
					_ = vint.Mul(i, bits)
					_ = vint.Add(i, bits)
					_ = vint.Div(i, bits)
					_ = vint.Set(i, bits)
					_ = vint.Mod(i, bits)
					_ = vint.Get(i, bits)
				}
			})
			bench("BigInt Slice", b, func(b *testing.B) {
				slice := make([]*big.Int, len)
				for i := 0; i < len; i++ {
					slice[i] = new(big.Int)
				}
				bits := new(big.Int).SetBits([]big.Word{0x123, 0x456})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = slice[i].Add(slice[i], bits)
					_ = slice[i].Sub(slice[i], bits)
					_ = slice[i].Mul(slice[i], bits)
					_ = slice[i].Add(slice[i], bits)
					_ = slice[i].Div(slice[i], bits)
					_ = slice[i].Set(bits)
					_ = slice[i].Mod(slice[i], bits)
					_ = slice[i].Bytes()
				}
			})
		})
		bench("100000 integers, 10000 bits width", b, func(b *testing.B) {
			const len, blen = 100000, 10000
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{0x123, 0x456, 0x678, 0x910, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x100})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Add(i, bits)
					_ = vint.Sub(i, bits)
					_ = vint.Mul(i, bits)
					_ = vint.Add(i, bits)
					_ = vint.Div(i, bits)
					_ = vint.Set(i, bits)
					_ = vint.Mod(i, bits)
					_ = vint.Get(i, bits)
				}
			})
			bench("BigInt Slice", b, func(b *testing.B) {
				slice := make([]*big.Int, len)
				for i := 0; i < len; i++ {
					slice[i] = new(big.Int)
				}
				bits := new(big.Int).SetBits([]big.Word{0x123, 0x456, 0x678, 0x910, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x100})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = slice[i].Add(slice[i], bits)
					_ = slice[i].Sub(slice[i], bits)
					_ = slice[i].Mul(slice[i], bits)
					_ = slice[i].Add(slice[i], bits)
					_ = slice[i].Div(slice[i], bits)
					_ = slice[i].Set(bits)
					_ = slice[i].Mod(slice[i], bits)
					_ = slice[i].Bytes()
				}
			})
		})
	})
	bench("Benchmark Bitwise Operations", b, func(b *testing.B) {
		bench("100000000 integers, 4 bits width", b, func(b *testing.B) {
			const len, blen = 100000000, 4
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{10})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Or(i, bits)
					_ = vint.Xor(i, bits)
					_ = vint.And(i, bits)
					_ = vint.Not(i)
					_ = vint.Lsh(i, blen)
					_ = vint.Rsh(i, blen)
				}
			})
			bench("Uint8 Slice", b, func(b *testing.B) {
				slice := make([]uint8, len)
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					slice[i] |= 10
					slice[i] ^= 10
					slice[i] &= 10
					slice[i] = ^slice[i]
					slice[i] <<= blen
					slice[i] >>= blen
				}
			})
		})
		bench("10000000 integers, 64 bits width", b, func(b *testing.B) {
			const len, blen = 10000000, 64
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{1000000000})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Or(i, bits)
					_ = vint.Xor(i, bits)
					_ = vint.And(i, bits)
					_ = vint.Not(i)
					_ = vint.Lsh(i, blen)
					_ = vint.Rsh(i, blen)
				}
			})
			bench("Uint64 Slice", b, func(b *testing.B) {
				slice := make([]uint64, len)
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					slice[i] |= 10
					slice[i] ^= 10
					slice[i] &= 10
					slice[i] = ^slice[i]
					slice[i] <<= blen - 1
					slice[i] >>= blen - 1
				}
			})
		})
		bench("10000000 integers, 100 bits width", b, func(b *testing.B) {
			const len, blen = 10000000, 100
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{0x123, 0x456})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Or(i, bits)
					_ = vint.Xor(i, bits)
					_ = vint.And(i, bits)
					_ = vint.Not(i)
					_ = vint.Lsh(i, blen)
					_ = vint.Rsh(i, blen)
				}
			})
			bench("BigInt Slice", b, func(b *testing.B) {
				slice := make([]*big.Int, len)
				for i := 0; i < len; i++ {
					slice[i] = new(big.Int)
				}
				bits := new(big.Int).SetBits([]big.Word{0x123, 0x456})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = slice[i].Or(slice[i], bits)
					_ = slice[i].Xor(slice[i], bits)
					_ = slice[i].And(slice[i], bits)
					_ = slice[i].Not(slice[i])
					_ = slice[i].Lsh(slice[i], blen)
					_ = slice[i].Rsh(bits, blen)
				}
			})
		})
		bench("100000 integers, 10000 bits width", b, func(b *testing.B) {
			const len, blen = 100000, 10000
			bench("VarInt", b, func(b *testing.B) {
				vint, _ := NewVarInt(blen, len)
				bits := NewBits(blen, []uint{0x123, 0x456, 0x678, 0x910, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x100})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = vint.Or(i, bits)
					_ = vint.Xor(i, bits)
					_ = vint.And(i, bits)
					_ = vint.Not(i)
					_ = vint.Lsh(i, blen)
					_ = vint.Rsh(i, blen)
				}
			})
			bench("BigInt Slice", b, func(b *testing.B) {
				slice := make([]*big.Int, len)
				for i := 0; i < len; i++ {
					slice[i] = new(big.Int)
				}
				bits := new(big.Int).SetBits([]big.Word{0x123, 0x456, 0x678, 0x910, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x100})
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					i := n % len
					_ = slice[i].Or(slice[i], bits)
					_ = slice[i].Xor(slice[i], bits)
					_ = slice[i].And(slice[i], bits)
					_ = slice[i].Not(slice[i])
					_ = slice[i].Lsh(slice[i], blen)
					_ = slice[i].Rsh(bits, blen)
				}
			})
		})
	})
}
