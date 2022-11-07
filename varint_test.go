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
			err:  ErrorBitLengthIsNotPositive{BitLen: 0},
		},
		"negative len should resolve in expected error": {
			blen: 10,
			len:  -1,
			err:  ErrorLengthIsNotPositive{Len: -1},
		},
		"positive bits len and len resolve in valid vint": {
			blen: 120,
			len:  5,
			vint: VarInt{5, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 0, 0},
		},
	}
	for tname, tcase := range table {
		test(tname, t, func(h h) {
			vint, err := NewVarInt(tcase.blen, tcase.len)
			if !h.NoError(tcase.err, err) {
				h.Equal(tcase.vint, vint)
			}
		})
	}
}

func TestVarIntError(t *testing.T) {
	const len = 10
	test("Common", t, func(th h) {
		table := map[string]struct {
			i    int
			bits Bits
			err  error
		}{
			"common operations should return negative index error": {
				i:    -1,
				bits: NewBits(len, nil),
				err:  ErrorIndexIsNegative{Index: -1},
			},
			"common operations should return index is out of range error": {
				i:    2 * len,
				bits: NewBits(len, nil),
				err:  ErrorIndexIsOutOfRange{Index: 2 * len, Length: 10},
			},
			"common operations should return bit len cardinarity error": {
				i:    1,
				bits: NewBits(2*len, nil),
				err:  ErrorUnequalBitLengthCardinality{BitLenLeft: len, BitLenRight: 2 * len},
			},
			"common operations should return a valid result for empty bits on valid index": {
				i:    1,
				bits: NewBits(len, []uint{1}),
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				vint := h.NewVarInt(len, len)
				h.VarIntSet(1, NewBits(len, []uint{len}))
				h.Equal(vint.Get(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Set(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.GetSet(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Add(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Sub(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Mul(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Div(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Mod(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Not(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.And(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Or(tcase.i, tcase.bits), tcase.err)
				h.Equal(vint.Xor(tcase.i, tcase.bits), tcase.err)
			})
		}
	})
	test("Shifts", t, func(th h) {
		table := map[string]struct {
			i   int
			n   int
			err error
		}{
			"shift operations should return negative index error": {
				i:   -1,
				n:   1,
				err: ErrorIndexIsNegative{Index: -1},
			},
			"shift operations should return index is out of range error": {
				i:   2 * len,
				n:   1,
				err: ErrorIndexIsOutOfRange{Index: 2 * len, Length: 10},
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				vint := h.NewVarInt(len, len)
				h.VarIntSet(1, NewBits(len, []uint{len}))
				h.Equal(vint.Rsh(tcase.i, tcase.n), tcase.err)
				h.Equal(vint.Lsh(tcase.i, tcase.n), tcase.err)
			})
		}
	})
	test("Math", t, func(th h) {
		type vintOp func(i int, bits Bits) error
		vint := th.NewVarInt(len, len)
		table := map[string]struct {
			op   vintOp
			bits Bits
			err  error
		}{
			"addition should return overflow error on bits overflow": {
				op:   vint.Add,
				bits: NewBits(len, []uint{1020}),
				err:  ErrorAdditionOverflow{},
			},
			"subtraction should return underflow error on bits underflow": {
				op:   vint.Sub,
				bits: NewBits(len, []uint{16}),
				err:  ErrorSubtractionUnderflow{},
			},
			"multiplication should return overflow error on bits overflow": {
				op:   vint.Mul,
				bits: NewBits(len, []uint{299}),
				err:  ErrorMultiplicationOverflow{},
			},
			"division should return zero division error on division by zero": {
				op:   vint.Div,
				bits: NewBits(len, nil),
				err:  ErrorDivisionByZero{},
			},
			"modulo should return zero division error on division by zero": {
				op:   vint.Mod,
				bits: NewBits(len, nil),
				err:  ErrorDivisionByZero{},
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
		bsum = NewBits(b1.BitLen(), bsum.Bytes())
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Add bits first time to zero vint.
		h.NoError(vint.Add(1, b1))
		h.VarIntEqual(1, b1)
		// Add bits to the same vint second time.
		// Allow overflow error, but don't check bits equality then.
		if !h.NoError(vint.Add(1, b2), ErrorAdditionOverflow{}) {
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
		bsub = NewBits(b1.BitLen(), bsub.Bytes())
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(1, b1)
		h.VarIntSet(0, b1)
		h.VarIntSet(2, b1)
		// Substract the bits.
		// Allow underflow error, but don't check bit equality then.
		if !h.NoError(vint.Sub(1, b2), ErrorSubtractionUnderflow{}) {
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
			NewBits(mblen, b1.Bytes()),
			NewBits(mblen, b2.Bytes()),
			NewBits(mblen, bmul.Bytes())
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(1, b1)
		h.VarIntSet(2, b1)
		// Multiply vint the bits.
		// Allow overflow error, but don't check bit equality then.
		if !h.NoError(vint.Mul(1, b2), ErrorMultiplicationOverflow{}) {
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
		if b2.Empty() {
			h.Skip()
		}
		bdiv := NewBitsBigInt(big.NewInt(1).Div(b1.BigInt(), b2.BigInt()))
		bdiv = NewBits(b1.BitLen(), bdiv.Bytes())
		vint := h.NewVarInt(b1.BitLen(), l)
		h.VarIntSet(0, b1)
		h.VarIntSet(1, b1)
		h.VarIntSet(2, b1)
		// Divide vint by the bits.
		if !h.NoError(vint.Div(1, b2)) {
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
		bmod = NewBits(b1.BitLen(), bmod.Bytes())
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
		bnot := NewBits(bits.BitLen(), nil)
		vint := h.NewVarInt(bits.BitLen(), l)
		h.VarIntSet(1, bits)
		h.VarIntSet(0, bits)
		h.VarIntSet(2, bits)
		h.VarIntEqual(1, bits)
		// Apply bit not ^ first time.
		h.NoError(vint.Not(1, bnot))
		h.VarIntNotEqual(1, bits)
		// Apply bit not ^ second time.
		h.NoError(vint.Not(1, bnot))
		h.Equal(bits, bnot)
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
		band = NewBits(b1.BitLen(), band.Bytes())
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
		bor = NewBits(b1.BitLen(), bor.Bytes())
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
		bxor = NewBits(b1.BitLen(), bxor.Bytes())
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
		bsh = NewBits(bits.BitLen(), bsh.Bytes())
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
		bsh = NewBits(bits.BitLen(), bsh.Bytes())
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

func BenchmarkAddGetVarIntvsSlice(b *testing.B) {
	const len = 100000000
	bench("Benchmark VarInt Add/Get", b, func(b *testing.B) {
		vint, _ := NewVarInt(4, len)
		bits := NewBits(4, []uint{10})
		tmp := NewBits(4, nil)
		for n := 0; n < b.N; n++ {
			_ = vint.Add(n%len, bits)
			_ = vint.Get(n%len, tmp)
		}
	})
	bench("Benchmark Slice Add/Get", b, func(b *testing.B) {
		slice := make([]uint8, len)
		for n := 0; n < b.N; n++ {
			slice[n%len] += 10
			_ = slice[n%len]
		}
	})
}
