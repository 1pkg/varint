package varint

import (
	"math/big"
	"testing"
)

func seedfuzz(f *testing.F) {
	for _, b62 := range []string{
		"15",
		"Jj",
		"4kmkU49SllO",
		"2erdLVDT8PFu",
		"3X00000000000000000000",
		"XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
		"3rNk68AgS73raYcuFFPjD3MPzU5ELtIwjHVcu",
	} {
		f.Add(b62)
	}
}

func FuzzVarIntSetAndGet(f *testing.F) {
	const l = 10
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits then randomly set
		// some vint numbers to fuzz original bits. Finally,
		// verify that all numbers in vint are either equal to
		// fuzz original bits or equal to zero.
		bits := tt.NewBitsB62(b62)
		_ = tt.NewVarInt(bits.BitLen(), l)
		for i := 0; i < l; i++ {
			n := tt.Int() % l
			tt.VarIntSet(n, bits)
			b := tt.VarIntGet(n)
			tt.Equal(bits, b)
		}
		for i := 0; i < l; i++ {
			// Check for zero or equal.
			if !tt.VarIntGet(i).Empty() {
				tt.VarIntEqual(i, bits)
			}
		}
	})
}

func FuzzVarIntGetSet(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Swap them
		// two times so result should be the same.
		b1, b2 := tt.NewBits2B62(b62)
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(2, b1)
		tt.VarIntSet(0, b1)
		// Swap the bits two times.
		tt.NoError(vint.GetSet(1, b2))
		tt.NoError(vint.GetSet(1, b2))
		tt.VarIntEqual(1, b1)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntCmp(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, result of ints comparison should match
		// vint comparison result.
		b1, b2 := tt.NewBits2B62(b62)
		for i := 0; i < tt.Int()%l; i++ {
			b1, b2 = b2, b1
		}
		cmp := b1.BigInt().Cmp(b2.BigInt())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(2, b1)
		tt.VarIntSet(0, b1)
		// Compare the bits.
		vcmp, err := vint.Cmp(1, b2)
		tt.NoError(err)
		tt.Equal(cmp, vcmp)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntAdd(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints sum and compare with
		// calculated bits sum.
		b1, b2 := tt.NewBits2B62(b62)
		bsum := NewBitsBigInt(big.NewInt(0).Add(b1.BigInt(), b2.BigInt()))
		bsum = NewBits(b1.BitLen(), bsum.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(2, b1)
		// Add bits first time to zero vint.
		tt.NoError(vint.Add(1, b1))
		tt.VarIntEqual(1, b1)
		// Add bits to the same vint second time.
		// Allow overflow error, but don't check bits equality then.
		if !tt.NoError(vint.Add(1, b2), ErrorAdditionOverflow{BitLen: b1.BitLen()}) {
			tt.VarIntEqual(1, bsum)
		}
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints sub and compare with
		// calculated bits delta.
		b1, b2 := tt.NewBits2B62(b62)
		bsub := NewBitsBigInt(big.NewInt(0).Sub(b1.BigInt(), b2.BigInt()))
		bsub = NewBits(b1.BitLen(), bsub.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(2, b1)
		// Substract the bits.
		// Allow underflow error, but don't check bit equality then.
		if !tt.NoError(vint.Sub(1, b2), ErrorSubtractionUnderflow{BitLen: b1.BitLen()}) {
			tt.VarIntEqual(1, bsub)
		}
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntMul(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated mul with bits product.
		b1, b2 := tt.NewBits2B62(b62)
		bmul := NewBitsBigInt(big.NewInt(1).Mul(b1.BigInt(), b2.BigInt()))
		mblen := b1.BitLen() * 2
		b1, b2, bmul =
			NewBits(mblen, b1.Bytes()),
			NewBits(mblen, b2.Bytes()),
			NewBits(mblen, bmul.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(2, b1)
		// Multiply vint the bits.
		// Allow overflow error, but don't check bit equality then.
		if !tt.NoError(vint.Mul(1, b2), ErrorMultiplicationOverflow{BitLen: b1.BitLen()}) {
			tt.VarIntEqual(1, bmul)
		}
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntDiv(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints div and compare to
		// calculated div with bits quotient.
		b1, b2 := tt.NewBits2B62(b62)
		if b2.Empty() {
			t.Skip()
		}
		bdiv := NewBitsBigInt(big.NewInt(1).Div(b1.BigInt(), b2.BigInt()))
		bdiv = NewBits(b1.BitLen(), bdiv.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(2, b1)
		// Divide vint by the bits.
		if !tt.NoError(vint.Div(1, b2)) {
			tt.VarIntEqual(1, bdiv)
		}
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntMod(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints mod and compare to
		// calculated mod with bits reminder.
		b1, b2 := tt.NewBits2B62(b62)
		if b2.Empty() {
			t.Skip()
		}
		bmod := NewBitsBigInt(big.NewInt(1).Mod(b1.BigInt(), b2.BigInt()))
		bmod = NewBits(b1.BitLen(), bmod.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(2, b1)
		// Modulo vint by the bits.
		if !tt.NoError(vint.Mod(1, b2)) {
			tt.VarIntEqual(1, bmod)
		}
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntNot(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits and apply bit not ^ two times.
		// First resul should be different from the bits.
		// And second result should match the bits.
		bits := tt.NewBitsB62(b62)
		vint := tt.NewVarInt(bits.BitLen(), l)
		tt.VarIntSet(1, bits)
		tt.VarIntSet(0, bits)
		tt.VarIntSet(2, bits)
		tt.VarIntEqual(1, bits)
		// Apply bit not ^ first time.
		tt.NoError(vint.Not(1))
		tt.VarIntNotEqual(1, bits)
		// Apply bit not ^ second time.
		tt.NoError(vint.Not(1))
		tt.VarIntEqual(1, bits)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}

func FuzzVarIntAnd(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints bit and & and compare to
		// calculated bit and & with bits result.
		b1, b2 := tt.NewBits2B62(b62)
		band := NewBitsBigInt(big.NewInt(0).And(b1.BigInt(), b2.BigInt()))
		band = NewBits(b1.BitLen(), band.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(2, b1)
		// Apply bit and &.
		tt.NoError(vint.And(1, b2))
		tt.VarIntEqual(1, band)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntOr(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints bit or | and compare to
		// calculated bit | or with bits result.
		b1, b2 := tt.NewBits2B62(b62)
		bor := NewBitsBigInt(big.NewInt(0).Or(b1.BigInt(), b2.BigInt()))
		bor = NewBits(b1.BitLen(), bor.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(2, b1)
		// Apply bit and |.
		tt.NoError(vint.Or(1, b2))
		tt.VarIntEqual(1, bor)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntXor(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits pair. Then bootstrap big ints
		// from them, calculate bit ints bit xor ^ and compare to
		// calculated bit ^ xor with bits result.
		b1, b2 := tt.NewBits2B62(b62)
		bxor := NewBitsBigInt(big.NewInt(0).Xor(b1.BigInt(), b2.BigInt()))
		bxor = NewBits(b1.BitLen(), bxor.Bytes())
		vint := tt.NewVarInt(b1.BitLen(), l)
		tt.VarIntSet(1, b1)
		tt.VarIntSet(0, b1)
		tt.VarIntSet(2, b1)
		// Apply bit xor ^.
		tt.NoError(vint.Xor(1, b2))
		tt.VarIntEqual(1, bxor)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, b1)
		tt.VarIntEqual(2, b1)
	})
}

func FuzzVarIntRsh(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits and bootstrap big int,
		// shift them both to the right in range [0, BitLen+1].
		// Finally, compare calculated bit shifts with the bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), tt.Int()%(bits.BitLen()+1)
		big = big.Rsh(big, uint(n))
		bsh := NewBitsBigInt(big)
		bsh = NewBits(bits.BitLen(), bsh.Bytes())
		vint := tt.NewVarInt(bits.BitLen(), l)
		tt.VarIntSet(1, bits)
		tt.VarIntSet(0, bits)
		tt.VarIntSet(2, bits)
		// Shift bits to the right.
		tt.NoError(vint.Rsh(1, n))
		tt.VarIntEqual(1, bsh)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}

func FuzzVarIntLsh(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz bits and bootstrap big int,
		// shift them both to the left in range [0, BitLen+1].
		// Finally, compare calculated bit shifts with the bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), tt.Int()%(bits.BitLen()+1)
		big = big.Lsh(big, uint(n))
		bsh := NewBitsBigInt(big)
		bsh = NewBits(bits.BitLen(), bsh.Bytes())
		vint := tt.NewVarInt(bits.BitLen(), l)
		tt.VarIntSet(1, bits)
		tt.VarIntSet(0, bits)
		tt.VarIntSet(2, bits)
		// Shift bits to the left.
		tt.NoError(vint.Lsh(1, n))
		tt.VarIntEqual(1, bsh)
		// Check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}
