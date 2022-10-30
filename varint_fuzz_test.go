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
			tt.VarIntEqual(i, bits, tt.NewBitsZero(bits.BitLen()))
		}
	})
}

func FuzzVarIntGetSet(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Swap original bits and
		// random bits two times so result should be the same.
		bits := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(bits.BitLen())
		vint := tt.NewVarInt(bits.BitLen(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(1, bits)
		tt.VarIntSet(2, bits)
		tt.VarIntSet(0, bits)
		// Then swap origin and rand bits two times.
		tt.NoError(vint.GetSet(1, brnd))
		tt.NoError(vint.GetSet(1, brnd))
		tt.VarIntEqual(1, bits)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}

func FuzzVarIntCmp(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, result of ints comparison should match
		// vint comparison result.
		bits := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(bits.BitLen())
		cmp := bits.BigInt().Cmp(brnd.BigInt())
		vint := tt.NewVarInt(bits.BitLen(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(1, bits)
		tt.VarIntSet(2, bits)
		tt.VarIntSet(0, bits)
		// Then compare origin and rand bits.
		vcmp, err := vint.Cmp(1, brnd)
		tt.NoError(err)
		tt.Equal(cmp, vcmp)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}

func FuzzVarIntAdd(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated sum of original + random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen())
		bsum := tt.NewBitsBigInt(big.NewInt(0).Add(borig.BigInt(), brnd.BigInt()))
		bsum = tt.NewBits(borig.BitLen(), bsum.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		// First, add original bits to zeroed vint.
		tt.NoError(vint.Add(1, borig))
		tt.VarIntEqual(1, borig)
		// Second, add random bits to the same vint.
		// Allow overflow error, but don't check bit equality then.
		if !tt.NoError(vint.Add(1, brnd), ErrorAdditionOverflow{BitLen: borig.BitLen()}) {
			tt.VarIntEqual(1, bsum)
		}
		// Third, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints sub and compare to
		// calculated sub of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen())
		bsub := tt.NewBitsBigInt(big.NewInt(0).Sub(borig.BigInt(), brnd.BigInt()))
		// Fix the cardinarity for sub bits.
		bsub = tt.NewBits(borig.BitLen(), bsub.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		// First, set original bits and sub random bits.
		tt.VarIntSet(1, borig)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		// Allow underflow error, but don't check bit equality then.
		if !tt.NoError(vint.Sub(1, brnd), ErrorSubtractionUnderflow{BitLen: borig.BitLen()}) {
			tt.VarIntEqual(1, bsub)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntMul(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated mul of original * random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen())
		bmul := tt.NewBitsBigInt(big.NewInt(1).Mul(borig.BigInt(), brnd.BigInt()))
		mblen := borig.BitLen() * 2
		borig, brnd, bmul =
			tt.NewBits(mblen, borig.Bytes()),
			tt.NewBits(mblen, brnd.Bytes()),
			tt.NewBits(mblen, bmul.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(1, borig)
		tt.VarIntSet(2, borig)
		// First, multiply vint by random bits.
		// Allow overflow error, but don't check bit equality then.
		if !tt.NoError(vint.Mul(1, brnd), ErrorMultiplicationOverflow{BitLen: borig.BitLen()}) {
			tt.VarIntEqual(1, bmul)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntDiv(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints div and compare to
		// calculated div of original / random bits.
		borig := tt.NewBitsB62(b62)
		dblen := borig.BitLen() / 2
		if dblen == 0 {
			dblen = 1
		}
		brnd := tt.NewBitsRand(dblen)
		for brnd.Empty() {
			brnd = tt.NewBitsRand(dblen)
		}
		brnd = tt.NewBits(borig.BitLen(), brnd.Bytes())
		bdiv := tt.NewBitsBigInt(big.NewInt(1).Div(borig.BigInt(), brnd.BigInt()))
		bdiv = tt.NewBits(borig.BitLen(), bdiv.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(1, borig)
		tt.VarIntSet(2, borig)
		// First, divide vint by random bits.
		// Allow overflow error, but don't check bit equality then.
		if !tt.NoError(vint.Div(1, brnd)) {
			tt.VarIntEqual(1, bdiv)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntMod(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints mod and compare to
		// calculated mod of original % random bits.
		borig := tt.NewBitsB62(b62)
		dblen := borig.BitLen() / 2
		if dblen == 0 {
			dblen = 1
		}
		brnd := tt.NewBitsRand(dblen)
		for brnd.Empty() {
			brnd = tt.NewBitsRand(dblen)
		}
		brnd = tt.NewBits(borig.BitLen(), brnd.Bytes())
		bmod := tt.NewBitsBigInt(big.NewInt(1).Mod(borig.BigInt(), brnd.BigInt()))
		bmod = tt.NewBits(borig.BitLen(), bmod.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(1, borig)
		tt.VarIntSet(2, borig)
		// First, modulo vint by random bits.
		// Allow overflow error, but don't check bit equality then.
		if !tt.NoError(vint.Mod(1, brnd)) {
			tt.VarIntEqual(1, bmod)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntNot(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and
		// apply bit not two times. First result
		// should be different from original bits.
		// And second result should match original bits.
		bits := tt.NewBitsB62(b62)
		vint := tt.NewVarInt(bits.BitLen(), l)
		tt.VarIntSet(1, bits)
		tt.VarIntSet(0, bits)
		tt.VarIntSet(2, bits)
		tt.VarIntEqual(1, bits)
		// First, apply not first time.
		tt.NoError(vint.Not(1))
		tt.VarIntNotEqual(1, bits)
		// Second, apply not second time.
		tt.NoError(vint.Not(1))
		tt.VarIntEqual(1, bits)
		// Third, check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}

func FuzzVarIntAnd(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit and and compare to
		// calculated bit and of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen())
		band := tt.NewBitsBigInt(big.NewInt(0).And(borig.BigInt(), brnd.BigInt()))
		// Fix the cardinarity for add bits.
		band = tt.NewBits(borig.BitLen(), band.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(1, borig)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		tt.NoError(vint.And(1, brnd))
		tt.VarIntEqual(1, band)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntOr(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit or and compare to
		// calculated bit or of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen())
		bor := tt.NewBitsBigInt(big.NewInt(0).Or(borig.BigInt(), brnd.BigInt()))
		// Fix the cardinarity for or bits.
		bor = tt.NewBits(borig.BitLen(), bor.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(1, borig)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		tt.NoError(vint.Or(1, brnd))
		tt.VarIntEqual(1, bor)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntXor(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit xor and compare to
		// calculated bit xor of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen())
		bxor := tt.NewBitsBigInt(big.NewInt(0).Xor(borig.BigInt(), brnd.BigInt()))
		// Fix the cardinarity for xor bits.
		bxor = tt.NewBits(borig.BitLen(), bxor.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(1, borig)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		tt.NoError(vint.Xor(1, brnd))
		tt.VarIntEqual(1, bxor)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntRsh(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and bootstrap big int,
		// shift them both bits and bigint to the right [0, bits+1].
		// Finally, compare calculated bit shifts with oriranal bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), tt.Int()%(bits.BitLen()+1)
		big = big.Rsh(big, uint(n))
		// Fix the cardinarity for sub bits.
		bsh := tt.NewBitsBigInt(big)
		bsh = tt.NewBits(bits.BitLen(), bsh.Bytes())
		vint := tt.NewVarInt(bits.BitLen(), l)
		// First, set original bits.
		tt.VarIntSet(1, bits)
		tt.VarIntSet(0, bits)
		tt.VarIntSet(2, bits)
		// Then shift bits to the right.
		tt.NoError(vint.Rsh(1, n))
		tt.VarIntEqual(1, bsh)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}

func FuzzVarIntLsh(f *testing.F) {
	const l = 3
	seedfuzz(f)
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := newtt(t)
		// Initialize fuzz original bits and bootstrap big int,
		// shift them both bits and bigint to the left [0, bits+1].
		// Finally, compare calculated bit shifts with oriranal bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), tt.Int()%(bits.BitLen()+1)
		big = big.Lsh(big, uint(n))
		// Fix the cardinarity for sub bits.
		bsh := tt.NewBitsBigInt(big)
		bsh = tt.NewBits(bits.BitLen(), bsh.Bytes())
		vint := tt.NewVarInt(bits.BitLen(), l)
		// First, set original bits.
		tt.VarIntSet(1, bits)
		tt.VarIntSet(0, bits)
		tt.VarIntSet(2, bits)
		// Then shift bits to the left.
		tt.NoError(vint.Lsh(1, n))
		tt.VarIntEqual(1, bsh)
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, bits)
		tt.VarIntEqual(2, bits)
	})
}
