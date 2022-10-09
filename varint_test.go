package varint

import (
	"math/big"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

var b62Seed = []string{
	"15",
	"Jj",
	"4kmkU49SllO",
	"2erdLVDT8PFu",
	"3X00000000000000000000",
	"XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
	"3rNk68AgS73raYcuFFPjD3MPzU5ELtIwjHVcu",
}

func mallocated(f func()) float64 {
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / 1024 / 1024
}

type thelper struct{ *testing.T }

func (t thelper) NewVarInt(bits, length int) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		t.Fatal(err)
	}
	return vint
}

func (t thelper) NewBits(bsize int, bits []uint) Bits {
	b, err := NewBits(bsize, bits)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t thelper) NewBitsRand(bsize int, rnd *rand.Rand) Bits {
	b, err := NewBitsRand(bsize, rnd)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t thelper) NewBitsBigInt(i *big.Int) Bits {
	b, err := NewBitsBigInt(i)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t thelper) NewBitsB62(b62 string) Bits {
	bits, err := NewBitsString(b62, 62)
	if err != nil {
		return t.NewBits(8, []uint{0xFF})
	}
	if bits.Bits() == 0 {
		return t.NewBits(8, []uint{0xFF})
	}
	return bits
}

func (t thelper) VarIntGet(vint VarInt, i int) Bits {
	b := t.NewBits(int(vint[0]), nil)
	if err := vint.Get(i, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (t thelper) VarIntSet(vint VarInt, i int, b Bits) {
	err := vint.Set(i, b)
	if err != nil {
		t.Fatal(err)
	}
}

func (t thelper) VarIntEqual(vint VarInt, i int, bits Bits) {
	b := t.VarIntGet(vint, i)
	if !b.Equal(bits) {
		t.Fatalf("%v doesn't equal to %v", b, bits)
	}
}

func BenchmarkAddGetVarIntvsSlice(b *testing.B) {
	const size = 100000000
	b.Run("Benchmark VarInt Add/Get", func(b *testing.B) {
		m := mallocated(func() {
			vint, _ := NewVarInt(4, size)
			bits, _ := NewBits(4, []uint{10})
			tmp, _ := NewBits(4, nil)
			for n := 0; n < b.N; n++ {
				_ = vint.Add(n%size, bits)
				_ = vint.Get(n%size, tmp)
			}
		})
		b.ReportMetric(m, "M_allocated")
	})
	b.Run("Benchmark Slice Add/Get", func(b *testing.B) {
		m := mallocated(func() {
			slice := make([]uint8, size)
			for n := 0; n < b.N; n++ {
				slice[n%size] += 10
				_ = slice[n%size]
			}
		})
		b.ReportMetric(m, "M_allocated")
	})
}

func FuzzVarIntGetSet(f *testing.F) {
	const l = 10
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits then randomly set
		// some vint numbers to fuzz original bits. Finally,
		// verify that all numbers in vint are either equal to
		// fuzz original bits or equal to zero.
		bits := tt.NewBitsB62(b62)
		vint := tt.NewVarInt(bits.Bits(), l)
		for i := 0; i < l; i++ {
			if err := vint.Set(rnd.Int()%l, bits); err != nil {
				t.Fatalf("set error %v is not expected on %v", err, bits)
			}
		}
		for i := 0; i < l; i++ {
			b := tt.NewBits(bits.Bits(), nil)
			if err := vint.Get(i, b); err != nil {
				t.Fatalf("get error %v is not expected on %v", err, bits)
			}
			// Equals to bits or zero.
			if zero := tt.NewBits(b.Bits(), []uint{0x0}); !(b.Equal(zero) || b.Equal(bits)) {
				t.Fatalf("expected result %v doesn't match actual result %v", bits, b)
			}
		}
	})
}

func FuzzVarIntSwap(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit and and compare to
		// calculated bit and of original - random bits.
		bits := tt.NewBitsB62(b62)
		bitsRnd := tt.NewBitsRand(bits.Bits(), rnd)
		vint := tt.NewVarInt(bits.Bits(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(vint, 1, bits)
		tt.VarIntSet(vint, 2, bits)
		tt.VarIntSet(vint, 0, bits)
		// Then swap origin and rand bits two times.
		if err := vint.Swap(1, bitsRnd); err != nil {
			t.Fatalf("swap error %v is not expected on %v with %v", err, bits, bitsRnd)
		}
		if err := vint.Swap(1, bitsRnd); err != nil {
			t.Fatalf("swap error %v is not expected on %v with %v", err, bits, bitsRnd)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result %v", bits, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bits)
		tt.VarIntEqual(vint, 2, bits)
	})
}

func FuzzVarIntAdd(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated sum of original + random bits.
		bitsOrig := tt.NewBitsB62(b62)
		bitsRnd := tt.NewBitsRand(bitsOrig.Bits(), rnd)
		bigOrig, bigRnd := bitsOrig.BigInt(), bitsRnd.BigInt()
		bigSum := big.NewInt(0).Add(bigOrig, bigRnd)
		bitsSum := tt.NewBitsBigInt(bigSum)
		vint := tt.NewVarInt(bitsOrig.Bits(), l)
		tt.VarIntSet(vint, 0, bitsOrig)
		tt.VarIntSet(vint, 2, bitsOrig)
		// First, add original bits to zeroed vint.
		if err := vint.Add(1, bitsOrig); err != nil {
			t.Fatalf("add error %v is not expected on %v", err, bitsOrig)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitsOrig) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsOrig, b)
		}
		// Second, add random bits to the same vint.
		if err := vint.Add(1, bitsRnd); err != nil {
			// Skip known expected error when sum overflows.
			if _, ok := err.(ErrorBitsOperationOverflow); ok {
				return
			}
			t.Fatalf("add error %v is not expected on %v with %v", err, bitsOrig, bitsRnd)
		}
		b = tt.VarIntGet(vint, 1)
		if !b.Equal(bitsSum) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsSum, b)
		}
		// Third, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bitsOrig)
		tt.VarIntEqual(vint, 2, bitsOrig)
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints sub and compare to
		// calculated sub of original - random bits.
		bitsOrig := tt.NewBitsB62(b62)
		bitsRnd := tt.NewBitsRand(bitsOrig.Bits(), rnd)
		bigOrig, bigRnd := bitsOrig.BigInt(), bitsRnd.BigInt()
		bigSub := big.NewInt(0).Sub(bigOrig, bigRnd)
		bitsSub := tt.NewBitsBigInt(bigSub)
		// Fix the cardinarity for sub bits.
		bitsSub = tt.NewBits(bitsOrig.Bits(), bitsSub.Bytes())
		vint := tt.NewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and sub random bits.
		tt.VarIntSet(vint, 1, bitsOrig)
		tt.VarIntSet(vint, 0, bitsOrig)
		tt.VarIntSet(vint, 2, bitsOrig)
		if err := vint.Sub(1, bitsRnd); err != nil {
			// Skip known expected error when sum overflows.
			if _, ok := err.(ErrorBitsOperationUnderflow); ok {
				return
			}
			t.Fatalf("sub error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bigSub)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitsSub) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsSub, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bitsOrig)
		tt.VarIntEqual(vint, 2, bitsOrig)
	})
}

func FuzzVarIntNot(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and
		// apply bit not two times. First result
		// should be different from original bits.
		// And second result should match original bits.
		bits := tt.NewBitsB62(b62)
		vint := tt.NewVarInt(bits.Bits(), l)
		tt.VarIntSet(vint, 1, bits)
		tt.VarIntSet(vint, 0, bits)
		tt.VarIntSet(vint, 2, bits)
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result %v", bits, b)
		}
		// First, apply not first time.
		if err := vint.Not(1); err != nil {
			t.Fatalf("not error %v is not expected on %v", err, bits)
		}
		b = tt.VarIntGet(vint, 1)
		if b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result not %v", bits, b)
		}
		// Second, apply not second time.
		if err := vint.Not(1); err != nil {
			t.Fatalf("not error %v is not expected on %v", err, bits)
		}
		b = tt.VarIntGet(vint, 1)
		if !b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result not %v", bits, b)
		}
		// Third, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bits)
		tt.VarIntEqual(vint, 2, bits)
	})
}

func FuzzVarIntAnd(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit and and compare to
		// calculated bit and of original - random bits.
		bitsOrig := tt.NewBitsB62(b62)
		bitsRnd := tt.NewBitsRand(bitsOrig.Bits(), rnd)
		bigOrig, bigRnd := bitsOrig.BigInt(), bitsRnd.BigInt()
		bigAnd := big.NewInt(0).And(bigOrig, bigRnd)
		bitsAnd := tt.NewBitsBigInt(bigAnd)
		// Fix the cardinarity for add bits.
		bitsAnd = tt.NewBits(bitsOrig.Bits(), bitsAnd.Bytes())
		vint := tt.NewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(vint, 1, bitsOrig)
		tt.VarIntSet(vint, 0, bitsOrig)
		tt.VarIntSet(vint, 2, bitsOrig)
		if err := vint.And(1, bitsRnd); err != nil {
			t.Fatalf("and error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bitsAnd)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitsAnd) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsAnd, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bitsOrig)
		tt.VarIntEqual(vint, 2, bitsOrig)
	})
}

func FuzzVarIntOr(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit or and compare to
		// calculated bit or of original - random bits.
		bitsOrig := tt.NewBitsB62(b62)
		bitsRnd := tt.NewBitsRand(bitsOrig.Bits(), rnd)
		bigOrig, bigRnd := bitsOrig.BigInt(), bitsRnd.BigInt()
		bigOr := big.NewInt(0).Or(bigOrig, bigRnd)
		bitsOr := tt.NewBitsBigInt(bigOr)
		// Fix the cardinarity for or bits.
		bitsOr = tt.NewBits(bitsOrig.Bits(), bitsOr.Bytes())
		vint := tt.NewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(vint, 1, bitsOrig)
		tt.VarIntSet(vint, 0, bitsOrig)
		tt.VarIntSet(vint, 2, bitsOrig)
		if err := vint.Or(1, bitsRnd); err != nil {
			t.Fatalf("or error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bitsOr)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitsOr) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsOr, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bitsOrig)
		tt.VarIntEqual(vint, 2, bitsOrig)
	})
}

func FuzzVarIntXor(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit xor and compare to
		// calculated bit xor of original - random bits.
		bitsOrig := tt.NewBitsB62(b62)
		bitsRnd := tt.NewBitsRand(bitsOrig.Bits(), rnd)
		bigOrig, bigRnd := bitsOrig.BigInt(), bitsRnd.BigInt()
		bigXor := big.NewInt(0).Xor(bigOrig, bigRnd)
		bitsXor := tt.NewBitsBigInt(bigXor)
		// Fix the cardinarity for xor bits.
		bitsXor = tt.NewBits(bitsOrig.Bits(), bitsXor.Bytes())
		vint := tt.NewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and and random bits.
		tt.VarIntSet(vint, 1, bitsOrig)
		tt.VarIntSet(vint, 0, bitsOrig)
		tt.VarIntSet(vint, 2, bitsOrig)
		if err := vint.Xor(1, bitsRnd); err != nil {
			t.Fatalf("xor error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bitsXor)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitsXor) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsXor, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bitsOrig)
		tt.VarIntEqual(vint, 2, bitsOrig)
	})
}

func FuzzVarIntRsh(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and bootstrap big int,
		// shift them both bits and bigint to the right [0, bits+1].
		// Finaly, compare calculated bit shifts with oriranal bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), rnd.Int()%(bits.Bits()+1)
		big = big.Rsh(big, uint(n))
		// Fix the cardinarity for sub bits.
		bitssh := tt.NewBitsBigInt(big)
		bitssh = tt.NewBits(bits.Bits(), bitssh.Bytes())
		vint := tt.NewVarInt(bits.Bits(), l)
		// First, set original bits.
		tt.VarIntSet(vint, 1, bits)
		tt.VarIntSet(vint, 0, bits)
		tt.VarIntSet(vint, 2, bits)
		// Then shift bits to the right.
		if err := vint.Rsh(1, n); err != nil {
			t.Fatalf("rsh error %v is not expected on %v with %v", err, bits, n)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitssh) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitssh, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bits)
		tt.VarIntEqual(vint, 2, bits)
	})
}

func FuzzVarIntLsh(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t}
		// Initialize fuzz original bits and bootstrap big int,
		// shift them both bits and bigint to the left [0, bits+1].
		// Finaly, compare calculated bit shifts with oriranal bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), rnd.Int()%(bits.Bits()+1)
		big = big.Lsh(big, uint(n))
		// Fix the cardinarity for sub bits.
		bitssh := tt.NewBitsBigInt(big)
		bitssh = tt.NewBits(bits.Bits(), bitssh.Bytes())
		vint := tt.NewVarInt(bits.Bits(), l)
		// First, set original bits.
		tt.VarIntSet(vint, 1, bits)
		tt.VarIntSet(vint, 0, bits)
		tt.VarIntSet(vint, 2, bits)
		// Then shift bits to the left.
		if err := vint.Lsh(1, n); err != nil {
			t.Fatalf("lsh error %v is not expected on %v with %v", err, bits, n)
		}
		b := tt.VarIntGet(vint, 1)
		if !b.Equal(bitssh) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitssh, b)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(vint, 0, bits)
		tt.VarIntEqual(vint, 2, bits)
	})
}
