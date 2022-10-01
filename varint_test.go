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

func mustNewVarInt(bits, length int) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		panic(err)
	}
	return vint
}

func mustNewBits(bsize int, bits []uint) Bits {
	b, err := NewBits(bsize, bits)
	if err != nil {
		panic(err)
	}
	return b
}

func mustNewBitsBigInt(i *big.Int) Bits {
	b, err := NewBitsBigInt(i)
	if err != nil {
		panic(err)
	}
	return b
}

func mustVarIntGet(vint VarInt, i int) Bits {
	b := mustNewBits(int(vint[0]), nil)
	if err := vint.Get(i, b); err != nil {
		panic(err)
	}
	return b
}

func mustVarIntSet(vint VarInt, i int, b Bits) {
	err := vint.Set(i, b)
	if err != nil {
		panic(err)
	}
}

func mustVarIntEqualZero(vint VarInt, i int) {
	b := mustVarIntGet(vint, i)
	if !b.Equal(mustNewBits(b.Bits(), []uint{0x0})) {
		panic("not equal to zero")
	}
}

func BenchmarkAddGetVarIntVSSlice(b *testing.B) {
	const size = 100000000
	b.Run("Benchmark VarInt Add/Get", func(b *testing.B) {
		m := mallocated(func() {
			vint := mustNewVarInt(4, size)
			bits, tmp := mustNewBits(4, []uint{10}), mustNewBits(4, nil)
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

func FuzzVarIntSetGet(f *testing.F) {
	const l = 10
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		bits, err := NewBitsString(b62, 62)
		if err != nil || bits == nil {
			return
		}
		vint := mustNewVarInt(bits.Bits(), l)
		for i := 0; i < l; i++ {
			if err := vint.Set(rnd.Int()%l, bits); err != nil {
				t.Fatalf("set error %v is not expected on %v", err, bits)
			}
		}
		for i := 0; i < l; i++ {
			b := mustNewBits(bits.Bits(), nil)
			if err := vint.Get(i, b); err != nil {
				t.Fatalf("get error %v is not expected on %v", err, bits)
			}
			// Equals to bits or zero.
			if zero := mustNewBits(b.Bits(), []uint{0x0}); !(b.Equal(zero) || b.Equal(bits)) {
				t.Fatalf("expected result %v doesn't match actual result %v", bits, b)
			}
		}
	})
}

func FuzzVarIntAdd(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated sum of original + random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigSum := big.NewInt(0).Add(bigOrig, bigRnd)
		// Skip cases when big sum overloads original bits size,
		// because it will inevitably produce ErrorBitsOperationOverflow.
		if bigSum.BitLen() > bitsOrig.Bits() {
			return
		}
		bitsSum := mustNewBitsBigInt(bigSum)
		bitsRnd := mustNewBitsBigInt(bigRnd)
		// Fix the cardinarity for random bits.
		bitsRnd[0] = uint(bitsOrig.Bits())
		vint := mustNewVarInt(bitsOrig.Bits(), l)
		// First, add original bits to zeroed vint.
		if err := vint.Add(1, bitsOrig); err != nil {
			t.Fatalf("add error %v is not expected on %v", err, bitsOrig)
		}
		b := mustVarIntGet(vint, 1)
		if !b.Equal(bitsOrig) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsOrig, b)
		}
		// Second, add random bits to the same vint.
		if err := vint.Add(1, bitsRnd); err != nil {
			t.Fatalf("add error %v is not expected on %v with %v", err, bitsOrig, bitsRnd)
		}
		b = mustVarIntGet(vint, 1)
		if !b.Equal(bitsSum) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsSum, b)
		}
		// Third, check that others bits were not affected.
		mustVarIntEqualZero(vint, 0)
		mustVarIntEqualZero(vint, 2)
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints sub and compare to
		// calculated sub of original - random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigSub := big.NewInt(0).Sub(bigOrig, bigRnd)
		bitsSub := mustNewBitsBigInt(bigSub)
		// Fix the cardinarity for sub bits.
		bitsSub = mustNewBits(bitsOrig.Bits(), bitsSub.Bytes())
		bitsRnd := mustNewBitsBigInt(bigRnd)
		if bitsRnd == nil {
			return
		}
		// Fix the cardinarity for random bits.
		bitsRnd = mustNewBits(bigOrig.BitLen(), bitsRnd.Bytes())
		vint := mustNewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and sub random bits.
		mustVarIntSet(vint, 1, bitsOrig)
		if err := vint.Sub(1, bitsRnd); err != nil {
			t.Fatalf("sub error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bigSub)
		}
		b := mustVarIntGet(vint, 1)
		if !b.Equal(bitsSub) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsSub, b)
		}
		// Second, check that others bits were not affected.
		mustVarIntEqualZero(vint, 0)
		mustVarIntEqualZero(vint, 2)
	})
}

func FuzzVarIntNot(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and
		// apply bit not two times. First result
		// should be different from original bits.
		// And second result should match original bits.
		bits, err := NewBitsString(b62, 62)
		if err != nil || bits == nil {
			return
		}
		vint := mustNewVarInt(bits.Bits(), l)
		mustVarIntSet(vint, 1, bits)
		b := mustVarIntGet(vint, 1)
		if !b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result %v", bits, b)
		}
		// First, apply not first time.
		if err := vint.Not(1); err != nil {
			t.Fatalf("not error %v is not expected on %v", err, bits)
		}
		b = mustVarIntGet(vint, 1)
		if b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result not %v", bits, b)
		}
		// Second, apply not second time.
		if err := vint.Not(1); err != nil {
			t.Fatalf("not error %v is not expected on %v", err, bits)
		}
		b = mustVarIntGet(vint, 1)
		if !b.Equal(bits) {
			t.Fatalf("expected result %v doesn't match actual result not %v", bits, b)
		}
		// Third, check that others bits were not affected.
		mustVarIntEqualZero(vint, 0)
		mustVarIntEqualZero(vint, 2)
	})
}

func FuzzVarIntAnd(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit and and compare to
		// calculated bit and of original - random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigAnd := big.NewInt(0).And(bigOrig, bigRnd)
		bitsAnd := mustNewBitsBigInt(bigAnd)
		// Fix the cardinarity for sub bits.
		bitsAnd = mustNewBits(bitsOrig.Bits(), bitsAnd.Bytes())
		bitsRnd := mustNewBitsBigInt(bigRnd)
		if bitsRnd == nil {
			return
		}
		// Fix the cardinarity for random bits.
		bitsRnd = mustNewBits(bigOrig.BitLen(), bitsRnd.Bytes())
		vint := mustNewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and and random bits.
		mustVarIntSet(vint, 1, bitsOrig)
		if err := vint.And(1, bitsRnd); err != nil {
			t.Fatalf("and error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bitsAnd)
		}
		b := mustVarIntGet(vint, 1)
		if !b.Equal(bitsAnd) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsAnd, b)
		}
		// Second, check that others bits were not affected.
		mustVarIntEqualZero(vint, 0)
		mustVarIntEqualZero(vint, 2)
	})
}

func FuzzVarIntOr(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit or and compare to
		// calculated bit or of original - random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigAnd := big.NewInt(0).Or(bigOrig, bigRnd)
		bitsAnd := mustNewBitsBigInt(bigAnd)
		// Fix the cardinarity for sub bits.
		bitsAnd = mustNewBits(bitsOrig.Bits(), bitsAnd.Bytes())
		bitsRnd := mustNewBitsBigInt(bigRnd)
		if bitsRnd == nil {
			return
		}
		// Fix the cardinarity for random bits.
		bitsRnd = mustNewBits(bigOrig.BitLen(), bitsRnd.Bytes())
		vint := mustNewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and and random bits.
		mustVarIntSet(vint, 1, bitsOrig)
		if err := vint.Or(1, bitsRnd); err != nil {
			t.Fatalf("or error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bitsAnd)
		}
		b := mustVarIntGet(vint, 1)
		if !b.Equal(bitsAnd) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsAnd, b)
		}
		// Second, check that others bits were not affected.
		mustVarIntEqualZero(vint, 0)
		mustVarIntEqualZero(vint, 2)
	})
}

func FuzzVarIntXor(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit xor and compare to
		// calculated bit xor of original - random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigAnd := big.NewInt(0).Xor(bigOrig, bigRnd)
		bitsAnd := mustNewBitsBigInt(bigAnd)
		// Fix the cardinarity for sub bits.
		bitsAnd = mustNewBits(bitsOrig.Bits(), bitsAnd.Bytes())
		bitsRnd := mustNewBitsBigInt(bigRnd)
		if bitsRnd == nil {
			return
		}
		// Fix the cardinarity for random bits.
		bitsRnd = mustNewBits(bigOrig.BitLen(), bitsRnd.Bytes())
		vint := mustNewVarInt(bitsOrig.Bits(), l)
		// First, set original bits and and random bits.
		mustVarIntSet(vint, 1, bitsOrig)
		if err := vint.Xor(1, bitsRnd); err != nil {
			t.Fatalf("xor error %v is not expected on %v with %v : %v", err, bitsOrig, bitsRnd, bitsAnd)
		}
		b := mustVarIntGet(vint, 1)
		if !b.Equal(bitsAnd) {
			t.Fatalf("expected result %v doesn't match actual result %v", bitsAnd, b)
		}
		// Second, check that others bits were not affected.
		mustVarIntEqualZero(vint, 0)
		mustVarIntEqualZero(vint, 2)
	})
}
