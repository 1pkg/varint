package varint

import (
	"math/big"
	"math/rand"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
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

type thelper struct {
	*testing.T
	VarInt
}

func (t *thelper) NewVarInt(bits, length int) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		t.Fatal(err)
	}
	t.VarInt = vint
	return vint
}

func (t thelper) NewBits(bsize int, bits []uint) Bits {
	b, err := NewBits(bsize, bits)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t thelper) NewBitsZero(bsize int) Bits {
	return t.NewBits(bsize, []uint{0x0})
}

func (t thelper) NewBitsUint(n uint) Bits {
	b, err := NewBitsUint(n)
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
	if bits.BitLen() == 0 {
		return t.NewBits(8, []uint{0xFF})
	}
	return bits
}

func (t thelper) VarIntGet(i int) Bits {
	b := t.NewBits(t.BitLen(), nil)
	if err := t.Get(i, b); err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
	return b
}

func (t thelper) VarIntSet(i int, b Bits) {
	err := t.Set(i, b)
	if err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
}

func (t thelper) VarIntEqual(i int, bits ...Bits) {
	for _, b := range bits {
		cmp, err := t.Cmp(i, b)
		if err != nil {
			debug.PrintStack()
			t.Fatal(err)
		}
		if cmp == 0 {
			return
		}
	}
	b := t.VarIntGet(i)
	debug.PrintStack()
	t.Fatalf("bits %v are not equal %v", bits, b)
}

func (t thelper) VarIntNotEqual(i int, bits ...Bits) {
	for _, b := range bits {
		cmp, err := t.Cmp(i, b)
		if err != nil {
			debug.PrintStack()
			t.Fatal(err)
		}
		if cmp != 0 {
			return
		}
	}
	b := t.VarIntGet(i)
	debug.PrintStack()
	t.Fatalf("bits %v are equal %v", bits, b)
}

func (t thelper) NoError(err error, exceptions ...error) bool {
	if err != nil {
		for _, except := range exceptions {
			if err == except {
				return true
			}
		}
		debug.PrintStack()
		t.Fatal(err)
		return true
	}
	return false
}

func (t thelper) Equal(i, j interface{}) {
	if !reflect.DeepEqual(i, j) {
		debug.PrintStack()
		t.Fatalf("values %v are not equal %v", i, j)
	}
}

func BenchmarkAddGetVarIntvsSlice(b *testing.B) {
	const len = 100000000
	b.Run("Benchmark VarInt Add/Get", func(b *testing.B) {
		m := mallocated(func() {
			vint, _ := NewVarInt(4, len)
			bits, _ := NewBits(4, []uint{10})
			tmp, _ := NewBits(4, nil)
			for n := 0; n < b.N; n++ {
				_ = vint.Add(n%len, bits)
				_ = vint.Get(n%len, tmp)
			}
		})
		b.ReportMetric(m, "M_allocated")
	})
	b.Run("Benchmark Slice Add/Get", func(b *testing.B) {
		m := mallocated(func() {
			slice := make([]uint8, len)
			for n := 0; n < b.N; n++ {
				slice[n%len] += 10
				_ = slice[n%len]
			}
		})
		b.ReportMetric(m, "M_allocated")
	})
}

func BenchmarkVarIntSort(b *testing.B) {
	const len = 100
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	vint, _ := NewVarInt(len, len)
	for i := 0; i < len; i++ {
		bits, _ := NewBitsRand(len, rnd)
		_ = vint.Set(i, bits)
	}
	b.ResetTimer()
	sort.Sort(vint.Sortable())
}

func FuzzVarIntSetAndGet(f *testing.F) {
	const l = 10
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits then randomly set
		// some vint numbers to fuzz original bits. Finally,
		// verify that all numbers in vint are either equal to
		// fuzz original bits or equal to zero.
		bits := tt.NewBitsB62(b62)
		_ = tt.NewVarInt(bits.BitLen(), l)
		for i := 0; i < l; i++ {
			n := rnd.Int() % l
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Swap original bits and
		// random bits two times so result should be the same.
		bits := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(bits.BitLen(), rnd)
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, result of ints comparison should match
		// vint comparison result.
		bits := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(bits.BitLen(), rnd)
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated sum of original + random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen(), rnd)
		bsum := tt.NewBitsBigInt(big.NewInt(0).Add(borig.BigInt(), brnd.BigInt()))
		vint := tt.NewVarInt(borig.BitLen(), l)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		// First, add original bits to zeroed vint.
		tt.NoError(vint.Add(1, borig))
		tt.VarIntEqual(1, borig)
		// Second, add random bits to the same vint.
		// Allow overflow error, but don't check bit equality then.
		if !tt.NoError(vint.Add(1, brnd), ErrorBitsOperationOverflow{Bits: borig.BitLen()}) {
			tt.VarIntEqual(1, bsum)
		}
		// Third, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints sub and compare to
		// calculated sub of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen(), rnd)
		bsub := tt.NewBitsBigInt(big.NewInt(0).Sub(borig.BigInt(), brnd.BigInt()))
		// Fix the cardinarity for sub bits.
		bsub = tt.NewBits(borig.BitLen(), bsub.Bytes())
		vint := tt.NewVarInt(borig.BitLen(), l)
		// First, set original bits and sub random bits.
		tt.VarIntSet(1, borig)
		tt.VarIntSet(0, borig)
		tt.VarIntSet(2, borig)
		// Allow underflow error, but don't check bit equality then.
		if !tt.NoError(vint.Sub(1, brnd), ErrorBitsOperationUnderflow{Bits: borig.BitLen()}) {
			tt.VarIntEqual(1, bsub)
		}
		// Second, check that others bits were not affected.
		tt.VarIntEqual(0, borig)
		tt.VarIntEqual(2, borig)
	})
}

func FuzzVarIntNot(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit and and compare to
		// calculated bit and of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen(), rnd)
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit or and compare to
		// calculated bit or of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen(), rnd)
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints bit xor and compare to
		// calculated bit xor of original - random bits.
		borig := tt.NewBitsB62(b62)
		brnd := tt.NewBitsRand(borig.BitLen(), rnd)
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and bootstrap big int,
		// shift them both bits and bigint to the right [0, bits+1].
		// Finaly, compare calculated bit shifts with oriranal bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), rnd.Int()%(bits.BitLen()+1)
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
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		tt := thelper{t, nil}
		// Initialize fuzz original bits and bootstrap big int,
		// shift them both bits and bigint to the left [0, bits+1].
		// Finaly, compare calculated bit shifts with oriranal bits.
		bits := tt.NewBitsB62(b62)
		big, n := bits.BigInt(), rnd.Int()%(bits.BitLen()+1)
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
