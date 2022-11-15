package varint

import (
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// rnd contains internal random generator used exclusively in tests.
var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

// test runs the provided named test function, by
// wrapping t.Run with internal test helper struct h.
func test(tname string, t *testing.T, ff func(h h)) {
	t.Run(tname, func(t *testing.T) {
		ff(h{T: t})
	})
}

// fuzz seeds and runs the provided named fuzz function, by
// wrapping f.Fuzz with internal test helper struct h.
func fuzz(f *testing.F, ff func(h h, b62 string)) {
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
	f.Fuzz(func(t *testing.T, s string) {
		ff(h{T: t}, s)
	})
}

// fuzz runs the provided named bench function, it
// also reports total allocated megabytes as 'M_allocated'.
func bench(bname string, b *testing.B, f func(b *testing.B)) {
	const k = 1024
	b.Run(bname, func(b *testing.B) {
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		f(b)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		m := float64(after.TotalAlloc-before.TotalAlloc) / k / k
		b.ReportMetric(m, "allocs/MB")
	})
}

// h is a test helper type that hosts array of operation and
// assertion methods for VarInt and Bits type. It's used in
// conjunction with test and fuzz functions.
type h struct {
	*testing.T
	VarInt
}

func (h h) NewBitsB62(b62 string) Bits {
	h.Helper()
	bits := NewBitsString(b62, 62)
	if bits.BitLen() == 0 {
		h.SkipNow()
	}
	return bits
}

func (h h) NewBits2B62(b62 string) (Bits, Bits) {
	h.Helper()
	rb62 := []rune(b62)
	for i, j := 0, len(rb62)-1; i <= j; i, j = i+1, j-1 {
		rb62[i], rb62[j] = rb62[j], rb62[i]
	}
	rb62s := string(rb62)
	var b1, b2 Bits
	// It should always return greater value first.
	if strings.Compare(b62, rb62s) < 0 {
		b1, b2 = h.NewBitsB62(rb62s), h.NewBitsB62(b62)
	} else {
		b1, b2 = h.NewBitsB62(b62), h.NewBitsB62(rb62s)
	}
	return b1, NewBitsBits(b1.BitLen(), b2)
}

func (h *h) NewVarInt(bits, length int) VarInt {
	h.Helper()
	vint, err := NewVarInt(bits, length)
	// Ignore known len warnings.
	if err != nil &&
		err != ErrorBitLengthIsNotEfficient &&
		err != ErrorLengthIsNotEfficient {
		h.Fatal(err)
	}
	h.VarInt = vint
	return vint
}

func (h h) VarIntGet(i int) Bits {
	h.Helper()
	b := NewBits(BitLen(h.VarInt), nil)
	if err := h.Get(i, b); err != nil {
		h.Fatal(err)
	}
	return b
}

func (h h) VarIntSet(i int, b Bits) {
	h.Helper()
	err := h.Set(i, b)
	if err != nil {
		h.Fatal(err)
	}
}

func (h h) VarIntEqual(i int, bits Bits) {
	h.Helper()
	b := h.VarIntGet(i)
	if Compare(b, bits) != 0 {
		h.Fatalf("bits %s are not equal %s", bits.String(), b.String())
	}
}

func (h h) VarIntNotEqual(i int, bits Bits) {
	h.Helper()
	b := h.VarIntGet(i)
	if Compare(b, bits) == 0 {
		h.Fatalf("bits %s are equal %s", bits.String(), b.String())
	}
}

func (h h) NoError(err error, exceptions ...error) bool {
	h.Helper()
	if err != nil {
		for _, except := range exceptions {
			if err == except {
				return true
			}
		}
		h.Fatal(err)
	}
	return false
}

func (h h) Equal(i, j interface{}) {
	h.Helper()
	if !reflect.DeepEqual(i, j) {
		h.Fatalf("values %v are not equal %v", i, j)
	}
}
