package varint

import (
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
)

func TestSupport(t *testing.T) {
	test("BitLenVar", t, func(th h) {
		vint0 := th.NewVarInt(5, 10)
		vint := th.NewVarInt(6, 1)
		_ = vint.Add(0, NewBitsRand(6, rnd))
		_ = vint.Mul(0, NewBitsRand(6, rnd))
		table := map[string]struct {
			vint VarInt
			bvar Bits
			len  int
			blen int
		}{
			"nil varint should produce expected empty results": {
				vint: nil,
				bvar: nil,
				len:  0,
				blen: 0,
			},
			"empty varint should produce expected results": {
				vint: vint0,
				bvar: NewBits(5, nil),
				len:  10,
				blen: 5,
			},
			"not empty varint should produce expected results": {
				vint: vint,
				bvar: NewBits(6, nil),
				len:  1,
				blen: 6,
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				h.Equal(tcase.bvar, bvar(tcase.vint, true))
				h.Equal(tcase.len, Len(tcase.vint))
				h.Equal(tcase.blen, BitLen(tcase.vint))
			})
		}
	})
	test("Compare", t, func(th h) {
		table := map[string]struct {
			abits Bits
			bbits Bits
			cmp   int
		}{
			"nil bits should be equal": {
				abits: nil,
				bbits: nil,
				cmp:   0,
			},
			"empty bits should be equal": {
				abits: NewBits(0, nil),
				bbits: NewBits(0, nil),
				cmp:   0,
			},
			"empty bits with different bit len size should not be equal": {
				abits: NewBits(0, nil),
				bbits: NewBits(1, nil),
				cmp:   -1,
			},
			"bits on the left should be bigger": {
				abits: NewBits(100, []uint{0x1111111111111111, 0x99}),
				bbits: NewBits(100, []uint{0x1111111111111111, 0x11}),
				cmp:   1,
			},
			"bits on the left should be smaller": {
				abits: NewBits(100, []uint{0x1111111111111111, 0x99}),
				bbits: NewBits(100, []uint{0x1111111111111111, 0x100}),
				cmp:   -1,
			},
			"not empty bits with same bit len size should be equal": {
				abits: NewBits(100, []uint{0x1111111111111111, 0x100}),
				bbits: NewBits(100, []uint{0x1111111111111111, 0x100}),
				cmp:   0,
			},
			"not empty bits with different bit len size should be equal": {
				abits: NewBits(105, []uint{0x1111111111111111, 0x100}),
				bbits: NewBits(100, []uint{0x1111111111111111, 0x100}),
				cmp:   1,
			},
		}
		for tname, tcase := range table {
			test(tname, th.T, func(h h) {
				h.Equal(Compare(tcase.abits, tcase.bbits), tcase.cmp)
			})
		}
	})
}

func TestSortable(t *testing.T) {
	test("Rand", t, func(h h) {
		// Fill a varint with 100 random bits,
		// sort them in ascending order and verify
		// that order is correct using cmp. Then
		// sort them again in descending order and
		// verify that order is correct using cmp.
		const len = 100
		vint := h.NewVarInt(len, len)
		for i := 0; i < len; i++ {
			bits := NewBitsRand(len, rnd)
			h.VarIntSet(i, bits)
		}
		sort.Sort(Sortable(vint))
		for i, j := 0, 1; i < len-1; i, j = i+1, j+1 {
			bi, bj := h.VarIntGet(i), h.VarIntGet(j)
			// Integers could be equal too.
			h.Equal(Compare(bi, bj) <= 0, true)
		}
		sort.Sort(sort.Reverse(Sortable(vint)))
		for i, j := 0, 1; i < len-1; i, j = i+1, j+1 {
			bi, bj := h.VarIntGet(i), h.VarIntGet(j)
			// Integers could be equal too.
			h.Equal(Compare(bi, bj) >= 0, true)
		}
	})
	test("Error", t, func(h h) {
		// Should not panic for nil varint.
		sort.Sort(Sortable(nil))
	})
}

func TestEncodeDecode(t *testing.T) {
	test("Rand", t, func(h h) {
		// Fill a varint with 100 random bits,
		// encode them into the reader. Then
		// flush it to the temporary file,
		// close the file, then open and again to
		// read it into second varint copt. Finally,
		// compare two varints for equallity.
		const l = 100
		blen := rnd.Int()%l + 1
		vint := h.NewVarInt(blen, l)
		vintd := h.NewVarInt(blen, l)
		for i := 0; i < l; i++ {
			h.VarIntSet(i, NewBitsRand(blen, rnd))
		}
		r := Encode(vint)
		f, err := os.Create("encoding.out")
		h.NoError(err)
		defer os.Remove(f.Name())
		_, err = f.ReadFrom(r)
		h.NoError(err)
		h.NoError(f.Close())
		f, err = os.Open(f.Name())
		h.NoError(err)
		h.NoError(Decode(f, vintd))
		for i := 0; i < l; i++ {
			h.VarInt = vint
			bits := h.VarIntGet(i)
			h.VarInt = vintd
			h.VarIntEqual(i, bits)
		}
		h.NoError(f.Close())
	})
	test("Error", t, func(h h) {
		// Verify that encode and decode produces expected
		// errors for broken input reader.
		vint := h.NewVarInt(1, 1)
		vintd := h.NewVarInt(1, 1)
		r := Encode(vint)
		h.NoError(r.Close())
		ioerr := errors.New("test")
		err := Decode(io.NopCloser(iotest.ErrReader(ioerr)), vintd)
		h.Equal(err, ioerr)
		err = Decode(io.NopCloser(strings.NewReader("foobar")), vintd)
		h.Equal(err, ErrorReaderIsNotDecodable)
		err = Decode(Encode(vint), nil)
		h.Equal(err, ErrorVarIntIsInvalid)
	})
}

func BenchmarkVarIntSupport(b *testing.B) {
	// Allocate the actual numbers before the bench.
	const len, blen = 1000000, 100
	vint, _ := NewVarInt(blen, len)
	vintd, _ := NewVarInt(blen, len)
	for i := 0; i < len; i++ {
		bits := NewBitsRand(blen, rnd)
		_ = vint.Set(i, bits)
	}
	bits := NewBits(blen, nil)
	bench("Benchmark VarInt Sort", b, func(b *testing.B) {
		// Shuffle before the sorting and reset timer.
		for i := 0; i < len; i++ {
			j := rnd.Int() % len
			_ = vint.Get(i, bits)
			_ = vint.GetSet(j, bits)
			_ = vint.Set(i, bits)
		}
		b.ResetTimer()
		sort.Sort(Sortable(vint))
	})
	bench("Benchmark VarInt Encode", b, func(b *testing.B) {
		r := Encode(vint)
		_, _ = io.Copy(io.Discard, r)
	})
	bench("Benchmark VarInt Decode", b, func(b *testing.B) {
		_ = Decode(Encode(vint), vintd)
	})
}
