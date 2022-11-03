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
	vint0, _ := NewVarInt(5, 10)
	vint, _ := NewVarInt(6, 1)
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
		test(tname, t, func(h h) {
			h.Equal(tcase.bvar, bvar(tcase.vint, true))
			h.Equal(tcase.len, Len(tcase.vint))
			h.Equal(tcase.blen, BitLen(tcase.vint))
		})
	}
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
		for i := 0; i < len-1; i++ {
			// Numbers could be equal too so check for >= 0.
			h.Equal(h.VarIntCmp(i+1, h.VarIntGet(i)) >= 0, true)
		}
		sort.Sort(sort.Reverse(Sortable(vint)))
		for i := 0; i < len-1; i++ {
			// Numbers could be equal too so check for <= 0.
			h.Equal(h.VarIntCmp(i+1, h.VarIntGet(i)) <= 0, true)
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
		nvint, err := Decode(f)
		h.NoError(err)
		for i := 0; i < l; i++ {
			h.VarInt = vint
			bits := h.VarIntGet(i)
			h.VarInt = nvint
			h.VarIntEqual(i, bits)
		}
		h.NoError(f.Close())
	})
	test("Error", t, func(h h) {
		// Verify that encode and decode produces expected
		// errors for broken input reader.
		vint := h.NewVarInt(1, 1)
		r := Encode(vint)
		h.NoError(r.Close())
		ioerr := errors.New("test")
		_, err := Decode(io.NopCloser(iotest.ErrReader(ioerr)))
		h.Equal(err, ioerr)
		_, err = Decode(io.NopCloser(strings.NewReader("foobar")))
		h.Equal(err, ErrorReaderIsNotDecodable{})
	})
}
