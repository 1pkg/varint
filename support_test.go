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
	tt := newtt(t)
	vint := tt.NewVarInt(6, 1)
	tt.NoError(vint.Add(0, NewBitsRand(6, tt.Rand)))
	tt.NoError(vint.Mul(0, NewBitsRand(6, tt.Rand)), ErrorMultiplicationOverflow{BitLen: 6})
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
			vint: tt.NewVarInt(5, 10),
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
		t.Run(tname, func(t *testing.T) {
			tt := newtt(t)
			tt.Equal(tcase.bvar, bvar(tcase.vint, true))
			tt.Equal(tcase.len, Len(tcase.vint))
			tt.Equal(tcase.blen, BitLen(tcase.vint))
		})
	}
}

func TestSortable(t *testing.T) {
	t.Run("Rand", func(t *testing.T) {
		// Fill a varint with 100 random bits,
		// sort them in ascending order and verify
		// that order is correct using cmp. Then
		// sort them again in descending order and
		// verify that order is correct using cmp.
		const len = 100
		tt := newtt(t)
		vint := tt.NewVarInt(len, len)
		for i := 0; i < len; i++ {
			bits := NewBitsRand(len, tt.Rand)
			tt.VarIntSet(i, bits)
		}
		sort.Sort(Sortable(vint))
		for i := 0; i < len-1; i++ {
			// Numbers could be equal too so check for >= 0.
			tt.Equal(tt.VarIntCmp(i+1, tt.VarIntGet(i)) >= 0, true)
		}
		sort.Sort(sort.Reverse(Sortable(vint)))
		for i := 0; i < len-1; i++ {
			// Numbers could be equal too so check for <= 0.
			tt.Equal(tt.VarIntCmp(i+1, tt.VarIntGet(i)) <= 0, true)
		}
	})
	t.Run("Error", func(t *testing.T) {
		// Should not panic for nil varint.
		sort.Sort(Sortable(nil))
	})
}

func TestEncodeDecode(t *testing.T) {
	t.Run("Rand", func(t *testing.T) {
		// Fill a varint with 100 random bits,
		// encode them into the reader. Then
		// flush it to the temporary file,
		// close the file, then open and again to
		// read it into second varint copt. Finally,
		// compare two varints for equallity.
		const l = 100
		tt := newtt(t)
		blen := tt.Int()%l + 1
		vint := tt.NewVarInt(blen, l)
		for i := 0; i < l; i++ {
			tt.VarIntSet(i, NewBitsRand(blen, tt.Rand))
		}
		r := Encode(vint)
		f, err := os.Create("encoding.out")
		tt.NoError(err)
		defer os.Remove(f.Name())
		_, err = f.ReadFrom(r)
		tt.NoError(err)
		tt.NoError(f.Close())
		f, err = os.Open(f.Name())
		tt.NoError(err)
		nvint, err := Decode(f)
		tt.NoError(err)
		for i := 0; i < l; i++ {
			tt.VarInt = vint
			bits := tt.VarIntGet(i)
			tt.VarInt = nvint
			tt.VarIntEqual(i, bits)
		}
		tt.NoError(f.Close())
	})
	t.Run("Error", func(t *testing.T) {
		// Verify that encode and decode produces expected
		// errors for broken input reader.
		tt := newtt(t)
		vint := tt.NewVarInt(1, 1)
		r := Encode(vint)
		tt.NoError(r.Close())
		ioerr := errors.New("test")
		_, err := Decode(io.NopCloser(iotest.ErrReader(ioerr)))
		tt.Equal(err, ioerr)
		_, err = Decode(io.NopCloser(strings.NewReader("foobar")))
		tt.Equal(err, ErrorReaderIsNotDecodable{})

	})
}
