package varint

import (
	"os"
	"testing"
)

func TestVarIntEncodingRand(t *testing.T) {
	const l = 10
	for i := 0; i < l*l; i++ {
		tt := newtt(t)
		blen := tt.Int() % (l * l * l)
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
	}
}
