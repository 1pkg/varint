package varint

import (
	"sort"
	"testing"
)

func TestVarIntSortable(t *testing.T) {
	const len = 100
	tt := newtt(t)
	vint := tt.NewVarInt(len, len)
	for i := 0; i < len; i++ {
		bits := tt.NewBitsRand(len)
		tt.VarIntSet(i, bits)
	}
	sort.Sort(Sortable(vint))
	for i := 0; i < len-1; i++ {
		tt.Equal(tt.VarIntCmp(i+1, tt.VarIntGet(i)), 1)
	}
}
