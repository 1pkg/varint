package varint

import (
	"sort"
	"testing"
)

func TestVarIntSortableRand(t *testing.T) {
	const len = 100
	tt := newtt(t)
	vint := tt.NewVarInt(len, len)
	for i := 0; i < len; i++ {
		bits := NewBitsRand(len, tt.Rand)
		tt.VarIntSet(i, bits)
	}
	sort.Sort(Sortable(vint))
	for i := 0; i < len-1; i++ {
		tt.Equal(tt.VarIntCmp(i+1, tt.VarIntGet(i)), 1)
	}
}
