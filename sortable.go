package varint

import "sort"

type sortable struct {
	vint VarInt
	bits Bits
}

func Sortable(vint VarInt) sort.Interface {
	return sortable{vint: vint, bits: vint.varbits(true)}
}

func (s sortable) Len() int {
	return s.vint.Len()
}

func (s sortable) Less(i, j int) bool {
	_ = s.vint.Get(j, s.bits)
	r, _ := s.vint.Cmp(i, s.bits)
	return r == -1
}

func (s sortable) Swap(i, j int) {
	_ = s.vint.Get(j, s.bits)
	_ = s.vint.GetSet(i, s.bits)
	_ = s.vint.GetSet(j, s.bits)
}
