package varint

type Sortable struct {
	vint VarInt
	bits Bits
}

func (s Sortable) Len() int {
	_, l := s.vint.Length()
	return l
}

func (s Sortable) Less(i, j int) bool {
	_ = s.vint.Get(j, s.bits)
	r, _ := s.vint.Cmp(i, s.bits)
	return r == -1
}

func (s Sortable) Swap(i, j int) {
	_ = s.vint.Get(j, s.bits)
	_ = s.vint.GetSet(i, s.bits)
	_ = s.vint.GetSet(j, s.bits)
}
