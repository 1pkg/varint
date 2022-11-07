package varint

type sortable struct {
	vint VarInt
	bits Bits
}

func (s sortable) Len() int {
	return Len(s.vint)
}

func (s sortable) Less(i, j int) bool {
	_ = s.vint.Get(i, s.bits)
	_ = s.vint.GetSet(j, s.bits)
	less := s.vint.Sub(i, s.bits) == ErrorSubtractionUnderflow{}
	_ = s.vint.GetSet(j, s.bits)
	_ = s.vint.Set(i, s.bits)
	return less
}

func (s sortable) Swap(i, j int) {
	_ = s.vint.Get(j, s.bits)
	_ = s.vint.GetSet(i, s.bits)
	_ = s.vint.Set(j, s.bits)
}
