package varint

// sortable implements sort.Interface on top of VarInt.
// VarInt doesn't implement sort.Interface directly by choice
// to make it more consistent and ergonomic.
type sortable struct {
	vint VarInt
	bits Bits
}

func (s sortable) Len() int {
	return Len(s.vint)
}

func (s sortable) Less(i, j int) bool {
	_ = s.vint.Get(j, s.bits)
	less := s.vint.Sub(i, s.bits) == ErrorSubtractionUnderflow
	_ = s.vint.Add(i, s.bits)
	return less
}

func (s sortable) Swap(i, j int) {
	_ = s.vint.Get(j, s.bits)
	_ = s.vint.GetSet(i, s.bits)
	_ = s.vint.Set(j, s.bits)
}
