package varint

const wsize = 64

type VarInt []uint64

func NewVarInt(bits, length int) (VarInt, error) {
	if bits <= 0 {
		return nil, ErrorBitsIsNegative{Bits: bits}
	}
	if length <= 0 {
		return nil, ErrorLengthIsNegative{Length: length}
	}
	size := (bits*length+wsize-1)/wsize + 1
	vint := VarInt(make([]uint64, size))
	vint[0] = uint64(bits<<32 | length)
	return vint, nil
}

func (vint VarInt) AtBits(i int) (Bits, error) {
	// Check that non negative index was provided.
	if i < 0 {
		return nil, ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize := int(vint[0] >> 32)
	if l := int(int32(vint[0])); i >= l {
		return nil, ErrorIndexIsOutOfRange{Index: i, Length: l}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize-1
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifting to fix the uint64 result.
	lbshift, rbshift := bfrom-(low)*wsize, (hiw+1)*wsize-bto-1
	if low == hiw {
		// In case we operate in the same word
		// just shift all excess bits on the left and ride sides.
		return []uint64{vint[low] << lbshift >> (rbshift + lbshift)}, nil
	}
	// Preallocate a slice to fit all words and start traversal them in reverse order.
	result := make([]uint64, 0, hiw-low+1)
	// Iterate until we didn't reach low word
	// accumulate the combined word by shifting all excess bits on the left and ride sides.
	for k := hiw; k > low; k-- {
		result = append(result, (vint[k-1]<<(wsize-rbshift))|(vint[k]>>rbshift))
	}
	if wsize <= lbshift+rbshift {
		// In case leftover low + high bits fit in single uint64 word fix last word
		// first shift all excess bits on the left side
		// of the low word and then align it to the right side to fit the high word.
		// Then shift all excess bits on the right side of the high word and merge the intermidiate results.
		result[len(result)-1] = (vint[low] << lbshift >> (lbshift - (wsize - rbshift))) | (vint[low+1] >> rbshift)
	} else {
		// Otherwise we need to add a separate word for leftover low + high bits
		// first accumulate the combined word by shifting all excess bits on the left and ride sides.
		// Then for low word just shift all excess bits on the left side and ride side with delta.
		result = append(result, (vint[low] << lbshift >> (lbshift + rbshift)))
	}
	return result, nil
}

func (vint VarInt) AtUint(i int) (uint64, error) {
	// Check that non negative index was provided.
	if i < 0 {
		return 0, ErrorIndexIsNegative{Index: i}
	}
	// Check that resulting uint64 can hold full bits representation.
	bsize := int(vint[0] >> 32)
	if bsize > wsize {
		return 0, ErrorBitsUint64Oveflow{Bits: bsize}
	}
	// Check that requested index is inside varint range.
	if l := int(int32(vint[0])); i >= l {
		return 0, ErrorIndexIsOutOfRange{Index: i, Length: l}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize-1
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifting to fix the uint64 result.
	lbshift, rbshift := bfrom-(low)*wsize, (hiw+1)*wsize-bto-1
	if low == hiw {
		// In case we operate in the same word
		// just shift all excess bits on the left and ride sides.
		return vint[low] << lbshift >> (rbshift + lbshift), nil
	} else {
		// In case we operate in different words
		// first shift all excess bits on the left side
		// of the low word and then align it to the right side to fit the high word.
		// Then shift all excess bits on the right side of the high word and merge the intermidiate results.
		// As we operate on 64 bits maximum expression
		// 'lbshift - (wsize - rbshift)' should always stay positive.
		return (vint[low] << lbshift >> (lbshift - (wsize - rbshift))) | (vint[hiw] >> rbshift), nil
	}
}
