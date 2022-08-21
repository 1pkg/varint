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

func (vint VarInt) Length() (bits, length int) {
	return int(vint[0] >> 32), int(vint[0] << 32 >> 32)
}

func (vint VarInt) AtBits(i int) (Bits, error) {
	// Check that non negative index was provided.
	if i < 0 {
		return nil, ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize, lenght := vint.Length()
	if i >= lenght {
		return nil, ErrorIndexIsOutOfRange{Index: i, Length: lenght}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize, bsize*(i+1)-1+wsize
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifts to fix the uint64 result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Preallocate a slice to fit all words and start traversal them in reverse order.
	result := make([]uint64, 0, hiw-low+2)
	result = append(result, uint64(bsize))
	// Iterate from high to low word
	// accumulate the combined word by shifting
	// all excess bits on the left and ride sides.
	for k := hiw; k >= low; k-- {
		switch {
		// Special case, the point where low == high word is reached
		// this means that extra word is needed to fit the last part
		// of low word. Combine it by shifting all excess bits on both
		// left side and ride side of low word.
		case k == low:
			result = append(result, (vint[k] << lbshift >> (rbshift + lbshift)))
		// Specia case, the point where low+1 == hight word is reached
		// and leftover low word bits will fit into last result word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means no extra result word is needed.
		// Accumulate right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= lbshift+rbshift:
			result = append(result, (vint[k-1]<<lbshift>>(lbshift-(wsize-rbshift)))|(vint[k]>>rbshift))
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high accumulate next full combined word
		// by shifting current and next word parts to the right.
		default:
			result = append(result, (vint[k-1]<<(wsize-rbshift))|(vint[k]>>rbshift))
		}
	}
	return result, nil
}

func (vint VarInt) SetBits(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize, lenght := vint.Length()
	if i >= lenght {
		return ErrorIndexIsOutOfRange{Index: i, Length: lenght}
	}
	if bzisex := bits.Bits(); bzisex > bsize {
		return ErrorUnmatchingBitsCardinality{Bits: bsize, BitsX: bzisex}
	}
	bitsb := bits.Bytes()
	// Calculate ending bit with ending index inside vint respecitvely.
	bto := bsize*(i+1) - 1 + wsize
	hiw := (bto) / wsize
	// Calculate just right shift to fix the uint64 result.
	rbshift := (hiw+1)*wsize - 1 - bto
	// Iterate from high to low word
	// update the combined word by shifting
	// all excess bits on the left and ride sides.
	// For set bits unlike at bits no special align cases
	// need to be handle. Because provided bits cardinarity
	// by default is matching underlying bits cardinarity.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		vint[k] |= bitsb[i] << rbshift
		vint[k-1] |= bitsb[i] >> (wsize - rbshift)
		k--
	}
	return nil
}
