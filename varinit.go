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
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize-1
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifting to fix the uint64 result.
	lbshift, rbshift := bfrom-(low)*wsize, (hiw+1)*wsize-bto-1
	if low == hiw {
		// In case we operate in the same word
		// just shift all excess bits on the left and ride sides.
		return []uint64{uint64(bsize), vint[low] << lbshift >> (rbshift + lbshift)}, nil
	}
	// Preallocate a slice to fit all words and start traversal them in reverse order.
	result := make([]uint64, 0, hiw-low+2)
	result = append(result, uint64(bsize))
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
	if bzisex := bits.Bits(); bsize != bzisex {
		return ErrorUnequalBitsCardinality{Bits: bsize, BitsX: bzisex}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize-1
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifting to fix the uint64 result.
	lbshift, rbshift := bfrom-(low)*wsize, (hiw+1)*wsize-bto-1
	if low == hiw {
		// In case we operate in the same word
		// just shift all excess bits on the left and ride sides.
		vint[low] |= bitsb[1] << rbshift
		return nil
	}
	// Iterate until we didn't reach low word
	// update the combined word by shifting all excess bits on the left and ride sides.
	for k, i := hiw, 1; k > low; k-- {
		vint[k] |= bitsb[i] << rbshift
		vint[k-1] |= bitsb[i] >> (wsize - rbshift)
		i++
	}
	if wsize <= lbshift+rbshift {
		// In case leftover low + high bits fit in single uint64 word fix last word
		// first shift all excess bits on the left side
		// of the low word and then align it to the right side to fit the high word.
		// Then shift all excess bits on the right side of the high word and merge the intermidiate results.
		vint[low] = (vint[low] << lbshift >> (lbshift - (wsize - rbshift))) | (vint[low+1] >> rbshift)
	} else {
		// Otherwise we need to update a separate word for leftover low + high bits
		// first accumulate the combined word by shifting all excess bits on the left and ride sides.
		// Then for low word just shift all excess bits on the left side and ride side with delta.
		vint[low] |= bitsb[len(bitsb)-1] << rbshift
	}
	return nil
}
