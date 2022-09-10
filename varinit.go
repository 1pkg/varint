package varint

import "math/bits"

const (
	rcap      = 2
	wsize     = bits.UintSize
	rcapwsize = wsize * rcap
)

type VarInt []uint

func NewVarInt(bits, length int) (VarInt, error) {
	if bits <= 0 {
		return nil, ErrorBitsIsNegative{Bits: bits}
	}
	if length <= 0 {
		return nil, ErrorLengthIsNegative{Length: length}
	}
	size := (bits*length+wsize-1)/wsize + rcap
	vint := VarInt(make([]uint, size))
	vint[0] = uint(bits)
	vint[1] = uint(length)
	return vint, nil
}

func (vint VarInt) Length() (bits, length int) {
	return int(vint[0]), int(vint[1])
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
	bfrom, bto := bsize*i+rcapwsize, bsize*(i+1)-1+rcapwsize
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	fullshift, adjrbshift := lbshift+rbshift, wsize-rbshift
	// Preallocate a slice to fit all words and start traversal them in reverse order.
	result := make([]uint, 0, hiw-low+2)
	result = append(result, uint(bsize))
	// Iterate from high to low word and
	// accumulate the combined words.
	for k := hiw; k >= low; k-- {
		switch {
		// Special case, the point where low == high word is reached
		// this means that extra word is needed to fit the last part
		// of low word. Combine it by shifting all excess bits on both
		// left side and ride side of low word.
		case k == low:
			result = append(result, (vint[k] << lbshift >> fullshift))
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits will fit into last result word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means no extra result word is needed.
		// Accumulate right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			result = append(result, (vint[k-1]<<lbshift>>(lbshift-adjrbshift))|(vint[k]>>rbshift))
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high accumulate next full combined word
		// by shifting current and next word parts to the right.
		default:
			result = append(result, (vint[k-1]<<adjrbshift)|(vint[k]>>rbshift))
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
	if bzisex := bits.Bits(); bzisex != bsize {
		return ErrorUnequalBitsCardinality{Bits: bsize, BitsX: bzisex}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+rcapwsize, bsize*(i+1)-1+rcapwsize
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits + from high to low word and
	// override the combined word in vint.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for provided in original word.
		case k == low:
			b, vbr, vbl := bitsb[i]<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means leftshifting is needed to be used.
		// Combine right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			vint[k-1] = vint[k-1]>>adjlbshift<<adjlbshift | bitsb[i]>>adjrbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of current and next word and combining them
		// with right shifted parts of word from bits.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | bitsb[i]>>adjrbshift
			k--
		}
	}
	return nil
}
