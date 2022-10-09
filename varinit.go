package varint

import math_bits "math/bits"

const (
	rcap  = 2
	wsize = math_bits.UintSize
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

func (vint VarInt) Get(i int, bits Bits) error {
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
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	fullshift, adjrbshift := lbshift+rbshift, wsize-rbshift
	// Iterate from high to low word and
	// accumulate the combined words.
	for i, k := 1, hiw; k >= low; k-- {
		switch {
		// Special case, the point where low == high word is reached
		// this means that extra word is needed to fit the last part
		// of low word. Combine it by shifting all excess bits on both
		// left side and ride side of low word.
		case k == low:
			bits[i] = vint[k] << lbshift >> fullshift
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits will fit into last result word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means no extra result word is needed.
		// Accumulate right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			bits[i] = vint[k-1]<<lbshift>>(lbshift-adjrbshift) | vint[k]>>rbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high accumulate next full combined word
		// by shifting the current and the next word parts to the right.
		default:
			bits[i] = vint[k-1]<<adjrbshift | vint[k]>>rbshift
		}
		i++
	}
	return nil
}

func (vint VarInt) Set(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// override the combined word in vint.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for provided bits in original word.
		case k == low:
			b, vbr, vbl := bitsb[i]<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | bitsb[i]>>adjrbshift
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of word from bits.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>rbshift<<rbshift | bitsb[i]>>adjrbshift
		}
	}
	return nil
}

func (vint VarInt) Swap(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// swap the combined wordd in vint with provided bits.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for provided bits in original word.
		case k == low:
			bk := vint[k] << lbshift >> fullshift
			b, vbr, vbl := bitsb[i]<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
			bitsb[i] = bk
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			bk := vint[k-1]<<lbshift>>(lbshift-adjrbshift) | vint[k]>>rbshift
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | bitsb[i]>>adjrbshift
			bitsb[i] = bk
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of word from bits.
		default:
			bk := vint[k-1]<<adjrbshift | vint[k]>>rbshift
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>rbshift<<rbshift | bitsb[i]>>adjrbshift
			bitsb[i] = bk
		}
	}
	return nil
}

func (vint VarInt) Add(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// add the combined word of vint and bits into vint.
	var carry uint
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, note that bits on the right side preserved by default.
		// Shift both parts of the word all the way to the left, preserving original
		// left bits separately, add left shifted carry flag and provided bits,
		// update the carry flag, finnaly restore separately preserved left bits back
		case k == low:
			var c1, c2 uint
			onleft := vint[k] >> adjlbshift << adjlbshift
			vint[k], c1 = math_bits.Add(vint[k]<<lbshift, carry<<fullshift, 0)
			vint[k], c2 = math_bits.Add(vint[k], bitsb[i]<<fullshift, 0)
			carry = c1 + c2
			vint[k] = onleft | vint[k]>>lbshift
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// Shift both parts of the word all the way to the left, preserving original
		// left bits separately, add left shifted carry flag and provided bits,
		// update the carry flag, finnaly restore separately preserved left bits back
		case k-1 == low && wsize <= fullshift:
			var c1, c2 uint
			vint[k], c1 = math_bits.Add(vint[k], carry<<rbshift, 0)
			vint[k], c2 = math_bits.Add(vint[k], bitsb[i]<<rbshift, 0)
			carry = c1 + c2
			k--
			onleft := vint[k] >> adjlbshift << adjlbshift
			vint[k], c1 = math_bits.Add(vint[k]<<lbshift, carry<<lbshift, 0)
			vint[k], c2 = math_bits.Add(vint[k], bitsb[i]>>adjrbshift<<lbshift, 0)
			carry = c1 | c2
			vint[k] = onleft | vint[k]>>lbshift
		// By default, for any word low != high shift both parts of the word
		// all the way to the left, preserving original left bits separately,
		// add left shifted carry flag and provided bits, update the carry flag,
		// finnaly restore separately preserved left bits back.
		default:
			var c1, c2 uint
			vint[k], c1 = math_bits.Add(vint[k], carry<<rbshift, 0)
			vint[k], c2 = math_bits.Add(vint[k], bitsb[i]<<rbshift, 0)
			carry = c1 + c2
			k--
			// In case word is round to wszie
			// no need to add next partial word.
			if rbshift == 0 {
				break
			}
			onleft := vint[k] >> rbshift << rbshift
			vint[k], c1 = math_bits.Add(vint[k]<<adjrbshift, carry<<adjrbshift, 0)
			vint[k], c2 = math_bits.Add(vint[k], bitsb[i]>>adjrbshift<<adjrbshift, 0)
			carry = c1 + c2
			vint[k] = onleft | vint[k]>>adjrbshift
		}
	}
	if carry > 0 {
		return ErrorBitsOperationOverflow{Bits: bsize}
	}
	return nil
}

func (vint VarInt) Sub(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// substract the combined word of vint and bits into vint.
	var borrow uint
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, note that bits on the right side preserved by default.
		// Shift both parts of the word all the way to the right, preserving original
		// right bits separately, substitute both borrow flag and right shifted provided bits,
		// finnaly restore separately preserved left bits back.
		case k == low:
			vbr, vbl := vint[k]<<adjrbshift>>adjrbshift, vint[k]>>adjlbshift<<adjlbshift
			vint[k], borrow = math_bits.Sub(vint[k]<<lbshift>>fullshift, bitsb[i], borrow)
			vint[k] = vbl | vint[k]<<fullshift>>lbshift | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// Shift both parts of the word all the way to the right, preserving original
		// right bits separately, substitute both borrow flag and right shifted provided bits,
		// finnaly restore separately preserved left bits back.
		case k-1 == low && wsize <= fullshift:
			onright := vint[k] << adjrbshift >> adjrbshift
			vint[k], borrow = math_bits.Sub(vint[k]>>rbshift, bitsb[i]<<rbshift>>rbshift, borrow)
			vint[k] = vint[k]<<rbshift | onright
			k--
			onleft := vint[k] >> adjlbshift << adjlbshift
			vint[k], borrow = math_bits.Sub(vint[k]<<lbshift>>lbshift, bitsb[i]>>adjrbshift, borrow)
			vint[k] = onleft | vint[k]<<lbshift>>lbshift
		// By default, for any word low != high shift both parts of the word
		// all the way to the right, preserving original right bits separately,
		// substitute both borrow flag and right shifted provided bits,
		// finnaly restore separately preserved left bits back.
		default:
			onright := vint[k] << adjrbshift >> adjrbshift
			vint[k], borrow = math_bits.Sub(vint[k]>>rbshift, bitsb[i]<<rbshift>>rbshift, borrow)
			vint[k] = vint[k]<<rbshift | onright
			k--
			// In case word is round to wszie
			// no need to sub next partial word.
			if rbshift == 0 {
				break
			}
			onleft := vint[k] >> rbshift << rbshift
			vint[k], borrow = math_bits.Sub(vint[k]<<adjrbshift>>adjrbshift, bitsb[i]>>adjrbshift, borrow)
			vint[k] = onleft | vint[k]<<adjrbshift>>adjrbshift
		}
	}
	if borrow > 0 {
		return ErrorBitsOperationUnderflow{Bits: bsize}
	}
	return nil
}

func (vint VarInt) Not(i int) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize, lenght := vint.Length()
	if i >= lenght {
		return ErrorIndexIsOutOfRange{Index: i, Length: lenght}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate from high to low word and
	// invert and override the combined words.
	for k := hiw; k >= low; k-- {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for inverted bits in original word.
		case k == low:
			b, vbr, vbl := ^vint[k]<<lbshift>>fullshift<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine inverted right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | ^vint[k]>>rbshift<<rbshift
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | ^vint[k]<<lbshift>>lbshift
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of inverted word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | ^vint[k]>>rbshift<<rbshift
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | ^vint[k-1]<<adjrbshift>>adjrbshift
		}
	}
	return nil
}

func (vint VarInt) And(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// override the combined word in vint.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for combined bits in original word.
		case k == low:
			b, vbr, vbl := (vint[k]<<lbshift>>fullshift<<rbshift)&(bitsb[i]<<rbshift),
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | (vint[k]>>rbshift<<rbshift)&(bitsb[i]<<rbshift)
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | (vint[k]<<lbshift>>lbshift)&(bitsb[i]>>adjrbshift)
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of current word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | (vint[k]>>rbshift<<rbshift)&(bitsb[i]<<rbshift)
			k--
			vint[k] = vint[k]>>rbshift<<rbshift | (vint[k]<<adjrbshift>>adjrbshift)&(bitsb[i]>>adjrbshift)
		}
	}
	return nil
}

func (vint VarInt) Or(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits from high to low word and
	// override the combined word in vint.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for combined bits in original word.
		case k == low:
			b, vbr, vbl := vint[k]<<lbshift>>fullshift<<rbshift|bitsb[i]<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>rbshift<<rbshift | bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | vint[k]<<lbshift>>lbshift | bitsb[i]>>adjrbshift
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of current word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>rbshift<<rbshift | bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>rbshift<<rbshift | vint[k]<<adjrbshift>>adjrbshift | bitsb[i]>>adjrbshift
		}
	}
	return nil
}

func (vint VarInt) Xor(i int, bits Bits) error {
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
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// override the combined word in vint.
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for combined bits in original word.
		case k == low:
			b, vbr, vbl := vint[k]<<lbshift>>fullshift<<rbshift^bitsb[i]<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>rbshift<<rbshift ^ bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | vint[k]<<lbshift>>lbshift ^ bitsb[i]>>adjrbshift
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of current word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>rbshift<<rbshift ^ bitsb[i]<<rbshift
			k--
			vint[k] = vint[k]>>rbshift<<rbshift | vint[k]<<adjrbshift>>adjrbshift ^ bitsb[i]>>adjrbshift
		}
	}
	return nil
}

func (vint VarInt) Rsh(i, n int) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize, lenght := vint.Length()
	if i >= lenght {
		return ErrorIndexIsOutOfRange{Index: i, Length: lenght}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw, nw := bfrom/wsize, bto/wsize, n/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift, nbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto, n%wsize
	adjlbshift, adjrbshift, adjnbshift := wsize-lbshift, wsize-rbshift, wsize-nbshift
	// Iterate from high to low word and
	// shift and override the combined words.
loop:
	for k := hiw; k >= low; k-- {
		// First get current shifted word position and
		// original copy of the current word.
		knw, val := k+nw, vint[k]
		// Second consume and clear current word bits and
		// fix copy of the current word if it's low word.
		switch {
		case k == hiw && k == low:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>adjlbshift<<adjlbshift
			val = val << lbshift >> lbshift
		case k == hiw:
			vint[k] = vint[k] << adjrbshift >> adjrbshift
		case k == low:
			vint[k] = vint[k] >> adjlbshift << adjlbshift
			val = val << lbshift >> lbshift
		default:
			vint[k] = 0
		}
		// Then split the current word into two parts
		// accordingly to provided and adjunctive shifts.
		v1, v2 := val>>nbshift, val<<adjnbshift
		// For main part, based on the operated index, either:
		// - skip the shift, if out of range
		// - apply partial word respecting high word boundary
		// - apply full shifted word
		switch {
		case knw > hiw:
			continue loop
		case knw == hiw:
			v1 = v1 >> rbshift << rbshift
			fallthrough
		default:
			vint[knw] = vint[knw] | v1
		}
		// For carryover part, based on the operated index, either:
		// - skip the shift, if out of range
		// - apply partial word respecting high word boundary
		// - apply full shifted word
		switch {
		case knw+1 > hiw:
			continue loop
		case knw+1 == hiw:
			v2 = v2 >> rbshift << rbshift
			fallthrough
		default:
			vint[knw+1] = vint[knw+1] | v2
		}
	}
	return nil
}

func (vint VarInt) Lsh(i, n int) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize, lenght := vint.Length()
	if i >= lenght {
		return ErrorIndexIsOutOfRange{Index: i, Length: lenght}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw, nw := bfrom/wsize, bto/wsize, n/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift, nbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto, n%wsize
	adjlbshift, adjrbshift, adjnbshift := wsize-lbshift, wsize-rbshift, wsize-nbshift
	// Iterate from low to high word and
	// shift and override the combined words.
loop:
	for k := low; k <= hiw; k++ {
		// First get current shifted word position and
		// original copy of the current word.
		knw, val := k-nw, vint[k]
		// Second consume and clear current word bits and
		// fix copy of the current word if it's low word.
		switch {
		case k == hiw && k == low:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>adjlbshift<<adjlbshift
			val = val >> rbshift << rbshift
		case k == hiw:
			vint[k] = vint[k] << adjrbshift >> adjrbshift
			val = val >> rbshift << rbshift
		case k == low:
			vint[k] = vint[k] >> adjlbshift << adjlbshift
		default:
			vint[k] = 0
		}
		// Then split the current word into two parts
		// accordingly to provided and adjunctive shifts.
		v1, v2 := val<<nbshift, val>>adjnbshift
		// For main part, based on the operated index, either:
		// - skip the shift, if out of range
		// - apply partial word respecting high word boundary
		// - apply full shifted word
		switch {
		case knw < low:
			continue loop
		case knw == low:
			v1 = v1 << lbshift >> lbshift
			fallthrough
		default:
			vint[knw] = vint[knw] | v1
		}
		// For carryover part, based on the operated index, either:
		// - skip the shift, if out of range
		// - apply partial word respecting high word boundary
		// - apply full shifted word
		switch {
		case knw-1 < low:
			continue loop
		case knw-1 == low:
			v2 = v2 << lbshift >> lbshift
			fallthrough
		default:
			vint[knw-1] = vint[knw-1] | v2
		}
	}
	return nil
}
