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

func (vint VarInt) Get(i int) (Bits, error) {
	if err := vint.check(i, nil); err != nil {
		return nil, err
	}
	bsize := int(vint[0])
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
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
		// by shifting the current and the next word parts to the right.
		default:
			result = append(result, (vint[k-1]<<adjrbshift)|(vint[k]>>rbshift))
		}
	}
	return result, nil
}

func (vint VarInt) Set(i int, bits Bits) error {
	if err := vint.check(i, bits); err != nil {
		return err
	}
	bsize, bitsb := int(vint[0]), bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
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
			vint[k-1] = vint[k-1]>>adjlbshift<<adjlbshift | bitsb[i]>>adjrbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of word from bits.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | bitsb[i]<<rbshift
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | bitsb[i]>>adjrbshift
			k--
		}
	}
	return nil
}

func (vint VarInt) Add(i int, bits Bits) error {
	if err := vint.check(i, bits); err != nil {
		return err
	}
	bsize, bitsb := int(vint[0]), bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits + from high to low word and
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
			//
			onleft := vint[k-1] >> adjlbshift << adjlbshift
			vint[k-1], c1 = math_bits.Add(vint[k-1]<<lbshift, carry<<lbshift, 0)
			vint[k-1], c2 = math_bits.Add(vint[k-1], bitsb[i]>>adjrbshift<<lbshift, 0)
			carry = c1 | c2
			vint[k-1] = onleft | vint[k-1]>>lbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high shift both parts of the word
		// all the way to the left, preserving original left bits separately,
		// add left shifted carry flag and provided bits, update the carry flag,
		// finnaly restore separately preserved left bits back.
		default:
			var c1, c2 uint
			vint[k], c1 = math_bits.Add(vint[k], carry<<rbshift, 0)
			vint[k], c2 = math_bits.Add(vint[k], bitsb[i]<<rbshift, 0)
			carry = c1 + c2
			onleft := vint[k-1] >> rbshift << rbshift
			vint[k-1], c1 = math_bits.Add(vint[k-1]<<adjrbshift, carry<<adjrbshift, 0)
			vint[k-1], c2 = math_bits.Add(vint[k-1], bitsb[i]>>adjrbshift<<adjrbshift, 0)
			carry = c1 + c2
			vint[k-1] = onleft | vint[k-1]>>adjrbshift
			k--
		}
	}
	if carry > 0 {
		return ErrorBitsOperationOverflow{Bits: bsize}
	}
	return nil
}

func (vint VarInt) Sub(i int, bits Bits) error {
	if err := vint.check(i, bits); err != nil {
		return err
	}
	bsize, bitsb := int(vint[0]), bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits + from high to low word and
	// add the combined word of vint and bits into vint.
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
			//
			onleft := vint[k-1] >> adjlbshift << adjlbshift
			vint[k-1], borrow = math_bits.Sub(vint[k-1]<<lbshift>>lbshift, bitsb[i]>>adjrbshift, borrow)
			vint[k-1] = onleft | vint[k-1]<<lbshift>>lbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high shift both parts of the word
		// all the way to the right, preserving original right bits separately,
		// substitute both borrow flag and right shifted provided bits,
		// finnaly restore separately preserved left bits back.
		default:
			onright := vint[k] << adjrbshift >> adjrbshift
			vint[k], borrow = math_bits.Sub(vint[k]>>rbshift, bitsb[i]<<rbshift>>rbshift, borrow)
			vint[k] = vint[k]<<rbshift | onright
			onleft := vint[k-1] >> rbshift << rbshift
			vint[k-1], borrow = math_bits.Sub(vint[k-1]<<adjrbshift>>adjrbshift, bitsb[i]>>adjrbshift, borrow)
			vint[k-1] = onleft | vint[k-1]<<adjrbshift>>adjrbshift
			k--
		}
	}
	if borrow > 0 {
		return ErrorBitsOperationUnderflow{Bits: bsize}
	}
	return nil
}

func (vint VarInt) Not(i int) error {
	if err := vint.check(i, nil); err != nil {
		return err
	}
	bsize := int(vint[0])
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
	low, hiw := (bfrom)/wsize, (bto)/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate from high to low word and
	// invert ^ the combined words.
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
			vint[k-1] = vint[k-1]>>adjlbshift<<adjlbshift | ^vint[k-1]<<lbshift>>lbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
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
	if err := vint.check(i, bits); err != nil {
		return err
	}
	bsize, bitsb := int(vint[0]), bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
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
			vint[k-1] = vint[k-1]>>adjlbshift<<adjlbshift | (vint[k-1]<<lbshift>>lbshift)&(bitsb[i]>>adjrbshift)
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of current word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | (vint[k]>>rbshift<<rbshift)&(bitsb[i]<<rbshift)
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | (vint[k-1]<<adjrbshift>>adjrbshift)&(bitsb[i]>>adjrbshift)
			k--
		}
	}
	return nil
}

func (vint VarInt) Or(i int, bits Bits) error {
	if err := vint.check(i, bits); err != nil {
		return err
	}
	bsize, bitsb := int(vint[0]), bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
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
			vint[k-1] = vint[k-1]>>adjlbshift<<adjlbshift | vint[k-1]<<lbshift>>lbshift | bitsb[i]>>adjrbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of current word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>rbshift<<rbshift | bitsb[i]<<rbshift
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | vint[k-1]<<adjrbshift>>adjrbshift | bitsb[i]>>adjrbshift
			k--
		}
	}
	return nil
}

func (vint VarInt) Xor(i int, bits Bits) error {
	if err := vint.check(i, bits); err != nil {
		return err
	}
	bsize, bitsb := int(vint[0]), bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize*rcap, bsize*(i+1)-1+wsize*rcap
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
			vint[k-1] = vint[k-1]>>adjlbshift<<adjlbshift | vint[k-1]<<lbshift>>lbshift ^ bitsb[i]>>adjrbshift
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of current word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | vint[k]>>rbshift<<rbshift ^ bitsb[i]<<rbshift
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | vint[k-1]<<adjrbshift>>adjrbshift ^ bitsb[i]>>adjrbshift
			k--
		}
	}
	return nil
}

func (vint VarInt) check(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	bsize, lenght := vint.Length()
	if i >= lenght {
		return ErrorIndexIsOutOfRange{Index: i, Length: lenght}
	}
	// Check bits cardinarity only if provided.
	if bits == nil {
		return nil
	}
	if bzisex := bits.Bits(); bzisex != bsize {
		return ErrorUnequalBitsCardinality{Bits: bsize, BitsX: bzisex}
	}
	return nil
}
