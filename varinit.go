package varint

import math_bits "math/bits"

const wsize = math_bits.UintSize

type VarInt []uint

func NewVarInt(blen, len int) (VarInt, error) {
	if blen <= 0 {
		return nil, ErrorBitLengthIsNotPositive{BitLen: blen}
	}
	if len <= 0 {
		return nil, ErrorLengthIsNotPositive{Len: len}
	}
	// Calculate capacity to fit all numbers with
	// provided bit length and capacity.
	cap := (blen*len+wsize-1)/wsize + 2
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	words := blen/wsize + (blen%wsize+wsize-1)/wsize
	vint := VarInt(make([]uint, cap+words+1))
	vint[0] = uint(len)
	vint[1] = uint(blen)
	// Allocate protected space at the for
	// the extra full bits at the back.
	// This temp variable is useful for operations
	// that require extra temp buffer like
	// multiplication, division or sorting.
	vint[cap] = uint(blen)
	return vint, nil
}

func (vint VarInt) Get(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	fullshift, adjrbshift := lbshift+rbshift, wsize-rbshift
	// Iterate from high to low word and
	// accumulate the combined words.
	for i, k := 1, hiw; k >= low; k, i = k-1, i+1 {
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
	}
	return nil
}

func (vint VarInt) Set(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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

func (vint VarInt) GetSet(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
		return ErrorAdditionOverflow{}
	}
	return nil
}

func (vint VarInt) Sub(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// subtract the combined word of vint and bits into vint.
	var borrow uint
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, note that bits on the right side preserved by default.
		// Shift both parts of the word all the way to the right, preserving original
		// right bits separately, subtract both borrow flag and right shifted provided bits,
		// finnaly restore separately preserved left bits back.
		case k == low:
			vbr, vbl := vint[k]<<adjrbshift>>adjrbshift, vint[k]>>adjlbshift<<adjlbshift
			vint[k], borrow = math_bits.Sub(vint[k]<<lbshift>>fullshift, bitsb[i], borrow)
			vint[k] = vbl | vint[k]<<fullshift>>lbshift | vbr
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// Shift both parts of the word all the way to the right, preserving original
		// right bits separately, subtract both borrow flag and right shifted provided bits,
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
		// subtract both borrow flag and right shifted provided bits,
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
		return ErrorSubtractionUnderflow{}
	}
	return nil
}

func (vint VarInt) Mul(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bvar := bvar(vint, true)
	bitsb, bvarb := bits.Bytes(), bvar.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjrbshift, fullshift := wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// multiply and combine the word of vint into tmp bits variable.
	var carry uint
	var overflow bool
	for i, maxl := 0, len(bitsb); i < maxl; i++ {
		b := bitsb[i]
		// Iterate from high to low word and
		// accumulate the combined words.
		for j, k := 0, hiw; k >= low; k, j = k-1, j+1 {
			// If out of temp bits buffer is riched,
			// set carry flag and jump to next iteration.
			w := i + j
			if w >= maxl {
				overflow = b != 0
				break
			}
			var bk uint
			switch {
			// Special case, the point where low == high word is reached
			// this means that extra word is needed to fit the last part
			// of low word. Combine it by shifting all excess bits on both
			// left side and ride side of low word.
			case k == low:
				bk = vint[k] << lbshift >> fullshift
			// Special case, the point where low+1 == hight word is reached
			// and leftover low word bits will fit into last result word size.
			// This can be deduced from sum of left bit shift plus right bit shift.
			// In case the sum is greater than word size, this means no extra result word is needed.
			// Accumulate right shifted prev high word with left shifted and adjusted bits of low word.
			case k-1 == low && wsize <= fullshift:
				bk = vint[k-1]<<lbshift>>(lbshift-adjrbshift) | vint[k]>>rbshift
				// Advance to mark low word as consumed, result is completed at this point.
				k--
			// By default, for any word low != high accumulate next full combined word
			// by shifting the current and the next word parts to the right.
			default:
				bk = vint[k-1]<<adjrbshift | vint[k]>>rbshift
			}
			var c1, c2 uint
			hi, lo := math_bits.Mul(bk, b)
			lo, c1 = math_bits.Add(lo, carry, 0)
			lo, c2 = math_bits.Add(lo, bvarb[w], 0)
			bvarb[w] = lo
			carry = hi + c1 + c2
			// For the very last word check if final
			// lower word result doesn't fit into bit len.
			if k == low && carry == 0 && math_bits.Len(lo) > blen%wsize {
				carry = 1
			}
		}
		if carry > 0 {
			overflow = true
			carry = 0
		}
	}
	// After multiplication is done set bits var
	// back to i-th number and check for any error.
	_ = vint.Set(i, bvar)
	if overflow {
		return ErrorMultiplicationOverflow{}
	}
	return nil
}

func (vint VarInt) Div(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	if bits.Empty() {
		return ErrorDivisionByZero{}
	}
	// Sub-block to compare divisor and divident using bits var.
	var cmp int
	{
		bvar := bvar(vint, true)
		_ = vint.Get(i, bvar)
		cmp = Compare(bvar, bits)
	}
	// Handle common cases early, in case
	// divisior is equal to divident - quotient = 1 and reminder = 0
	// divisior is greater than divident - quotient = 0 and reminder = divident.
	bvar := bvar(vint, true)
	switch cmp {
	case 0:
		bvar[1] = 1
		_ = vint.Set(i, bvar)
		bvar[1] = 0
		return nil
	case -1:
		_ = vint.GetSet(i, bvar)
		return nil
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Run bit len iterations to perform slow restoring division method here.
	// Extra swaps with tmp bits variable is needed to perform all
	// necessary left shifts and subtracts.
	for j := 0; j < blen; j++ {
		// Start with quotient Q in vint number and
		// partial reminder R in tmp bits variable.
		//
		// Do a left shift across both RQ, by
		// picking last bit from quotient Q in vint number
		// and applying left shift. Then swap partial reminder R
		// with vint number, apply left shift and set last memorized bit.
		lb := vint[low] << lbshift >> (wsize - 1)
		_ = vint.Lsh(i, 1)
		_ = vint.GetSet(i, bvar)
		_ = vint.Lsh(i, 1)
		vint[hiw] |= lb << rbshift
		// Subtract partial reminder R in in vint number with divisor
		// if it's greater or equal to R then set last bit of quotient
		// Q in tmp bits variable, otherwise cancel Subtraction by addition.
		switch vint.Sub(i, bits) {
		case ErrorSubtractionUnderflow{}:
			_ = vint.Add(i, bits)
		case nil:
			bvar[1] |= 1
		}
		// Finally swap R and Q back to restore the iteration state.
		_ = vint.GetSet(i, bvar)
	}
	return nil
}

func (vint VarInt) Mod(i int, bits Bits) error {
	// For modulo we can just use the fact that
	// in division operation the reminder is left
	// inside tmp bits variable. Reuse all the
	// logic validation from div here.
	if err := vint.Div(i, bits); err != nil {
		return err
	}
	// Get tmp bits variable with reminder inise,
	// don't clear the previous and swap it with vint number.
	_ = vint.GetSet(i, bvar(vint, false))
	return nil
}

func (vint VarInt) Not(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjlbshift, adjrbshift, fullshift := wsize-lbshift, wsize-rbshift, lbshift+rbshift
	// Iterate from high to low word and
	// invert and override the combined words.
	for k, i := hiw, 1; k >= low; k, i = k-1, i+1 {
		switch {
		// Special case, the point where low == high word is reached
		// this means that original word bits from vint need to be
		// respected, so clear the place for inverted bits in original word.
		case k == low:
			b, vbr, vbl := ^vint[k]<<lbshift>>fullshift<<rbshift,
				vint[k]<<adjrbshift>>adjrbshift,
				vint[k]>>adjlbshift<<adjlbshift
			vint[k] = vbl | b | vbr
			bits[i] = vint[k] << lbshift >> fullshift
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits is enough to fit last bits provided word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means left shifting is needed to be used.
		// Combine inverted right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | ^vint[k]>>rbshift<<rbshift
			k--
			vint[k] = vint[k]>>adjlbshift<<adjlbshift | ^vint[k]<<lbshift>>lbshift
			bits[i] = vint[k]<<lbshift>>(lbshift-adjrbshift) | vint[k+1]>>rbshift
		// By default, for any word low != high override word from provided bits
		// by clearing vint right parts of the current and the next word and combining them
		// with right shifted parts of inverted word.
		default:
			vint[k] = vint[k]<<adjrbshift>>adjrbshift | ^vint[k]>>rbshift<<rbshift
			vint[k-1] = vint[k-1]>>rbshift<<rbshift | ^vint[k-1]<<adjrbshift>>adjrbshift
			bits[i] = vint[k-1]<<adjrbshift | vint[k]>>rbshift
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
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := BitLen(vint)
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*2, blen*(i+1)-1+wsize*2
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
