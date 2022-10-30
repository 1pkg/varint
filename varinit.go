package varint

import math_bits "math/bits"

const (
	rcap  = 2
	wsize = math_bits.UintSize
)

type VarInt []uint

func NewVarInt(blen, len int) (VarInt, error) {
	if blen <= 0 {
		return nil, ErrorBitLengthIsNegative{BitLen: blen}
	}
	if len <= 0 {
		return nil, ErrorLengthIsNegative{Len: len}
	}
	// Calculate capacity to fit all numbers with
	// provided bit length and capacity.
	cap := (blen*len+wsize-1)/wsize + rcap
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

func (vint VarInt) varbits(empty bool) Bits {
	cap := (vint.BitLen()*vint.Len()+wsize-1)/wsize + rcap
	b := Bits(vint[cap:])
	if !empty {
		return b
	}
	// Clear var bits state from prev manipulations.
	for i := 1; i < len(vint)-cap; i++ {
		b[i] = 0
	}
	return b
}

func (vint VarInt) Len() int {
	return int(vint[0])
}

func (vint VarInt) BitLen() int {
	return int(vint[1])
}

func (vint VarInt) Get(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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

func (vint VarInt) Cmp(i int, bits Bits) (int, error) {
	// Check that non negative index was provided.
	if i < 0 {
		return 0, ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return 0, ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return 0, ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Calculate word size adjunctive left and right shifts.
	adjrbshift, fullshift := wsize-rbshift, lbshift+rbshift
	// Iterate over bits and from high to low word and
	// compare the combined wordd in vint with provided bits.
	var bk, b, cmp uint
	for k, i := hiw, 0; i < len(bitsb); i++ {
		switch {
		// Special case, the point where low == high word is reached
		// this means that extra word is needed to fit the last part
		// of low word. Combine it by shifting all excess bits on both
		// left side and ride side of low word.
		case k == low:
			bk, b = vint[k]<<lbshift>>fullshift, bitsb[i]
		// Special case, the point where low+1 == hight word is reached
		// and leftover low word bits will fit into last result word size.
		// This can be deduced from sum of left bit shift plus right bit shift.
		// In case the sum is greater than word size, this means no extra result word is needed.
		// Accumulate right shifted prev high word with left shifted and adjusted bits of low word.
		case k-1 == low && wsize <= fullshift:
			bk, b = vint[k-1]<<lbshift>>(lbshift-adjrbshift)|vint[k]>>rbshift, bitsb[i]
			// Advance to mark low word as consumed, result is completed at this point.
			k--
		// By default, for any word low != high accumulate next full combined word
		// by shifting the current and the next word parts to the right.
		default:
			bk, b = vint[k-1]<<adjrbshift|vint[k]>>rbshift, bitsb[i]
		}
		k--
		// Override the current result depending on words comparison.
		switch {
		case b > bk:
			cmp = ^uint(0)
		case b < bk:
			cmp = 1
		}
	}
	return int(cmp), nil
}

func (vint VarInt) Add(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
		return ErrorAdditionOverflow{BitLen: blen}
	}
	return nil
}

func (vint VarInt) Sub(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
		return ErrorSubtractionUnderflow{BitLen: blen}
	}
	return nil
}

func (vint VarInt) Mul(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	varbits := vint.varbits(true)
	bitsb, varbitsb := bits.Bytes(), varbits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
		for j, k := 0, hiw; k >= low; k-- {
			// If out of temp bits buffer is riched,
			// set carry flag and jump to next iteration.
			w := i + j
			if w >= maxl {
				overflow = b != 0
				continue
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
			lo, c2 = math_bits.Add(lo, varbitsb[w], 0)
			varbitsb[w] = lo
			carry = hi + c1 + c2
			j++
		}
		if carry > 0 {
			overflow = true
			carry = 0
		}
	}
	// After multiplication is done set bits var
	// back to i-th number and check for any error.
	if err := vint.Set(i, varbits); err != nil {
		return err
	}
	if overflow {
		return ErrorMultiplicationOverflow{BitLen: blen}
	}
	return nil
}

func (vint VarInt) Div(i int, bits Bits) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	if bits.Empty() {
		return ErrorDivisionByZero{}
	}
	// Handle common cases early, in case
	// divisior is equal to divident - quotient = 1 and reminder = 0
	// divisior is greater than divident - quotient = 0 and reminder = divident.
	cmp, err := vint.Cmp(i, bits)
	if err != nil {
		return err
	}
	varbits := vint.varbits(true)
	varbitsb := varbits.Bytes()
	switch cmp {
	case 0:
		varbitsb[0] = 1
		if err := vint.Set(i, varbits); err != nil {
			return err
		}
		varbitsb[0] = 0
		return nil
	case -1:
		return vint.GetSet(i, varbits)
	default:
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
	low, hiw := bfrom/wsize, bto/wsize
	// Calculate left and right shifts to fix the uint result.
	lbshift, rbshift := bfrom-low*wsize, (hiw+1)*wsize-1-bto
	// Run bit len iterations to perform slow restoring division method here.
	// Extra swaps with tmp bits variable is needed to perform all
	// necessary left shifts and substitutes.
	for j := 0; j < blen; j++ {
		// Start with quotient Q in vint number and
		// partial reminder R in tmp bits variable.
		//
		// Do a left shift across both RQ, by
		// picking last bit from quotient Q in vint number
		// and applying left shift. Then swap partial reminder R
		// with vint number, apply left shift and set last memorized bit.
		lb := vint[low] << lbshift >> (wsize - 1)
		if err := vint.Lsh(i, 1); err != nil {
			return err
		}
		if err := vint.GetSet(i, varbits); err != nil {
			return err
		}
		if err := vint.Lsh(i, 1); err != nil {
			return err
		}
		vint[hiw] |= lb << rbshift
		// Compare partial reminder R in in vint number with divisor
		// only subtract it if it's bigger or equal to R and set
		// last bit of quotient Q in tmp bits variable.
		cmp, err := vint.Cmp(i, bits)
		if err != nil {
			return err
		}
		if cmp >= 0 {
			if err := vint.Sub(i, bits); err != nil {
				return err
			}
			varbitsb[0] |= 1
		}
		// Finally swap R and Q back to restore the iteration state.
		if err := vint.GetSet(i, varbits); err != nil {
			return err
		}
	}
	return nil
}

func (vint VarInt) Mod(i int, bits Bits) error {
	// For modulo we can just use the fact that
	// in division operation the reminder is left
	// inside tmp bits variable.
	if err := vint.Div(i, bits); err != nil {
		return err
	}
	// Get tmp bits variable with reminder inise,
	// don't clear the previous and swap it with vint number.
	varbits := vint.varbits(false)
	return vint.GetSet(i, varbits)
}

func (vint VarInt) Not(i int) error {
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative{Index: i}
	}
	// Check that requested index is inside varint range.
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality{BitLenLeft: blen, BitLenRight: blenx}
	}
	bitsb := bits.Bytes()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
	if length := vint.Len(); i >= length {
		return ErrorIndexIsOutOfRange{Index: i, Length: length}
	}
	blen := vint.BitLen()
	// Calculate starting and ending bit with
	// starting and ending index inside vint respectively.
	bfrom, bto := blen*i+wsize*rcap, blen*(i+1)-1+wsize*rcap
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
