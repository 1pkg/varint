package varint

import math_bits "math/bits"

// wsize const alias to system uint word size in bits.
const wsize = math_bits.UintSize

// VarInt provides fast and memory efficient arbitrary bit length unsigned integer array type.
//
// The purpose of VarInt to provide the maximum memory compact way to use and store unsigned custom bits integers.
// It does so by storing all the integers adjacent to each other inside a continuous numeric byte slice.
// It allocates the underlying numeric bytes slice only once on creation and doesn't expect to allocate any more memory afterwards.
// VarInt provides all the basic arithmetic and bitwise operations. To apply any of these operations, internal bits manipulations are required
// which implies certain computational overhead. Thus providing a tradeoff between CPU time and memory.
// Overhead grows lineraly, proportionally to bit len and is comparable with overhead from big.Int operations.
// Unlike big.Int however, VarInt uses exact number of bits to store the integers inside. Which makes VarInt extremely memory efficient.
// For example, to store a slice of 100 integers 100 bit each, big.Int requires 12400 bits, while VarInt needs exactly 10000 bits.
// In the same fashion VarInt also provides an efficient way to store integers smaller than 64 bits.
// For example, to store a slice of 1000 integers 2 bit each, []uin8 requires 8000 bits, while VarInt needs exactly 2000 bits.
// However, note that VarInt is no way close to be optimized as well as big.Int, and provides diminishing returns as bit length grows above certain threshold.
//
// Currently, in a conscious decision multiple operations are implemented in favour of simplicity and not computational complexity,
// this includes Mul that uses standard long multiplication instead of fast multiplication algorithms like Karatsuba multiplication,
// and Div that uses standard slow division instead of fast division algorithms.
// The main rationale behind this choice is the fact that VarInt has the most efficiency when used for small and medium size integers
// in the range of 1 to 5000 bit width, therefore asymptotic complexity should be less significant for this library.
// Note that VarInt carries a small fixed overhead internaly, it allocates 2 separate uint cells at the beginning of the numeric bytes slice
// to store length and bit length. It also collocates extra Bits variable at the end of numeric bytes slice which is used internally
// for many operations as a computation temporary buffer, including: Mul, Div, Mod, Sort.
// Currently, for simplicity and consistency most VarInt operations apply changes in place on the provided index and require
// the provided Bits to have exactly the same bit len, otherwise ErrorUnequalBitLengthCardinality is returned.
// Currently, VarInt provides only unsigned arithmetic.
type VarInt []uint

// NewVarInt allocates and returns VarInt instance that is capable to
// fit the provided number of integers each of the provided bit len in width.
// In case the provided bit len is not positive, invalid number and ErrorBitLengthIsNotPositive is returned.
// In case the len is not positive, invalid number and ErrorLengthIsNotPositive is returned.
// In case the provided bit len is larger than predefined threshold of 4096,
// valid VarInt is still returned along with ErrorBitLengthIsNotEfficient warning.
// In case the provided len is smaller than predefined threshold of 4,
// valid VarInt is still returned along with ErrorLengthIsNotEfficient warning.
// See VarInt type for more details.
func NewVarInt(blen, len int) (VarInt, error) {
	if blen <= 0 {
		return nil, ErrorBitLengthIsNotPositive
	}
	if len <= 0 {
		return nil, ErrorLengthIsNotPositive
	}
	// Calculate capacity to fit all integers with
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
	// Lastly, check for len thresholds, in case the
	// thresholds are violated still return a valid
	// number but also return the warning along with it.
	const bzise = 4
	switch {
	case blen > wsize*wsize:
		return vint, ErrorBitLengthIsNotEfficient
	case len < bzise:
		return vint, ErrorLengthIsNotEfficient
	default:
		return vint, nil
	}
}

// Get sets the provided bits to the integer inside VarInt at the provided index.
// It never allocates new Bits, the provided Bits are expected to be preallocated by the caller.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
func (vint VarInt) Get(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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

// Set sets the provided bits into the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
func (vint VarInt) Set(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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

// GetSet swaps the provided bits with the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
func (vint VarInt) GetSet(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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

// Add adds the provided bits to the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
// In case the addition result overflows the bit len, the regular unsigned semantic applies and
// extra ErrorAdditionOverflow warning is returned.
func (vint VarInt) Add(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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
		return ErrorAdditionOverflow
	}
	return nil
}

// Sub subtracts the provided bits from the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
// In case the subtraction result underflows the integer, the regular unsigned semantic applies and
// extra ErrorSubtractionUnderflow warning is returned.
func (vint VarInt) Sub(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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
		return ErrorSubtractionUnderflow
	}
	return nil
}

// Mul multiplies the provided bits with the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
// In case the multiplication result overflows the bit len, the integer is trucated and
// extra ErrorMultiplicationOverflow warning is returned.
func (vint VarInt) Mul(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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
	// back to i-th integer and check for any error.
	_ = vint.Set(i, bvar)
	if overflow {
		return ErrorMultiplicationOverflow
	}
	return nil
}

// Div divides the provided bits with the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
// In case the division by zero is attempted, ErrorDivisionByZero is returned
func (vint VarInt) Div(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
	}
	if bits.Empty() {
		return ErrorDivisionByZero
	}
	bvar := bvar(vint, true)
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
		case ErrorSubtractionUnderflow:
			_ = vint.Add(i, bits)
		case nil:
			bvar[1] |= 1
		}
		// Finally swap R and Q back to restore the iteration state.
		_ = vint.GetSet(i, bvar)
	}
	return nil
}

// Mod applies modulo operation to the provided bits and the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
// In case the division by zero is attempted, ErrorDivisionByZero is returned
func (vint VarInt) Mod(i int, bits Bits) error {
	// For modulo we can just use the fact that
	// in division operation the reminder is left
	// inside tmp bits variable. Reuse all the
	// logic validation from div here.
	if err := vint.Div(i, bits); err != nil {
		return err
	}
	// Get tmp bits variable with reminder inise,
	// don't clear the previous and swap it with vint.
	_ = vint.GetSet(i, bvar(vint, false))
	return nil
}

// Not applies bitwise negation ^ operation to the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
func (vint VarInt) Not(i int) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
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

// And applies bitwise and & operation to the provided bits and the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
func (vint VarInt) And(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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

// Or applies bitwise and | operation to the provided bits and the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
func (vint VarInt) Or(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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

// Xor applies bitwise and ^ operation to the provided bits and the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
// In case the provided bits has different bit len, ErrorUnequalBitLengthCardinality is returned.
func (vint VarInt) Xor(i int, bits Bits) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
	}
	blen := BitLen(vint)
	if blenx := bits.BitLen(); blenx != blen {
		return ErrorUnequalBitLengthCardinality
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

// Rsh applies right shift >> operation to the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative shift is provided, ErrorShiftIsNegative is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
func (vint VarInt) Rsh(i, n int) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that valid shift is provided.
	if n < 0 {
		return ErrorShiftIsNegative
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
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

// Lsh applies left shift << operation to the integer inside VarInt at the provided index.
// In case the operation is used on invalid nil VarInt, ErrorVarIntIsInvalid is returned.
// In case negative shift is provided, ErrorShiftIsNegative is returned.
// In case negative index is provided, ErrorIndexIsNegative is returned.
// In case the provided index is greater than len of VarInt, ErrorIndexIsOutOfRange is returned.
func (vint VarInt) Lsh(i, n int) error {
	// Check explicitly for invalid number.
	if vint == nil {
		return ErrorVarIntIsInvalid
	}
	// Check that valid shift is provided.
	if n < 0 {
		return ErrorShiftIsNegative
	}
	// Check that non negative index was provided.
	if i < 0 {
		return ErrorIndexIsNegative
	}
	// Check that requested index is inside varint range.
	if length := Len(vint); i >= length {
		return ErrorIndexIsOutOfRange
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
