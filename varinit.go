package varint

import "math/bits"

const wsize = 8

type VarInt []uint64

func NewVarInt(bits, length int) (*VarInt, error) {
	if bits <= 0 {
		return nil, ErrorBitsIsNotPositive{Bits: bits}
	}
	if length <= 0 {
		return nil, ErrorLengthIsNotPositive{Length: length}
	}
	size := (bits*length+wsize-1)/wsize + 1
	vint := VarInt(make([]uint64, size))
	vint[0] = uint64(bits)
	return &vint, nil
}

func (vint VarInt) AtBits(i int) ([]uint64, error) {
	if l := len(vint) - 1; i >= l {
		return nil, ErrorIndexOutOfRange{Index: i, Length: l}
	}
	bsize := int(vint[0])
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize-1
	low, hiw := (bfrom-1)/wsize, (bto-1)/wsize
	// Calculate shifting to fix the result.
	lbshift, hbshift := bfrom-(low)*wsize-1, (hiw+1)*wsize-bto
	// Slice words betwen low and high index and fix last and first word.
	result := vint[low : hiw+1]
	result[len(result)-1] >>= hbshift
	result[len(result)-1] <<= hbshift
	result[0] <<= lbshift
	// Iterate over all result parts and fix shifting accordingly.
	for i := 1; i < len(result); i++ {
		result[i-1] |= result[i] >> (wsize - lbshift)
		result[i] <<= lbshift
	}
	return result, nil
}

func (vint VarInt) AtInt(i int) (int64, error) {
	// Check that requested index is inside varint range.
	if l := len(vint) - 1; i >= l {
		return 0, ErrorIndexOutOfRange{Index: i, Length: l}
	}
	// Check that resulting int64 can hold full bits representation.
	bsize := int(vint[0])
	if bsize > wsize {
		return 0, ErrorBitsInt64Oveflow{Bits: bsize}
	}
	// Calculate starting and ending bit with
	// starting and ending index inside vint respecitvely.
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize-1
	low, hiw := (bfrom-1)/wsize, (bto-1)/wsize
	// Calculate shifting to fix the int64 result.
	lbshift, hbshift := bfrom-(low)*wsize-1, (hiw+1)*wsize-bto
	result := ((vint[low] << lbshift) >> lbshift) | vint[hiw]>>hbshift
	return int64(result), nil
}

func (pvint *VarInt) AddInt(i int, val int64) (bool, error) {
	// TODO
	left, bsize, bshift, low, hiw, err := pvint.atInt(i)
	if err != nil {
		return false, err
	}
	// This fixes overflow of original vint bits size for
	// provided value. Consider return int value overflow error instead.
	v := uint64(val)
	if normshift := wsize - bsize; normshift > 0 {
		v = (v << normshift) >> normshift
	}
	result, tip := bits.Add64(uint64(left), v, 0)
	(*pvint)[low] |= result >> bshift
	(*pvint)[hiw] |= result << bshift
	return tip > 0, nil
}

func (pvint *VarInt) SubInt(i int, val int64) (underflow bool, err error) {
	// TODO
	left, bsize, bshift, low, hiw, err := pvint.atInt(i)
	if err != nil {
		return false, err
	}
	// This fixes overflow of original vint bits size for
	// provided value. Consider return int value overflow error instead.
	v := uint64(val)
	if normshift := wsize - bsize; normshift > 0 {
		v = (v << normshift) >> normshift
	}
	result, tip := bits.Sub64(uint64(left), v, 0)
	(*pvint)[low] |= result >> bshift
	(*pvint)[hiw] |= result << bshift
	return tip > 0, nil
}
