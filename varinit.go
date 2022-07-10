package varint

import (
	"math/bits"
)

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

func (vint VarInt) AtInt(i int) (int64, error) {
	result, _, _, _, _, err := vint.atInt(i)
	return int64(result), err
}

func (pvint *VarInt) AddInt(i int, val int64) (bool, error) {
	left, bsize, bshift, low, hiw, err := pvint.atInt(i)
	if err != nil {
		return false, err
	}
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
	left, bsize, bshift, low, hiw, err := pvint.atInt(i)
	if err != nil {
		return false, err
	}
	v := uint64(val)
	if normshift := wsize - bsize; normshift > 0 {
		v = (v << normshift) >> normshift
	}
	result, tip := bits.Sub64(uint64(left), v, 0)
	(*pvint)[low] |= result >> bshift
	(*pvint)[hiw] |= result << bshift
	return tip > 0, nil
}

func (vint VarInt) atInt(i int) (result uint64, bsize, bshift, low, hiw int, err error) {
	if l := len(vint); i >= l {
		return 0, 0, 0, 0, 0, ErrorIndexOutOfRange{Index: i, Length: l}
	}
	bsize = int(vint[0])
	bfrom, bto := bsize*i+wsize, bsize*(i+1)+wsize
	low, hiw = (bfrom-1)/wsize, (bto-1)/wsize
	bshift, normshift := (hiw+1)*wsize-bto, wsize-(bsize%wsize)
	result = ((vint[low] << (bshift + normshift)) >> normshift) | vint[hiw]>>bshift
	return
}
