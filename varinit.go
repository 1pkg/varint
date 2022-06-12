package varint

import (
	"fmt"
	"math/bits"
)

const wsize = 8

type signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type VarInt []uint64

func NewVarInt(bits, count int) *VarInt {
	size := (bits*count+wsize-1)/wsize + 1
	vint := VarInt(make([]uint64, size))
	vint[0] = uint64(bits)
	return &vint
}

func atInt[T signed](vint VarInt, i int) (val T, bsize, low, hiw, shift int, err error) {
	if l := len(vint); i >= l {
		return 0, 0, 0, 0, 0, fmt.Errorf("index out of range [%d] with length %d", i, l)
	}
	bsize = int(vint[0])
	bfrom, bto := bsize*i, bsize*(i+1)
	low, hiw = bfrom/wsize, bto/wsize
	bshift, normshift := (hiw+1)*wsize-bto, wsize-(bsize%wsize)
	result := ((vint[low] << (bshift + normshift)) >> normshift) | vint[hiw]>>bshift
	return T(result), bsize, low, hiw, shift, nil
}

func AtInt[T signed](vint VarInt, i int) (val T, err error) {
	result, _, _, _, _, err := atInt[T](vint, i)
	return result, err
}

func AddInt[T signed](vint *VarInt, i int, val T) (overflow bool, err error) {
	v := *vint
	left, bsize, low, hiw, bshift, err := atInt[T](v, i)
	if err != nil {
		return false, err
	}
	right := uint64(val)
	if normshift := wsize - bsize; normshift > 0 {
		right = (right << normshift) >> normshift
	}
	var result, tip uint64
	if (int64(left) < 0) == (val < 0) {
		result, tip = bits.Add64(uint64(left), right, 0)
	} else {
		result, tip = bits.Sub64(uint64(left), right, 0)
	}
	v[low] |= result >> bshift
	v[hiw] |= result << bshift
	overflow = tip > 0
	return
}

func SubInt[T signed](vint *VarInt, i int, val T) (overflow bool, err error) {
	return AddInt(vint, i, val*-1)
}
