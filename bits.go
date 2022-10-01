package varint

import (
	"fmt"
	"math/big"
	math_bits "math/bits"
)

// TODO for format, parse and base operations for now just reuse big.Int for simplicitly
// untimetely after native mod-div is implemented use that instead.

const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type Bits []uint

func NewBits(bsize int, bits []uint) (Bits, error) {
	if bsize == 0 {
		return []uint{0}, nil
	}
	// Calculate min bits size to hold provided bits slice.
	minbsize := 0
	if lb := len(bits) - 1; lb > -1 {
		minbsize = wsize*(lb) + math_bits.Len(uint(bits[lb]))
	}
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	words, bsizemod := bsize/wsize, bsize%wsize
	if bsizemod > 0 {
		words++
	}
	switch {
	// Special marker, use a guess min bits size.
	case bsize < 0:
		bsize = minbsize
	// Truncate original bits to provided size.
	case bsize < minbsize:
		bits = bits[:words]
		shift := wsize - bsizemod
		bits[words-1] = bits[words-1] << shift >> shift
	}
	b := make([]uint, words+1)
	b[0] = uint(bsize)
	copy(b[1:], bits)
	return b, nil
}

func NewBitsUint(bsize int, n uint) (Bits, error) {
	return NewBits(bsize, []uint{n})
}

func NewBitsBigInt(i *big.Int) (Bits, error) {
	words := i.Bits()
	bits := make([]uint, 0, len(words))
	for _, w := range words {
		bits = append(bits, uint(w))
	}
	return NewBits(i.BitLen(), bits)
}

func NewBitsString(s string, base int) (Bits, error) {
	if base < 2 || base > 62 {
		return nil, ErrorBitsBaseOveflow{Base: base}
	}
	i := new(big.Int)
	_, ok := i.SetString(s, base)
	if !ok {
		return nil, ErrorStringIsNotValidBaseNumber{String: s, Base: base}
	}
	return NewBitsBigInt(i)
}

func (bits Bits) Equal(b Bits) bool {
	if bits.Bits() != b.Bits() {
		return false
	}
	bitsb, bb := bits.Bytes(), b.Bytes()
	if len(bitsb) != len(bb) {
		return false
	}
	for i := 0; i < len(bitsb); i++ {
		if bitsb[i] != bb[i] {
			return false
		}
	}
	return true
}

func (bits Bits) Bits() int {
	return int(bits[0])
}

func (bits Bits) Bytes() []uint {
	return bits[1:]
}

func (bits Bits) Uint() (uint, error) {
	b := bits.Bits()
	if b == 0 {
		return 0, nil
	}
	if b > wsize {
		return 0, ErrorBitsUintOveflow{Bits: b}
	}
	return bits[1], nil
}

func (bits Bits) BigInt() *big.Int {
	i := new(big.Int)
	bytes := bits.Bytes()
	words := make([]big.Word, 0, len(bytes))
	for _, b := range bytes {
		words = append(words, big.Word(b))
	}
	i.SetBits(words)
	return i
}

func (bits Bits) Format(f fmt.State, verb rune) {
	if verb == 'v' {
		fmt.Fprintf(f, "[%d]{%X}", bits.Bits(), bits)
		return
	}
	bits.BigInt().Format(f, verb)
}

func (bits Bits) String() string {
	return fmt.Sprintf("%s", bits)
}

func (bits Bits) Base(base int) ([]byte, error) {
	if base < 2 || base > 62 {
		return nil, ErrorBitsBaseOveflow{Base: base}
	}
	var r []byte
	i, b, m := bits.BigInt(), big.NewInt(int64(base)), new(big.Int)
	for i.Uint64() > 0 {
		_, _ = i.DivMod(i, b, m)
		r = append([]byte{digits[m.Uint64()]}, r...)
	}
	return r, nil
}
