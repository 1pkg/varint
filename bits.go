package varint

import (
	"fmt"
	"math/big"
	math_bits "math/bits"
	"math/rand"
)

// TODO for format, parse and base operations for now just reuse big.Int for simplicitly
// untimetely after native mod-div is implemented use that instead.

const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type Bits []uint

func NewBits(blen int, bits []uint) (Bits, error) {
	if blen == 0 {
		return []uint{0}, nil
	}
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	words, bdelta := blen/wsize, blen%wsize
	if bdelta > 0 {
		words++
		// If delta is not zero convert it to
		// shift number to truncate original bits.
		bdelta = wsize - bdelta
	}
	// Calculate min bits size to hold provided bits slice.
	var minblen int
	if lb := len(bits) - 1; lb > -1 {
		minblen = wsize*(lb) + math_bits.Len(uint(bits[lb]))
	}
	switch {
	// Special marker, use a guess min bits size.
	case blen < 0:
		blen = minblen
	// Truncate original bits to provided size.
	case blen < minblen:
		bits = bits[:words]
		bits[words-1] = bits[words-1] << bdelta >> bdelta
	}
	b := make([]uint, words+1)
	b[0] = uint(blen)
	copy(b[1:], bits)
	return b, nil
}

func NewBitsUint(n uint) (Bits, error) {
	return NewBits(wsize, []uint{n})
}

func NewBitsInt(n int) (Bits, error) {
	return NewBits(wsize, []uint{uint(n)})
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
		return nil, ErrorBaseIsOutOfRange{Base: base}
	}
	i := new(big.Int)
	_, ok := i.SetString(s, base)
	if !ok {
		return nil, ErrorStringIsNotValidNumber{String: s, Base: base}
	}
	return NewBitsBigInt(i)
}

func NewBitsRand(blen int, rnd *rand.Rand) (Bits, error) {
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	words := blen/wsize + (blen%wsize+wsize-1)/wsize
	// Generate enough random bits.
	bits := make([]uint, 0, words)
	for i := 0; i < words; i++ {
		bits = append(bits, uint(rnd.Int()))
	}
	return NewBits(blen, bits)
}

func (bits Bits) BitLen() int {
	return int(bits[0])
}

func (bits Bits) Bytes() []uint {
	return bits[1:]
}

func (bits Bits) Uint() (uint, error) {
	blen := bits.BitLen()
	switch {
	case blen == 0:
		return 0, nil
	case blen > wsize:
		return 0, ErrorBitLengthUintOveflow{BitLen: blen}
	default:
		return bits[1], nil
	}
}

func (bits Bits) Int() (int, error) {
	blen := bits.BitLen()
	switch {
	case blen == 0:
		return 0, nil
	case blen > wsize:
		return 0, ErrorBitLengthUintOveflow{BitLen: blen}
	default:
		return int(bits[1]), nil
	}
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
		fmt.Fprintf(f, "[%d]{%X}", bits.BitLen(), bits)
		return
	}
	bits.BigInt().Format(f, verb)
}

func (bits Bits) String() string {
	return fmt.Sprintf("%s", bits)
}

func (bits Bits) Base(base int) ([]byte, error) {
	if base < 2 || base > 62 {
		return nil, ErrorBaseIsOutOfRange{Base: base}
	}
	var r []byte
	i, b, m := bits.BigInt(), big.NewInt(int64(base)), new(big.Int)
	for i.Uint64() > 0 {
		_, _ = i.DivMod(i, b, m)
		r = append([]byte{digits[m.Uint64()]}, r...)
	}
	return r, nil
}
