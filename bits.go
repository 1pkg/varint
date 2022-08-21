package varint

import (
	"fmt"
	"math"
	"math/big"
)

// TODO for format, parse and base operations for now just reuse big.Int for simplicitly
// untimetely after native mod-div is implemented use that instead.

const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func minbsize(i uint64) uint64 {
	return uint64(math.Ceil(math.Log2(float64(i))))
}

type Bits []uint64

func NewBits(bits []uint64) Bits {
	l := len(bits) - 1
	if l < 0 {
		return nil
	}
	bsize := uint64(wsize*l) + minbsize(bits[l])
	if bsize == 0 {
		return nil
	}
	b := make([]uint64, l+2)
	b[0] = bsize
	copy(b[1:], bits)
	return b
}

func NewBitsUint64(n uint64) Bits {
	if n == 0 {
		return nil
	}
	return []uint64{minbsize(n), n}
}

func NewBitsBigInt(i *big.Int) (Bits, error) {
	wbits := i.Bits()
	lw := len(wbits)
	bits := make([]uint64, 0, lw/2+1)
	for j := 0; j < lw; j += 2 {
		// Do the same big.Int multi words check here.
		if j == lw-1 {
			bits = append(bits, uint64(wbits[j]))
			continue
		}
		bits = append(bits, uint64(wbits[j+1])<<32|uint64(wbits[j]))
	}
	return NewBits(bits), nil
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
	return bits.Bits() == b.Bits() && bits.EqualBytes(b)
}

func (bits Bits) EqualBytes(b Bits) bool {
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
	if bits == nil {
		return 0
	}
	return int(bits[0])
}

func (bits Bits) Bytes() []uint64 {
	if bits == nil {
		return nil
	}
	return bits[1:]
}

func (bits Bits) Uint64() (uint64, error) {
	b := bits.Bits()
	if b == 0 {
		return 0, nil
	}
	if b > 64 {
		return 0, ErrorBitsUint64Oveflow{Bits: b}
	}
	return bits[1], nil
}

func (bits Bits) BigInt() *big.Int {
	if bits == nil {
		return nil
	}
	i := new(big.Int)
	words := make([]big.Word, 0, (len(bits)-1)*2)
	for _, b := range bits[1:] {
		// Do the same big.Int multi words check here.
		if w := big.Word(b); uint64(w) == b {
			words = append(words, w)
			continue
		}
		words = append(words, big.Word(b))
		words = append(words, big.Word(b>>32))
	}
	i.SetBits(words)
	return i
}

func (bits Bits) Format(f fmt.State, verb rune) {
	if bits == nil {
		fmt.Fprintf(f, "")
		return
	}
	bits.BigInt().Format(f, verb)
}

func (bits Bits) String() string {
	return fmt.Sprintf("%s", bits)
}

func (bits Bits) Base(base int) ([]byte, error) {
	if bits == nil {
		return nil, nil
	}
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
