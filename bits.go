package varint

import (
	"fmt"
	"math/big"
)

const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type Bits []uint64

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

func (bits Bits) Uint64() uint64 {
	if b := bits.Bits(); b == 0 || b > 64 {
		return 0
	}
	return bits[1]
}

func (bits Bits) Format(f fmt.State, verb rune) {
	if bits == nil {
		fmt.Fprintf(f, "")
		return
	}
	// TODO for now just reuse big.Int Format here for simplicitly
	// but untimetely after native mod-div is implemented use that.
	bits.BigInt().Format(f, verb)
}

func (bits Bits) String() string {
	return fmt.Sprintf("%s", bits)
}

func (bits Bits) Base(base int) []byte {
	if bits == nil {
		return nil
	}
	switch {
	case base < 2:
		base = 2
	case base > 62:
		base = 62
	}
	// TODO for now just reuse big.Int Format here for simplicitly
	// but untimetely after native mod-div is implemented use that.
	var r []byte
	i, b, m := bits.BigInt(), big.NewInt(int64(base)), big.NewInt(0)
	for i.Uint64() > 0 {
		_, _ = i.DivMod(i, b, m)
		r = append([]byte{digits[m.Uint64()]}, r...)
	}
	return r
}

func (bits Bits) BigInt() *big.Int {
	if bits == nil {
		return nil
	}
	i := big.NewInt(0)
	words := make([]big.Word, 0, len(bits)-1)
	for _, b := range bits[1:] {
		words = append(words, big.Word(b))
	}
	i.SetBits(words)
	return i
}
