package varint

import (
	"bytes"
	"fmt"
	"math/big"
	math_bits "math/bits"
	"math/rand"
	"strings"
)

const (
	b62digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	minbase   = 2
	maxbase   = 62
)

type Bits []uint

func NewBits(blen int, bytes []uint) (Bits, error) {
	if blen == 0 {
		return []uint{0}, nil
	}
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	// Calculate delta shift is not zero convert it to
	// shift number to truncate original bits.
	words, bdelta := blen/wsize+(blen%wsize+wsize-1)/wsize, wsize-blen%wsize
	// Calculate min bits size to hold provided bits slice.
	var minblen int
	if lb := len(bytes) - 1; lb > -1 {
		for ; lb > 0; lb-- {
			// Exclude all 0 bytes at the beginning.
			if bytes[lb] != 0 {
				break
			}
		}
		minblen = wsize*(lb) + math_bits.Len(uint(bytes[lb]))
	}
	switch {
	// Special marker, use a guess min bits size.
	case blen < 0:
		blen = minblen
		// Recalculate words number accordingly to new bits len.
		words = blen/wsize + (blen%wsize+wsize-1)/wsize
	// Truncate original bits to provided size.
	case blen < minblen:
		bytes = bytes[:words]
		// If delta shift is equal to word,
		// there is nothing to shift.
		if bdelta != wsize {
			bytes[words-1] = bytes[words-1] << bdelta >> bdelta
		}
	}
	b := make([]uint, words+1)
	b[0] = uint(blen)
	copy(b[1:], bytes)
	return b, nil
}

func NewBitsUint(n uint) (Bits, error) {
	return NewBits(-1, []uint{n})
}

func NewBitsInt(n int) (Bits, error) {
	return NewBits(-1, []uint{uint(n)})
}

func NewBitsBits(bits Bits) (Bits, error) {
	return NewBits(bits.BitLen(), bits.Bytes())
}

func NewBitsRand(blen int, rnd *rand.Rand) (Bits, error) {
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	words := blen/wsize + (blen%wsize+wsize-1)/wsize
	// Generate enough random bits.
	bytes := make([]uint, 0, words)
	for i := 0; i < words; i++ {
		bytes = append(bytes, uint(rnd.Int()))
	}
	return NewBits(blen, bytes)
}

func NewBitsBigInt(i *big.Int) (Bits, error) {
	words := i.Bits()
	bytes := make([]uint, 0, len(words))
	for _, w := range words {
		bytes = append(bytes, uint(w))
	}
	return NewBits(i.BitLen(), bytes)
}

func NewBitsString(s string, base int) (Bits, error) {
	if base < minbase || base > maxbase {
		return nil, ErrorBaseIsOutOfRange{Base: base}
	}
	// Ignore leading + sign.
	ss := strings.TrimPrefix(s, "+")
	// Fail prematurely for empty string input.
	if ss == "" {
		return nil, ErrorStringIsNotValidNumber{String: s, Base: base}
	}
	ls, ubase := len(ss), uint(base)
	// Create a 1 varint to use multiplication and addition operations.
	// The bit len of varint should be at least equal to
	// length of the string * minimum number of bits required to represent base.
	blen := math_bits.Len(ubase) * ls
	vint, err := NewVarInt(blen, 1)
	if err != nil {
		return nil, err
	}
	// Calculate max number with base which fits
	// the word size and simultaneously calculate
	// the max power with base which fits the word size.
	bmax, bpow := ubase, uint(1)
	for max := wmax / ubase; bmax <= max; {
		bmax *= ubase
		bpow++
	}
	bbmax, err := NewBits(blen, []uint{bmax})
	if err != nil {
		return nil, err
	}
	var psum, pi uint
loop:
	for i := 0; i < ls; i++ {
		// Convert next character into base number.
		ch := ss[i]
		var w uint
		switch {
		case ch == '_' && i != 0 && i != ls-1:
			// Allow _ as number separator anywhere,
			// except beginning and end of the number.
			continue loop
		case '0' <= ch && ch <= '9':
			w = uint(ch - '0')
		case 'a' <= ch && ch <= 'z':
			w = uint(ch - 'a' + 10)
		case 'A' <= ch && ch <= 'Z':
			if base <= 36 {
				w = uint(ch - 'A' + 10)
			} else {
				w = uint(ch - 'A' + 36)
			}
		default:
			return nil, ErrorStringIsNotValidNumber{String: s, Base: base}
		}
		if int(w) > base {
			return nil, ErrorStringIsNotValidNumber{String: s, Base: base}
		}
		// Collect intermediate number into buffer.
		psum = psum*ubase + w
		// Then if buffer is full for the base,
		// multiply the number by max base number
		// and add the temp buffer inside.
		pi++
		if pi == bpow {
			if err := vint.Mul(0, bbmax); err != nil {
				return nil, err
			}
			bpsum, err := NewBits(blen, []uint{psum})
			if err != nil {
				return nil, err
			}
			if err := vint.Add(0, bpsum); err != nil {
				return nil, err
			}
			psum, pi = 0, 0
		}
	}
	// Flush last partial sum into the buffer.
	if pi > 0 {
		// Recalculate max number with base which fits
		// into leftover pi iterations.
		bnum, ubasex := uint(1), ubase
		for pi > 0 {
			if pi&1 != 0 {
				bnum *= ubasex
			}
			ubasex *= ubasex
			pi >>= 1
		}
		bbmax, err := NewBits(blen, []uint{bnum})
		if err != nil {
			return nil, err
		}
		if err := vint.Mul(0, bbmax); err != nil {
			return nil, err
		}
		bpsum, err := NewBits(blen, []uint{psum})
		if err != nil {
			return nil, err
		}
		if err := vint.Add(0, bpsum); err != nil {
			return nil, err
		}
	}
	// Get final result into tmp buffer and return it
	// as new bits with deduced bit len.
	if err := vint.Get(0, bbmax); err != nil {
		return nil, err
	}
	return NewBits(-1, bbmax.Bytes())
}

func (bits Bits) BitLen() int {
	if bits == nil {
		return 0
	}
	return int(bits[0])
}

func (bits Bits) Bytes() []uint {
	if bits == nil {
		return nil
	}
	return bits[1:]
}

func (bits Bits) Empty() bool {
	if bits == nil {
		return true
	}
	if bits.BitLen() == 0 {
		return true
	}
	for _, b := range bits.Bytes() {
		if b != 0 {
			return false
		}
	}
	return true
}

func (bits Bits) Uint() (uint, error) {
	blen := bits.BitLen()
	switch {
	case blen == 0:
		return 0, nil
	case blen > wsize:
		return bits[1], ErrorUintIntOveflow{BitLen: blen}
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
		return int(bits[1]), ErrorUintIntOveflow{BitLen: blen}
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

func (bits Bits) String() string {
	return fmt.Sprintf("[%d]{%X}", bits.BitLen(), bits)
}

func (bits Bits) Format(f fmt.State, verb rune) {
	// Start with parsing preferred base and prefix.
	var base int
	var prefix string
	var upper bool
	switch verb {
	case 'b':
		base = 2
	// A special prefix treatment for 'O'.
	case 'O':
		prefix = "0o"
		fallthrough
	case 'o':
		base = 8
	case 'd', 's', 'v':
		base = 10
	case 'X':
		upper = true
		fallthrough
	case 'x':
		base = 16
	// Use default case as catch all to
	// print extra debug bit len information.
	default:
		return
	}
	b, _ := bits.Base(base)
	if f.Flag('#') {
		switch verb {
		case 'b':
			prefix = "0b"
		case 'o':
			prefix = "0"
		case 'x':
			prefix = "0x"
		// A special bytes treatment for 'X'.
		case 'X':
			prefix = "0X"
		}
	}
	if upper {
		b = bytes.ToUpper(b)
	}
	// Calculate padding on left and zeros padding.
	var left, zeros int
	if width, ok := f.Width(); ok {
		if d := width - len(prefix) - len(b); d > 0 {
			if f.Flag('0') {
				zeros = d
			} else {
				left = d
			}
		}
	}
	// Print final number as [left pad][prefix][zero pad][bytes].
	var bs, b0 []byte = []byte{' '}, []byte{'0'}
	for ; left > 0; left-- {
		_, _ = f.Write(bs)
	}
	_, _ = f.Write([]byte(prefix))
	for ; zeros > 0; zeros-- {
		_, _ = f.Write(b0)
	}
	_, _ = f.Write(b)
}

func (bits Bits) Base(base int) ([]byte, error) {
	if base < minbase || base > maxbase {
		return nil, ErrorBaseIsOutOfRange{Base: base}
	}
	blen, ubase := bits.BitLen(), uint(base)
	if blen == 0 {
		return []byte{'0'}, nil
	}
	if bmin := math_bits.Len(ubase); blen < bmin {
		blen = bmin
	}
	// Create a tmp buffer variable for bits.
	b, err := NewBits(blen, bits.Bytes())
	if err != nil {
		return nil, err
	}
	// Create bits for provided base number for
	// all the computations.
	bs, err := NewBits(blen, []uint{ubase})
	if err != nil {
		return nil, err
	}
	// Create a 1 varint to use division and modulo operations.
	// And set it to the bits value first.
	vint, err := NewVarInt(blen, 1)
	if err != nil {
		return nil, err
	}
	if err := vint.Set(0, b); err != nil {
		return nil, err
	}
	// Preallocate approximate resulting bytes.
	r := make([]byte, 0, blen/base+1)
	for run := true; run; {
		// Start with division operation
		// to advance to next digit.
		if err := vint.Div(0, bs); err != nil {
			return nil, err
		}
		if err := vint.GetSet(0, b); err != nil {
			return nil, err
		}
		// Record the division result for the loop.
		run = !b.Empty()
		// Then take modulo from the value.
		if err := vint.Mod(0, bs); err != nil {
			return nil, err
		}
		// Then take it value by swapping it with
		// tmp variable, note then it's safe to get
		// uint value directly here because modulo
		// at most is equal to 62.
		if err := vint.GetSet(0, b); err != nil {
			return nil, err
		}
		mod, _ := b.Uint()
		r = append(r, b62digits[mod])
		// Override original value back and continue iterating.
		if err := vint.Get(0, b); err != nil {
			return nil, err
		}
	}
	// Reverse the resulting bytes.
	for i, j := 0, len(r)-1; i <= j; {
		r[i], r[j] = r[j], r[i]
		i++
		j--
	}
	return r, nil
}
