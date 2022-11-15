package varint

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	math_bits "math/bits"
	"math/rand"
	"strings"
)

// b62digits const preallocated alphabet.
const b62digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Bits is immutable intermediate representation for single integer inside VarInt.
// It's used as data transfer object for most of VarInt operations, and
// provides a number of convenient methods to convert it back and forth
// between other numerical presentations. Bits type somewhat resembles
// unsigned big.Int internally and provides similar transformations.
// However, note that by design most of Bits operations are not fast and allocate memory
// therefore should be only used to bootstrap and pass data to VarIant and not as standalone type.
type Bits []uint

// NewBits allocates and returns new Bits instance with predefined bit length
// and optional initialization value bytes slice. In case value bytes slice
// doesn't fit into the provided bit length, it is truncated to fit into the provided bit len.
// In case the provided bit len is negative number, actual bit len is calculated from the bytes slice.
// In case the provided bit len is 0, empty Bits marker is returned.
// See Bits type for more details.
func NewBits(blen int, bytes []uint) Bits {
	if blen == 0 {
		return []uint{0}
	}
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	// Calculate delta shift is not zero convert it to
	// shift number to truncate original bits.
	words, bdelta := blen/wsize+(blen%wsize+wsize-1)/wsize, wsize-blen%wsize
	// Calculate min bits size to hold the provided bits slice.
	var minblen int
	if lb := len(bytes) - 1; lb > -1 {
		for ; lb > 0; lb-- {
			// Exclude all 0 bytes at the beginning.
			if bytes[lb] != 0 {
				break
			}
		}
		minblen = wsize*lb + math_bits.Len(uint(bytes[lb]))
	}
	switch {
	// Special marker, use a guess min bits size.
	case blen < 0:
		blen = minblen
		// Recalculate words number accordingly to new bits len.
		words = blen/wsize + (blen%wsize+wsize-1)/wsize
	// Truncate original bits to the provided len.
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
	return b
}

// NewBitsUint allocates and returns new Bits instance with
// deduced bit length to exactly fit the provided number.
// See Bits type for more details.
func NewBitsUint(n uint) Bits {
	return NewBits(-1, []uint{n})
}

// NewBitsBits allocates, copies and returns new Bits instance
// from the provided bit len and Bits, effectively making a deep copy of it.
// See Bits type for more details.
func NewBitsBits(blen int, bits Bits) Bits {
	return NewBits(blen, bits.Bytes())
}

// NewBitsRand allocates and returns new Bits instance filled with
// random bytes from provided Rand that fits the provided bit length.
// See Bits type for more details.
func NewBitsRand(blen int, rnd *rand.Rand) Bits {
	// Calculate number of whole words plus
	// one word if partial mod word is needed.
	words := blen/wsize + (blen%wsize+wsize-1)/wsize
	// Generate enough random bytes.
	bytes := make([]uint, 0, words)
	for i := 0; i < words; i++ {
		bytes = append(bytes, uint(rnd.Int()))
	}
	return NewBits(blen, bytes)
}

// NewBitsBigInt allocates, copies and returns new Bits instance
// from the provided big.Int, it deduces bit length to exactly fit
// the provided number. In case nil is provided empty Bits marker is returned.
// See Bits type for more details.
func NewBitsBigInt(i *big.Int) Bits {
	if i == nil {
		return NewBitsUint(0)
	}
	words := i.Bits()
	bytes := make([]uint, 0, len(words))
	for _, w := range words {
		bytes = append(bytes, uint(w))
	}
	return NewBits(i.BitLen(), bytes)
}

// NewBitsString parses, allocates and returns new Bits instance
// from the provided string and base, it deduces bit length to exactly fit
// the provided number. Valid base values are inside [2, 62], base values below 2 are
// converted to 2, base values above 62 are converted to 62. Leading plus '+' sings are ignored.
// Separating underscore '_' signs are allowed and also ignored. In case empty or invalid
// string is provided a special nil Bits marker is returned. The implementation follows big.Int.
// See Bits type for more details.
func NewBitsString(s string, base int) Bits {
	// Fix unsuported bases to closest supported.
	const minb, maxb = 2, 62
	switch {
	case base < minb:
		base = minb
	case base > maxb:
		base = maxb
	}
	// Ignore leading '+' sign.
	ss := strings.TrimPrefix(s, "+")
	// Fail prematurely for empty string input.
	if ss == "" {
		return nil
	}
	ls, ubase := len(ss), uint(base)
	// Create a 1 varint to use multiplication and addition operations.
	// The bit len of varint should be at least equal to
	// length of the string * minimum number of bits required to represent base.
	blen := math_bits.Len(ubase) * ls
	vint, _ := NewVarInt(blen, 1)
	// Calculate max number with base which fits
	// the word size and simultaneously calculate
	// the max power with base which fits the word size.
	bmax, bpow := ubase, uint(1)
	for max := math.MaxUint / ubase; bmax <= max; {
		bmax *= ubase
		bpow++
	}
	bbmax := NewBits(blen, []uint{bmax})
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
			// In case any unsuported char yield empty bits.
			return nil
		}
		// If a char is larger than provided base yield empty bits.
		if int(w) > base {
			return nil
		}
		// Collect intermediate number into buffer.
		psum = psum*ubase + w
		// Then if buffer is full for the base,
		// multiply the number by max base number
		// and add the temp buffer inside.
		pi++
		if pi == bpow {
			_ = vint.Mul(0, bbmax)
			_ = vint.Add(0, NewBits(blen, []uint{psum}))
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
		_ = vint.Mul(0, NewBits(blen, []uint{bnum}))
		_ = vint.Add(0, NewBits(blen, []uint{psum}))
	}
	// Get final result into tmp buffer and return it
	// as new bits with deduced bit len.
	_ = vint.Get(0, bbmax)
	return NewBits(-1, bbmax.Bytes())
}

// BitLen returns bit length of the Bits instance.
// It's safe to use on nil Bits, 0 is returned.
func (bits Bits) BitLen() int {
	if bits == nil {
		return 0
	}
	return int(bits[0])
}

// Bytes returns value bytes slice of the Bits instance.
// It's safe to use on nil Bits, {0} is returned.
func (bits Bits) Bytes() []uint {
	if bits.BitLen() == 0 {
		return []uint{0}
	}
	return bits[1:]
}

// Empty returns true on nil Bits, or if the bit length is 0
// or if value bytes slice is empty, otherwise returns false.
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

// Uint returns the low word from value bytes slice of the Bits instance.
// It's safe to use on nil Bits, 0 is returned.
func (bits Bits) Uint() uint {
	if bits.BitLen() == 0 {
		return 0
	}
	return bits[1]
}

// BigInt allocates and returns a big.Int from value bytes slice of the Bits instance.
// It's safe to use on nil Bits, 0 is returned.
func (bits Bits) BigInt() *big.Int {
	i := big.NewInt(0)
	if bits.BitLen() == 0 {
		return i
	}
	bytes := bits.Bytes()
	words := make([]big.Word, 0, len(bytes))
	for _, b := range bytes {
		words = append(words, big.Word(b))
	}
	return i.SetBits(words)
}

// String returns a hex '%#X' string representation of the Bits instance
// decorated with bit length, in format '[blen]{hex_bytes}'.
// It's safe to use on nil Bits, [0]{0x0} is returned. Implements fmt.Stringer.
func (bits Bits) String() string {
	return fmt.Sprintf("[%d]{%#X}", bits.BitLen(), bits)
}

// Format formats the Bits instance accordingly to provided format,
// most numeric formats are supported as well as #, 0 flags and pad width flag.
// In case invalid format is provided nothing is returned.
// It's safe to use on nil Bits, empty value is returned.
// Implements fmt.Formatter. The implementation follows big.Int.
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
	default:
		return
	}
	b := bits.To(base)
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

// To allocates and returns []byte representation of the Bits instance
// using the provided base. Valid base values are inside [2, 62], base values below
// 2 are converted to 2, base values above 62 are converted to 62.
// It's safe to use on nil Bits, {'0'} is returned. The implementation follows big.Int.
func (bits Bits) To(base int) []byte {
	// Fix unsuported bases to closest supported.
	const minb, maxb = 2, 62
	switch {
	case base < minb:
		base = minb
	case base > maxb:
		base = maxb
	}
	blen, ubase := bits.BitLen(), uint(base)
	if blen == 0 {
		return []byte{'0'}
	}
	if bmin := math_bits.Len(ubase); blen < bmin {
		blen = bmin
	}
	// Create a tmp buffer variable for bits.
	b := NewBits(blen, bits.Bytes())
	// Create bits for provided base number for
	// all the computations.
	bs := NewBits(blen, []uint{ubase})
	// Create a 1 varint to use division and modulo operations.
	// And set it to the bits value first.
	vint, _ := NewVarInt(blen, 1)
	_ = vint.Set(0, b)
	// Preallocate approximate resulting bytes.
	r := make([]byte, 0, blen/base+1)
	for run := true; run; {
		// Start with division operation
		// to advance to next digit.
		_ = vint.Div(0, bs)
		_ = vint.GetSet(0, b)
		// Record the division result for the loop.
		run = !b.Empty()
		// Then take modulo from the value.
		_ = vint.Mod(0, bs)
		// Then take it value by swapping it with
		// tmp variable, note then it's safe to get
		// uint value directly here because modulo
		// at most is equal to 62.
		_ = vint.GetSet(0, b)
		r = append(r, b62digits[b.Uint()])
		// Override original value back and continue iterating.
		_ = vint.Get(0, b)
	}
	// Reverse the resulting bytes.
	for i, j := 0, len(r)-1; i <= j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return r
}
