package varint

import (
	"bytes"
	"fmt"
)

var bSpace = []byte(" ")
var bZero = []byte("0")

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

func (bits Bits) Format(f fmt.State, verb rune) {
	if bits == nil {
		fmt.Fprintf(f, "")
		return
	}
	// Closely follow https://pkg.go.dev/math/big#Int.Format.
	// First convert the formatting verb into sub-format verb for bytes.
	var base int
	switch verb {
	case 'b':
		base = 2
	case 'o', 'O':
		base = 8
	case 'd', 's', 'v':
		base = 10
	case 'x', 'X':
		base = 16
	default:
		fmt.Fprintf(f, "%%!%c(varint.Bits=%b)", verb, bits)
		return
	}
	// Second get format prefix from fmt flags.
	var prefix string
	if f.Flag('#') {
		switch verb {
		case 'b':
			prefix = "0b"
		case 'o':
			prefix = "0"
		case 'x':
			prefix = "0x"
		case 'X':
			prefix = "0X"
		}
	}
	if verb == 'O' {
		prefix = "0o"
	}
	// Third print all underlying bytes into temporary buffer with sub-verb format.
	numBytes := bits.Base(base)
	if verb == 'X' {
		numBytes = bytes.ToUpper(numBytes)
	}
	// Number of characters for the three classes of number padding.
	// Left space characters to left of digits for right justification ("%8d").
	// Zero characters (actually cs[0]) as left-most digits ("%.8d").
	// Right space characters to right of digits for left justification ("%-8d").
	var left, zero, right int
	precision, pok := f.Precision()
	if pok && len(numBytes) < precision {
		zero = precision - len(numBytes)
	}
	length := len(prefix) + zero + len(numBytes)
	if width, wok := f.Width(); wok && length < width {
		switch d := width - length; {
		case f.Flag('-'):
			// Pad on the right with spaces; supersedes '0' when both specified.
			right = d
		case f.Flag('0') && !pok:
			// Pad with zeros unless precision also specified.
			zero = d
		default:
			// Pad on the left with spaces.
			left = d
		}
	}
	// Print number as [left pad][prefix][zero pad][digits][right pad]
	for ; left > 0; left-- {
		_, _ = f.Write(bSpace)
	}
	_, _ = f.Write([]byte(prefix))
	for ; zero > 0; zero-- {
		_, _ = f.Write(bZero)
	}
	_, _ = f.Write(numBytes)
	for ; right > 0; right-- {
		_, _ = f.Write(bSpace)
	}
}

func (bits Bits) String() string {
	return fmt.Sprintf("%s", bits)
}

func (bits Bits) Base(base int) []byte {
	return nil
}
