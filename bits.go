package varint

import (
	"bytes"
	"fmt"
)

const digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var bSpace = []byte(" ")
var bZero = []byte("0")

type Bits []uint64

func (bits Bits) Value() []uint64 {
	return bits
}

func (bits Bits) Format(f fmt.State, verb rune) {
	if bits == nil {
		fmt.Fprintf(f, "")
		return
	}
	// Closely follow https://pkg.go.dev/math/big#Int.Format.
	// First convert the formatting verb into sub-format verb for bytes.
	var subVerb string
	switch verb {
	case 'b':
		subVerb = "%b"
	case 'o', 'O':
		subVerb = "%o"
	case 'd', 's', 'v':
		subVerb = "%d"
	case 'x':
		subVerb = "%x"
	case 'X':
		subVerb = "%X"
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
	var buf bytes.Buffer
	for i := len(bits) - 1; i >= 0; i-- {
		fmt.Fprintf(&buf, subVerb, bits[i])
	}
	// Number of characters for the three classes of number padding.
	// Left space characters to left of digits for right justification ("%8d").
	// Zero characters (actually cs[0]) as left-most digits ("%.8d").
	// Right space characters to right of digits for left justification ("%-8d").
	var left, zero, right int
	precision, pok := f.Precision()
	if pok && buf.Len() < precision {
		zero = precision - buf.Len()
	}
	length := len(prefix) + zero + buf.Len()
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
		f.Write(bSpace)
	}
	f.Write([]byte(prefix))
	for ; zero > 0; zero-- {
		f.Write(bZero)
	}
	f.Write(buf.Bytes())
	for ; right > 0; right-- {
		f.Write(bSpace)
	}
}

func (bits Bits) String() string {
	return fmt.Sprintf("%s", bits)
}

func (bits Bits) ToBase(base int) []byte {
	return nil
}
