package varint

import (
	"encoding/binary"
	"io"
	"sort"
)

// bvar internal accessor that returns reserved Bits variable.
// The Bits variable is collocated on VarInt itself, so bvar
// doesn't allocate any new memory. The reserved Bits variable
// is appended to the end of any VarInt and used internally for many operations
// as a compuatation temporary buffer, including: Mul, Div, Mod, Sort.
// bvar is standalone function by choice to make VarInt more consistent and ergonomic.
func bvar(vint VarInt, empty bool) Bits {
	if vint == nil {
		return nil
	}
	cap := (BitLen(vint)*Len(vint)+wsize-1)/wsize + 2
	b := Bits(vint[cap:])
	if !empty {
		return b
	}
	// Clear var bits state from prev manipulations.
	for i := 1; i < len(vint)-cap; i++ {
		b[i] = 0
	}
	return b
}

// Len returns length of the VarInt instance.
// Len is standalone function by choice to make
// VarInt more consistent and ergonomic.
// It's safe to use on nil VarInt, 0 is returned.
func Len(vint VarInt) int {
	if vint == nil {
		return 0
	}
	return int(vint[0])
}

// BitLen returns bit length of the VarInt instance.
// BitLen is standalone function by choice to make
// VarInt more consistent and ergonomic.
// It's safe to use on nil VarInt, 0 is returned.
func BitLen(vint VarInt) int {
	if vint == nil {
		return 0
	}
	return int(vint[1])
}

// Sortable returns sort.Interface adapter for provided VarInt
// that is capable to work with standard sort package.
func Sortable(vint VarInt) sort.Interface {
	return sortable{vint: vint, bits: bvar(vint, true)}
}

// Encode lazily encodes the provided VarInt into io.ReadCloser.
// It uses binary.BigEndian encoding for the number. It also starts
// a goroutine to encode the number lazily, so the returned io.ReadCloser
// has to be always closed otherwise goroutine leak occures.
func Encode(vint VarInt) io.ReadCloser {
	const bzise = 8
	r, w := io.Pipe()
	go func() {
		for i, l, d, u := 0, len(vint)-1, wsize*wsize, wsize/bzise; i <= l; i += d {
			// Round to max len for the last batch.
			to := i + d
			if to > l {
				to = l
			}
			chunk := vint[i:to]
			bytes := make([]byte, len(chunk)*u)
			// Use system word byte size when encoding.
			for i, n := range chunk {
				switch wsize {
				case 64:
					binary.BigEndian.PutUint64(bytes[i*u:], uint64(n))
				case 32:
					binary.BigEndian.PutUint32(bytes[i*u:], uint32(n))
				}
			}
			if _, err := w.Write(bytes); err != nil {
				_ = w.CloseWithError(err)
			}
		}
		_ = w.Close()
	}()
	return r
}

// Decode dencodes the io.ReadCloser result from Encode into the provided VarInt.
// The provided VarInt has to be already preallocated, otherwise the ErrorVarIntIsInvalid
// is returned. The provided io.ReadCloser has to be encoded with binary.BigEndian iside,
// otherwise the ErrorReaderIsNotDecodable is returned.
func Decode(r io.ReadCloser, vint VarInt) error {
	const bzise = 8
	bytes := make([]byte, wsize*wsize)
	for k, l, u := 0, len(vint), wsize/bzise; ; {
		n, err := r.Read(bytes)
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		// Check that size of byte sequence is legit.
		case n%u != 0:
			return ErrorReaderIsNotDecodable
		}
		bytes = bytes[:n]
		// Check if vint fits the read bytes.
		if k+n/u >= l {
			return ErrorVarIntIsInvalid
		}
		// Use system word byte size when decoding.
		for i := 0; i < n/u; i++ {
			switch wsize {
			case 64:
				vint[k] = uint(binary.BigEndian.Uint64(bytes[i*u:]))
			case 32:
				vint[k] = uint(binary.BigEndian.Uint32(bytes[i*u:]))
			}
			k++
		}
	}
}

// Compare returns an integer comparing of the provided Bits.
// The result is 0 if Bits a == b, -1 if Bits a < b, and +1 Bits if a > b.
// Currently it only compare bits with the same bit len akin to VarInt operations.
func Compare(abits, bbits Bits) int {
	switch lblen, rblen := abits.BitLen(), bbits.BitLen(); {
	case lblen < rblen:
		return -1
	case lblen > rblen:
		return 1
	}
	for i := len(abits) - 1; i > 0; i-- {
		switch {
		case abits[i] < bbits[i]:
			return -1
		case abits[i] > bbits[i]:
			return 1
		}
	}
	return 0
}
