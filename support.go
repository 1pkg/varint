package varint

import (
	"encoding/binary"
	"io"
	"sort"
)

func Compare(lbits, rbits Bits) int {
	switch lblen, rblen := lbits.BitLen(), rbits.BitLen(); {
	case lblen < rblen:
		return -1
	case lblen > rblen:
		return 1
	}
	for i := len(lbits) - 1; i > 0; i-- {
		switch {
		case lbits[i] < rbits[i]:
			return -1
		case lbits[i] > rbits[i]:
			return 1
		}
	}
	return 0
}

func Equal(lbits, rbits Bits) bool {
	return Compare(lbits, rbits) == 0
}

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

func Len(vint VarInt) int {
	if vint == nil {
		return 0
	}
	return int(vint[0])
}

func BitLen(vint VarInt) int {
	if vint == nil {
		return 0
	}
	return int(vint[1])
}

func Sortable(vint VarInt) sort.Interface {
	return sortable{vint: vint, bits: bvar(vint, true)}
}

func Encode(vint VarInt) io.ReadCloser {
	const buflen, uisize = 1024, wsize / 8
	r, w := io.Pipe()
	go func() {
		for i, l := 0, len(vint); i < l; i += buflen {
			to := i + buflen
			if to > l-1 {
				to = l - 1
			}
			chunk := vint[i:to]
			bytes := make([]byte, len(chunk)*uisize)
			for i, n := range chunk {
				switch uisize {
				case 8:
					binary.BigEndian.PutUint64(bytes[i*uisize:], uint64(n))
				case 4:
					binary.BigEndian.PutUint32(bytes[i*uisize:], uint32(n))
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

func Decode(r io.ReadCloser) (vint VarInt, err error) {
	const buflen, uisize = 1024, wsize / 8
	var n int
	bytes, bits := make([]byte, buflen*uisize), make([]uint, buflen)
	for {
		n, err = r.Read(bytes)
		switch {
		case err == io.EOF:
			err = nil
			return
		case err != nil:
			return nil, err
		// Check that size of byte sequence is legit.
		case n%uisize != 0:
			return nil, ErrorReaderIsNotDecodable{}
		}
		bytes, bits = bytes[:n], bits[:n/uisize]
		for i := range bits {
			switch uisize {
			case 8:
				bits[i] = uint(binary.BigEndian.Uint64(bytes[i*uisize:]))
			case 4:
				bits[i] = uint(binary.BigEndian.Uint32(bytes[i*uisize:]))
			}
		}
		vint = append(vint, bits...)
	}
}
