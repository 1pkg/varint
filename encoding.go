package varint

import (
	"encoding/binary"
	"io"
)

// Technically generics could be used together
// with bits.UintSize to make encoding/decoding more efficient
// for x32 systems, but this would make varint dependent on 1.19.

const buflen, uisize = 1024, 8

func Encode(vint VarInt) io.ReadCloser {
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
				binary.BigEndian.PutUint64(bytes[i*uisize:], uint64(n))
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
		default:
			if n%uisize != 0 {
				return nil, err
			}
			bytes, bits = bytes[:n], bits[:n/uisize]
			for i := range bits {
				bits[i] = uint(binary.BigEndian.Uint64(bytes[i*uisize:]))
			}
			vint = append(vint, bits...)
		}
	}
}
