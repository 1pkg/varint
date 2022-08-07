package varint

import "fmt"

type ErrorBitsIsNegative struct {
	Bits int
}

func (err ErrorBitsIsNegative) Error() string {
	return fmt.Sprintf("bits should be strictly positive number, but got %d", err.Bits)
}

type ErrorLengthIsNegative struct {
	Length int
}

func (err ErrorLengthIsNegative) Error() string {
	return fmt.Sprintf("lenght should be strictly positive number, but got %d", err.Length)
}

type ErrorBitsUint64Oveflow struct {
	Bits int
}

func (err ErrorBitsUint64Oveflow) Error() string {
	return fmt.Sprintf("bits %d overflows max size of uint64 %d", err.Bits, wsize)
}

type ErrorIndexIsNegative struct {
	Index int
}

func (err ErrorIndexIsNegative) Error() string {
	return fmt.Sprintf("index should be strictly positive number, but got %d", err.Index)
}

type ErrorIndexIsOutOfRange struct {
	Index  int
	Length int
}

func (err ErrorIndexIsOutOfRange) Error() string {
	return fmt.Sprintf("index is out of range [%d] with length %d", err.Index, err.Length)
}

type ErrorUnequalBitsCardinality struct {
	Bits  int
	BitsX int
}

func (err ErrorUnequalBitsCardinality) Error() string {
	return fmt.Sprintf("bits %d do not have equal cardinality with %d", err.Bits, err.BitsX)
}
