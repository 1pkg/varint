package varint

import "fmt"

type ErrorBitsIsNotPositive struct {
	Bits int
}

func (err ErrorBitsIsNotPositive) Error() string {
	return fmt.Sprintf("bits should be strictly positive number, but got %d", err.Bits)
}

type ErrorLengthIsNotPositive struct {
	Length int
}

func (err ErrorLengthIsNotPositive) Error() string {
	return fmt.Sprintf("lenght should be strictly positive number, but got %d", err.Length)
}

type ErrorBitsInt64Oveflow struct {
	Bits int
}

func (err ErrorBitsInt64Oveflow) Error() string {
	return fmt.Sprintf("bits %d overflows max size of int64", err.Bits)
}

type ErrorIndexOutOfRange struct {
	Index  int
	Length int
}

func (err ErrorIndexOutOfRange) Error() string {
	return fmt.Sprintf("index is out of range [%d] with length %d", err.Index, err.Length)
}