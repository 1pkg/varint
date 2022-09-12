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

type ErrorBitsUintOveflow struct {
	Bits int
}

func (err ErrorBitsUintOveflow) Error() string {
	return fmt.Sprintf("bits %d overflows max size of uint %d", err.Bits, wsize)
}

type ErrorBitsBaseOveflow struct {
	Base int
}

func (err ErrorBitsBaseOveflow) Error() string {
	return fmt.Sprintf("bits base %d overflows the range [0,62]", err.Base)
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

type ErrorBitsOperationOverflow struct {
	Bits int
}

func (err ErrorBitsOperationOverflow) Error() string {
	return fmt.Sprintf("the operation on bits %d overflows its max size", err.Bits)
}

type ErrorStringIsNotValidBaseNumber struct {
	String string
	Base   int
}

func (err ErrorStringIsNotValidBaseNumber) Error() string {
	return fmt.Sprintf("string %s is not valid base %d number", err.String, err.Base)
}
