package varint

import "fmt"

type ErrorBitLengthIsNegative struct {
	BitLen int
}

func (err ErrorBitLengthIsNegative) Error() string {
	return fmt.Sprintf("bit length should be strictly positive number, but got %d", err.BitLen)
}

type ErrorLengthIsNegative struct {
	Len int
}

func (err ErrorLengthIsNegative) Error() string {
	return fmt.Sprintf("length should be strictly positive number, but got %d", err.Len)
}

type ErrorBitLengthUintOveflow struct {
	BitLen int
}

func (err ErrorBitLengthUintOveflow) Error() string {
	return fmt.Sprintf("bit length %d overflows max size of uint %d", err.BitLen, wsize)
}

type ErrorBaseIsOutOfRange struct {
	Base int
}

func (err ErrorBaseIsOutOfRange) Error() string {
	return fmt.Sprintf("base %d is out the range [2,62]", err.Base)
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

type ErrorUnequalBitLengthCardinality struct {
	BitLenLeft  int
	BitLenRight int
}

func (err ErrorUnequalBitLengthCardinality) Error() string {
	return fmt.Sprintf("bit length %d do not have equal cardinality with %d", err.BitLenLeft, err.BitLenRight)
}

type ErrorBitLengthOperationOverflow struct {
	BitLen int
}

func (err ErrorBitLengthOperationOverflow) Error() string {
	return fmt.Sprintf("the operation result on bit length %d overflows its max value", err.BitLen)
}

type ErrorBitLengthOperationUnderflow struct {
	BitLen int
}

func (err ErrorBitLengthOperationUnderflow) Error() string {
	return fmt.Sprintf("the operation result on bit length %d underflow its min value", err.BitLen)
}

type ErrorStringIsNotValidNumber struct {
	String string
	Base   int
}

func (err ErrorStringIsNotValidNumber) Error() string {
	return fmt.Sprintf("string %s is not valid number with base %d", err.String, err.Base)
}

type ErrorReaderIsNotDecodable struct {
}

func (err ErrorReaderIsNotDecodable) Error() string {
	return "reader does not contain decodable bytes"
}
