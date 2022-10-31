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

type ErrorAdditionOverflow struct {
	BitLen int
}

func (err ErrorAdditionOverflow) Error() string {
	return fmt.Sprintf("the addition result on bit length %d overflows its max value", err.BitLen)
}

type ErrorMultiplicationOverflow struct {
	BitLen int
}

func (err ErrorMultiplicationOverflow) Error() string {
	return fmt.Sprintf("the multiplication result on bit length %d overflows its max value", err.BitLen)
}

type ErrorSubtractionUnderflow struct {
	BitLen int
}

func (err ErrorSubtractionUnderflow) Error() string {
	return fmt.Sprintf("the subtraction result on bit length %d underflow its min value", err.BitLen)
}

type ErrorDivisionByZero struct {
}

func (ErrorDivisionByZero) Error() string {
	return "the division result is undefined for 0 value divisor"
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

func (ErrorReaderIsNotDecodable) Error() string {
	return "reader does not contain decodable bytes"
}
