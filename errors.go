package varint

import "fmt"

type ErrorBitLengthIsNotPositive struct {
	BitLen int
}

func (err ErrorBitLengthIsNotPositive) Error() string {
	return fmt.Sprintf("bit length should be a strictly positive number, but got %d", err.BitLen)
}

type ErrorLengthIsNotPositive struct {
	Len int
}

func (err ErrorLengthIsNotPositive) Error() string {
	return fmt.Sprintf("length should be a strictly positive number, but got %d", err.Len)
}

type ErrorIndexIsNegative struct {
	Index int
}

func (err ErrorIndexIsNegative) Error() string {
	return fmt.Sprintf("index should not be a negative number, but got %d", err.Index)
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
}

func (err ErrorAdditionOverflow) Error() string {
	return "the addition result overflows its max value"
}

type ErrorMultiplicationOverflow struct {
}

func (err ErrorMultiplicationOverflow) Error() string {
	return "the multiplication result overflows its max value"
}

type ErrorSubtractionUnderflow struct {
}

func (err ErrorSubtractionUnderflow) Error() string {
	return "the subtraction result underflow its min value"
}

type ErrorDivisionByZero struct {
}

func (ErrorDivisionByZero) Error() string {
	return "the division result is undefined for 0 value divisor"
}

type ErrorReaderIsNotDecodable struct {
}

func (ErrorReaderIsNotDecodable) Error() string {
	return "reader does not contain decodable bytes"
}
