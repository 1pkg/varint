package varint

import "errors"

// The register of all static errors that can be returned by VarInt.
var (
	ErrorBitLengthIsNotPositive      = errors.New("provided bit length has to be a strictly positive")
	ErrorLengthIsNotPositive         = errors.New("provided number length has to be a strictly positive")
	ErrorVarIntIsInvalid             = errors.New("the varint is not valid for this operation")
	ErrorIndexIsNegative             = errors.New("provided index has to be not be a negative")
	ErrorIndexIsOutOfRange           = errors.New("provided index is out of the number range")
	ErrorUnequalBitLengthCardinality = errors.New("provided bit length does not have equal cardinality with the number")
	ErrorAdditionOverflow            = errors.New("the addition result overflows its max value")
	ErrorMultiplicationOverflow      = errors.New("the multiplication result overflows its max value")
	ErrorSubtractionUnderflow        = errors.New("the subtraction result underflow its min value")
	ErrorDivisionByZero              = errors.New("the division result is undefined for 0 value divisor")
	ErrorReaderIsNotDecodable        = errors.New("reader does not contain decodable bytes")
)
