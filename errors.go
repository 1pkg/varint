package varint

import "errors"

// The register of all static errors and warns that can be returned by VarInt.
var (
	ErrorBitLengthIsNotPositive      = errors.New("the provided bit length has to be a strictly positive number")
	ErrorLengthIsNotPositive         = errors.New("the provided length has to be a strictly positive number")
	ErrorBitLengthIsNotEfficient     = errors.New("the provided bit length is over the threshold, for efficiency consider decreasing it or use big.Int slice")
	ErrorLengthIsNotEfficient        = errors.New("the provided length is under the threshold, for efficiency consider increasing it or use uint slice")
	ErrorVarIntIsInvalid             = errors.New("the varint is not valid for this operation")
	ErrorIndexIsNegative             = errors.New("the provided index has to be not be a negative number")
	ErrorIndexIsOutOfRange           = errors.New("the provided index is out of the number range")
	ErrorUnequalBitLengthCardinality = errors.New("the provided bit length does not have equal cardinality with the number")
	ErrorAdditionOverflow            = errors.New("the addition result overflows its max value")
	ErrorMultiplicationOverflow      = errors.New("the multiplication result overflows its max value")
	ErrorSubtractionUnderflow        = errors.New("the subtraction result underflow its min value")
	ErrorDivisionByZero              = errors.New("the division result is undefined for 0 value divisor")
	ErrorReaderIsNotDecodable        = errors.New("reader does not contain decodable bytes")
	ErrorShiftIsNegative             = errors.New("the provided shift has to be not be a negative number")
)
