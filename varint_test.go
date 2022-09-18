package varint

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

var (
	b62Seed = []string{
		"15",
		"Jj",
		"4kmkU49SllO",
		"2erdLVDT8PFu",
		"XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
		"3rNk68AgS73raYcuFFPjD3MPzU5ELtIwjHVcu",
	}
	fixture0  = []uint{0x0}
	fixtureFF = []uint{0xFFFFFFFFFFFFFFFF}
	fixtureAt = []uint{0x1C0B204899DFE765, 0xDE01245899CFE865, 0xBB0A2E43094FE733}
)

func mustNewVarInt(bits, length int, fixture []uint) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		panic(err)
	}
	for i := rcap; i < len(vint)-1; i++ {
		vint[i] = fixture[(i-rcap)%len(fixture)]
	}
	return vint
}

func mustNewBits(bsize int, bits []uint) Bits {
	b, err := NewBits(bsize, bits)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVarIntAt(t *testing.T) {
	tcases := map[string]struct {
		vint    VarInt
		at      int
		rbits   Bits
		errbits error
		rbin    string
		roct    string
		rdec    string
		rhex    string
		rb62    string
	}{
		"should return index is negative error for negative index": {
			vint:    mustNewVarInt(8, 100, fixtureAt),
			at:      -1,
			errbits: ErrorIndexIsNegative{Index: -1},
		},
		"should return index is out of range error for out of lenght index": {
			vint:    mustNewVarInt(8, 100, fixtureAt),
			at:      1000,
			errbits: ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return expected correct results for same small word varint": {
			vint:  mustNewVarInt(8, 100, fixtureAt),
			at:    19,
			rbits: mustNewBits(8, []uint{0x43}),
			rbin:  "0b1000011",
			roct:  "0o103",
			rdec:  "67",
			rhex:  "0X43",
			rb62:  "15",
		},
		"should return expected correct results for different odd small word varint": {
			vint:  mustNewVarInt(11, 100, fixtureAt),
			at:    17,
			rbits: mustNewBits(11, []uint{0x4C7}),
			rbin:  "0b10011000111",
			roct:  "0o2307",
			rdec:  "1223",
			rhex:  "0X4C7",
			rb62:  "Jj",
		},
		"should return expected correct results for close to cap word varint": {
			vint:  mustNewVarInt(63, 100, fixtureAt),
			at:    2,
			rbits: mustNewBits(63, []uint{0x376145C86129FCE6}),
			rbin:  "0b11011101100001010001011100100001100001001010011111110011100110",
			roct:  "0o335412134414112376346",
			rdec:  "3990547471752887526",
			rhex:  "0X376145C86129FCE6",
			rb62:  "4kmkU49SllO",
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint:  mustNewVarInt(67, 100, fixtureAt),
			at:    1,
			rbits: mustNewBits(67, []uint{0x8049162673FA196E, 0x7}),
			rbin:  "0b1111000000001001001000101100010011001110011111110100001100101101110",
			roct:  "0o17001110542316376414556",
			rdec:  "138371152580531853678",
			rhex:  "0X78049162673FA196E",
			rb62:  "2erdLVDT8PFu",
		},
		"should return expected correct results for more than 2 word even varint": {
			vint:  mustNewVarInt(190, 100, fixtureAt),
			at:    1,
			rbits: mustNewBits(190, []uint{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76}),
			rbin:  "0b1100011100000010110010000001001000100110011101111111100111011001011101111000000001001001000101100010011001110011111110100001100101101110110000101000101110010000110000100101001111111001110011",
			roct:  "0o1434026201104635774731357001110542316376414556605056206045177163",
			rdec:  "1219933054867519094558795547060405704302187833031700840051",
			rhex:  "0X31C0B204899DFE765DE01245899CFE865BB0A2E43094FE73",
			rb62:  "XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint:  mustNewVarInt(217, 100, fixtureAt),
			at:    2,
			rbits: mustNewBits(217, []uint{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x0922C4CE7F432DD8, 0x13B2EF0}),
			rbin:  "0b1001110110010111011110000000010010010001011000100110011100111111101000011001011011101100001010001011100100001100001001010011111110011100110011000111000000101100100000010010001001100111011111111001110110010111011110000",
			roct:  "0o1166273600222130463477503133541213441411237634630700544022114737716627360",
			rdec:  "129658909767506927186822060435586250621066445025784138118639333104",
			rhex:  "0X13B2EF00922C4CE7F432DD85172184A7F3998E0590244CEFF3B2EF0",
			rb62:  "3rNk68AgS73raYcuFFPjD3MPzU5ELtIwjHVcu",
		},
	}
	for tname, tcase := range tcases {
		t.Run(tname, func(t *testing.T) {
			rbits, errbits := tcase.vint.AtBits(tcase.at)
			if !rbits.Equal(tcase.rbits) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", tcase.rbits, rbits)
			}
			if errbits != tcase.errbits {
				t.Fatalf("expected AtBits error %v doesn't match actual error %v", tcase.errbits, errbits)
			}
			if fmt.Sprintf("%#b", rbits) != tcase.rbin {
				t.Fatalf("expected binary AtBits result %s doesn't match actual result %#b", tcase.rbin, rbits)
			}
			if fmt.Sprintf("%O", rbits) != tcase.roct {
				t.Fatalf("expected octal AtBits result %s doesn't match actual result %O", tcase.roct, rbits)
			}
			if fmt.Sprintf("%d", rbits) != tcase.rdec {
				t.Fatalf("expected decimal AtBits result %s doesn't match actual result %d", tcase.rdec, rbits)
			}
			if fmt.Sprintf("%#X", rbits) != tcase.rhex {
				t.Fatalf("expected hexadecimal AtBits result %s doesn't match actual result %#X", tcase.rhex, rbits)
			}
			if b62, _ := rbits.Base(62); string(b62) != tcase.rb62 {
				t.Fatalf("expected base62 AtBits result %s doesn't match actual result %s", tcase.rb62, string(b62))
			}
		})
	}
}

func TestVarIntSet(t *testing.T) {
	tcases := map[string]struct {
		vint VarInt
		at   int
		bits Bits
		err  error
	}{
		"should return index is negative error for negative index": {
			vint: mustNewVarInt(8, 100, fixtureFF),
			at:   -1,
			err:  ErrorIndexIsNegative{Index: -1},
		},
		"should return index is out of range error for out of lenght index": {
			vint: mustNewVarInt(8, 100, fixtureFF),
			at:   1000,
			err:  ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return unequal cardinality for not equal bits sizes": {
			vint: mustNewVarInt(8, 100, fixtureFF),
			at:   19,
			bits: mustNewBits(24, []uint{0x43}),
			err:  ErrorUnequalBitsCardinality{Bits: 8, BitsX: 24},
		},
		"should return expected correct results for same small word varint": {
			vint: mustNewVarInt(8, 100, fixtureFF),
			at:   19,
			bits: mustNewBits(8, []uint{0x43}),
		},
		"should return expected correct results for different odd small word varint": {
			vint: mustNewVarInt(11, 100, fixtureFF),
			at:   17,
			bits: mustNewBits(11, []uint{0x4C7}),
		},
		"should return expected correct results for close to cap word varint": {
			vint: mustNewVarInt(63, 100, fixtureFF),
			at:   2,
			bits: mustNewBits(63, []uint{0x376145C86129FCE6}),
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint: mustNewVarInt(67, 100, fixtureFF),
			at:   1,
			bits: mustNewBits(67, []uint{0x8049162673FA196E, 0x7}),
		},
		"should return expected correct results for more than 2 word even varint": {
			vint: mustNewVarInt(190, 100, fixtureFF),
			at:   1,
			bits: mustNewBits(190, []uint{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76}),
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint: mustNewVarInt(217, 100, fixtureFF),
			at:   2,
			bits: mustNewBits(217, []uint{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x0922C4CE7F432DD8, 0x13B2EF0}),
		},
	}
	for tname, tcase := range tcases {
		t.Run(tname, func(t *testing.T) {
			if err := tcase.vint.SetBits(tcase.at, tcase.bits); err != nil {
				if err != tcase.err {
					t.Fatalf("expected SetBits error %v doesn't match actual error %v", tcase.err, err)
				}
				return
			}
			rbits, err := tcase.vint.AtBits(tcase.at)
			if err != nil {
				t.Fatal(err)
			}
			if !rbits.Equal(tcase.bits) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", tcase.bits, rbits)
			}
		})
	}
}

func TestVarIntAdd(t *testing.T) {
	tcases := map[string]struct {
		vint  VarInt
		at    int
		bits  Bits
		rbits Bits
		err   error
	}{
		"should return index is negative error for negative index": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   -1,
			err:  ErrorIndexIsNegative{Index: -1},
		},
		"should return index is out of range error for out of lenght index": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   1000,
			err:  ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return unequal cardinality for not equal bits sizes": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   19,
			bits: mustNewBits(24, []uint{0x43}),
			err:  ErrorUnequalBitsCardinality{Bits: 8, BitsX: 24},
		},
		"should return bits overflow error for overflowing bits operation": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   19,
			bits: mustNewBits(8, []uint{0xCA}),
			err:  ErrorBitsOperationOverflow{Bits: 8},
		},
		"should return expected correct results for same small word varint": {
			vint:  mustNewVarInt(8, 100, fixtureAt),
			at:    19,
			bits:  mustNewBits(8, []uint{0x43}),
			rbits: mustNewBits(8, []uint{0x86}),
		},
		"should return expected correct results for different odd small word varint": {
			vint:  mustNewVarInt(11, 100, fixtureAt),
			at:    17,
			bits:  mustNewBits(11, []uint{0x1C7}),
			rbits: mustNewBits(11, []uint{0x68E}),
		},
		"should return expected correct results for close to cap word varint": {
			vint:  mustNewVarInt(63, 100, fixtureAt),
			at:    2,
			bits:  mustNewBits(63, []uint{0x376145C86129FCE6}),
			rbits: mustNewBits(63, []uint{0x6EC28B90C253F9CC}),
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint:  mustNewVarInt(67, 100, fixtureAt),
			at:    1,
			bits:  mustNewBits(67, []uint{0x49162673FA196E}),
			rbits: mustNewBits(67, []uint{0x80922C4CE7F432DC, 0x7}),
		},
		"should return expected correct results for more than 2 word even varint": {
			vint:  mustNewVarInt(190, 100, fixtureAt),
			at:    1,
			bits:  mustNewBits(190, []uint{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0xC0B204899DFE76}),
			rbits: mustNewBits(190, []uint{0xB76145C86129FCE6, 0xBBC0248B1339FD0C, 0x32816409133BFCEC}),
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint:  mustNewVarInt(217, 100, fixtureAt),
			at:    2,
			bits:  mustNewBits(217, []uint{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x0922C4CE7F432DD8, 0x3B2EF0}),
			rbits: mustNewBits(217, []uint{0xB204899DFE765DE0, 0xA2E43094FE7331C0, 0x1245899CFE865BB0, 0x1765DE0}),
		},
	}
	for tname, tcase := range tcases {
		t.Run(tname, func(t *testing.T) {
			if err := tcase.vint.AddBits(tcase.at, tcase.bits); err != nil {
				if err != tcase.err {
					t.Fatalf("expected AddBits error %v doesn't match actual error %v", tcase.err, err)
				}
				return
			}
			rbits, err := tcase.vint.AtBits(tcase.at)
			if err != nil {
				t.Fatal(err)
			}
			if !rbits.Equal(tcase.rbits) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", tcase.rbits, rbits)
			}
		})
	}
}

func TestVarIntSub(t *testing.T) {
	tcases := map[string]struct {
		vint  VarInt
		at    int
		bits  Bits
		rbits Bits
		err   error
	}{
		"should return index is negative error for negative index": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   -1,
			err:  ErrorIndexIsNegative{Index: -1},
		},
		"should return index is out of range error for out of lenght index": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   1000,
			err:  ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return unequal cardinality for not equal bits sizes": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   19,
			bits: mustNewBits(24, []uint{0x43}),
			err:  ErrorUnequalBitsCardinality{Bits: 8, BitsX: 24},
		},
		"should return bits underflow error for underflowing bits operation": {
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   19,
			bits: mustNewBits(8, []uint{0x48}),
			err:  ErrorBitsOperationUnderflow{Bits: 8},
		},
		"should return expected correct results for same small word varint": {
			vint:  mustNewVarInt(8, 100, fixtureAt),
			at:    19,
			bits:  mustNewBits(8, []uint{0x40}),
			rbits: mustNewBits(8, []uint{0x3}),
		},
		"should return expected correct results for different odd small word varint": {
			vint:  mustNewVarInt(11, 100, fixtureAt),
			at:    17,
			bits:  mustNewBits(11, []uint{0x1C7}),
			rbits: mustNewBits(11, []uint{0x300}),
		},
		"should return expected correct results for close to cap word varint": {
			vint:  mustNewVarInt(63, 100, fixtureAt),
			at:    2,
			bits:  mustNewBits(63, []uint{0x376145C86129FCE6}),
			rbits: mustNewBits(63, []uint{0x0}),
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint:  mustNewVarInt(67, 100, fixtureAt),
			at:    1,
			bits:  mustNewBits(67, []uint{0x49162673FA196E}),
			rbits: mustNewBits(67, []uint{0x08000000000000000, 0x7}),
		},
		"should return expected correct results for more than 2 word even varint": {
			vint:  mustNewVarInt(190, 100, fixtureAt),
			at:    1,
			bits:  mustNewBits(190, []uint{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0xC0B204899DFE76}),
			rbits: mustNewBits(190, []uint{0x0000000000000000, 0x0000000000000000, 0x3100000000000000}),
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint:  mustNewVarInt(217, 100, fixtureAt),
			at:    2,
			bits:  mustNewBits(217, []uint{0xB204899DFE765DE0, 0xA2E43094FE7331C0, 0x1245899CFE865BB0, 0x3B2EF0}),
			rbits: mustNewBits(217, []uint{0xA6FDBB3100C4D110, 0xAE8DE7B580C6671F, 0xF6DD3B3180BCD227, 0xFFFFFF}),
		},
	}
	for tname, tcase := range tcases {
		t.Run(tname, func(t *testing.T) {
			if err := tcase.vint.SubBits(tcase.at, tcase.bits); err != nil {
				if err != tcase.err {
					t.Fatalf("expected AddBits error %v doesn't match actual error %v", tcase.err, err)
				}
				return
			}
			rbits, err := tcase.vint.AtBits(tcase.at)
			if err != nil {
				t.Fatal(err)
			}
			if !rbits.Equal(tcase.rbits) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", tcase.rbits, rbits)
			}
		})
	}
}

func FuzzVarIntSetAt(f *testing.F) {
	const l = 10
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		bits, err := NewBitsString(b62, 62)
		if err != nil || bits == nil {
			return
		}
		vint, zero := mustNewVarInt(bits.Bits(), l, fixture0), mustNewBits(bits.Bits(), fixture0)
		for i := 0; i < l; i++ {
			if err := vint.SetBits(rnd.Int()%l, bits); err != nil {
				t.Fatalf("SetBits error %v is not expected on %v", err, bits)
			}
		}
		for i := 0; i < l; i++ {
			b, err := vint.AtBits(i)
			if err != nil {
				t.Fatalf("AtBits error %v is not expected on %v", err, bits)
			}
			if !(b.Equal(zero) || b.Equal(bits)) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", bits, b)
			}
		}
	})
}

func FuzzVarIntAdd(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [0, bits]. Then bootstrap big ints
		// from them, calculate bit ints sum and compare to
		// calculated sum of original + random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigSum := big.NewInt(0).Add(bigOrig, bigRnd)
		// Skip cases when big sum overloads original bits size,
		// because it will inevitably produce ErrorBitsOperationOverflow.
		if bigSum.BitLen() > bitsOrig.Bits() {
			return
		}
		bitsSum, err := NewBitsBigInt(bigSum)
		if err != nil {
			t.Fatal(err)
		}
		bitsRnd, err := NewBitsBigInt(bigRnd)
		if err != nil {
			t.Fatal(err)
		}
		// Fix the cardinarity for random bits.
		bitsRnd[0] = uint(bitsOrig.Bits())
		vint, zero := mustNewVarInt(bitsOrig.Bits(), l, fixture0), mustNewBits(bitsOrig.Bits(), fixture0)
		// First, add original bits to zeroed vint.
		if err := vint.AddBits(1, bitsOrig); err != nil {
			t.Fatal(err)
		}
		b, err := vint.AtBits(1)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(bitsOrig) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", bitsOrig, b)
		}
		// Second, add random bits to the same vint.
		if err := vint.AddBits(1, bitsRnd); err != nil {
			t.Fatal(err)
		}
		b, err = vint.AtBits(1)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(bitsSum) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", bitsSum, b)
		}
		// Third, check that others bits were not affected.
		b, err = vint.AtBits(0)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(zero) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", zero, b)
		}
		b, err = vint.AtBits(2)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(zero) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", zero, b)
		}
	})
}

func FuzzVarIntSub(f *testing.F) {
	const l = 3
	for _, b62 := range b62Seed {
		f.Add(b62)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	f.Fuzz(func(t *testing.T, b62 string) {
		// Initialize fuzz original bits and extra random bits
		// in the range of [1, bits]. Then bootstrap big ints
		// from them, calculate bit ints sub and compare to
		// calculated sub of original - random bits.
		bitsOrig, err := NewBitsString(b62, 62)
		if err != nil || bitsOrig == nil {
			return
		}
		bigOrig := bitsOrig.BigInt()
		bigRnd := big.NewInt(0).Rand(rnd, bigOrig)
		bigSub := big.NewInt(0).Sub(bigOrig, bigRnd)
		bitsSub, err := NewBitsBigInt(bigSub)
		if err != nil {
			t.Fatal(err)
		}
		// Fix the cardinarity for sub bits.
		bitsSub, err = NewBits(bitsOrig.Bits(), bitsSub.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		bitsRnd, err := NewBitsBigInt(bigRnd)
		if err != nil {
			t.Fatal(err)
		}
		if bitsRnd == nil {
			return
		}
		// Fix the cardinarity for random bits.
		bitsRnd[0] = uint(bitsOrig.Bits())
		vint, zero := mustNewVarInt(bitsOrig.Bits(), l, fixture0), mustNewBits(bitsOrig.Bits(), fixture0)
		// First, set original bits and sub random bits.
		if err := vint.SetBits(1, bitsOrig); err != nil {
			t.Fatal(err)
		}
		if err := vint.SubBits(1, bitsRnd); err != nil {
			t.Fatal(err)
		}
		b, err := vint.AtBits(1)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(bitsSub) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", bitsSub, b)
		}
		// Second, check that others bits were not affected.
		b, err = vint.AtBits(0)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(zero) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", zero, b)
		}
		b, err = vint.AtBits(2)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Equal(zero) {
			t.Fatalf("expected AtBits result %v doesn't match actual result %v", zero, b)
		}
	})
}
