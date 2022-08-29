package varint

import (
	"fmt"
	"testing"
)

var (
	fixture0  = []uint64{0x0}
	fixtureFF = []uint64{0xFFFFFFFFFFFFFFFF}
	fixtureAt = []uint64{0x1C0B204899DFE765, 0xDE01245899CFE865, 0xBB0A2E43094FE733}
)

func mustNewVarInt(bits, length int, fixture []uint64) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		panic(err)
	}
	for i := 1; i < len(vint)-1; i++ {
		vint[i] = fixture[(i-1)%len(fixture)]
	}
	return vint
}

func mustNewBits(bsize int, bits []uint64) Bits {
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
			rbits: mustNewBits(8, []uint64{0x43}),
			rbin:  "0b1000011",
			roct:  "0o103",
			rdec:  "67",
			rhex:  "0X43",
			rb62:  "15",
		},
		"should return expected correct results for different odd small word varint": {
			vint:  mustNewVarInt(11, 100, fixtureAt),
			at:    17,
			rbits: mustNewBits(11, []uint64{0x4C7}),
			rbin:  "0b10011000111",
			roct:  "0o2307",
			rdec:  "1223",
			rhex:  "0X4C7",
			rb62:  "Jj",
		},
		"should return expected correct results for close to cap word varint": {
			vint:  mustNewVarInt(63, 100, fixtureAt),
			at:    2,
			rbits: mustNewBits(63, []uint64{0x376145C86129FCE6}),
			rbin:  "0b11011101100001010001011100100001100001001010011111110011100110",
			roct:  "0o335412134414112376346",
			rdec:  "3990547471752887526",
			rhex:  "0X376145C86129FCE6",
			rb62:  "4kmkU49SllO",
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint:  mustNewVarInt(67, 100, fixtureAt),
			at:    1,
			rbits: mustNewBits(67, []uint64{0x8049162673FA196E, 0x7}),
			rbin:  "0b1111000000001001001000101100010011001110011111110100001100101101110",
			roct:  "0o17001110542316376414556",
			rdec:  "138371152580531853678",
			rhex:  "0X78049162673FA196E",
			rb62:  "2erdLVDT8PFu",
		},
		"should return expected correct results for more than 2 word even varint": {
			vint:  mustNewVarInt(190, 100, fixtureAt),
			at:    1,
			rbits: mustNewBits(190, []uint64{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76}),
			rbin:  "0b1100011100000010110010000001001000100110011101111111100111011001011101111000000001001001000101100010011001110011111110100001100101101110110000101000101110010000110000100101001111111001110011",
			roct:  "0o1434026201104635774731357001110542316376414556605056206045177163",
			rdec:  "1219933054867519094558795547060405704302187833031700840051",
			rhex:  "0X31C0B204899DFE765DE01245899CFE865BB0A2E43094FE73",
			rb62:  "XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint:  mustNewVarInt(217, 100, fixtureAt),
			at:    2,
			rbits: mustNewBits(217, []uint64{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x922C4CE7F432DD8, 0x13B2EF0}),
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
				t.Fatalf("expected AtBits error %v doesn't match actual error %d", tcase.errbits, errbits)
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
			vint: mustNewVarInt(8, 100, fixtureAt),
			at:   1000,
			err:  ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return unequal cardinality for not equal bits sizes": {
			vint: mustNewVarInt(8, 100, fixtureFF),
			at:   19,
			bits: mustNewBits(24, []uint64{0x43}),
			err:  ErrorUnequalBitsCardinality{Bits: 8, BitsX: 24},
		},
		"should return expected correct results for same small word varint": {
			vint: mustNewVarInt(8, 100, fixtureFF),
			at:   19,
			bits: mustNewBits(8, []uint64{0x43}),
		},
		"should return expected correct results for different odd small word varint": {
			vint: mustNewVarInt(11, 100, fixtureFF),
			at:   17,
			bits: mustNewBits(11, []uint64{0x4C7}),
		},
		"should return expected correct results for close to cap word varint": {
			vint: mustNewVarInt(63, 100, fixtureFF),
			at:   2,
			bits: mustNewBits(63, []uint64{0x376145C86129FCE6}),
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint: mustNewVarInt(67, 100, fixtureFF),
			at:   1,
			bits: mustNewBits(67, []uint64{0x8049162673FA196E, 0x7}),
		},
		"should return expected correct results for more than 2 word even varint": {
			vint: mustNewVarInt(190, 100, fixtureFF),
			at:   1,
			bits: mustNewBits(190, []uint64{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76}),
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint: mustNewVarInt(217, 100, fixtureFF),
			at:   2,
			bits: mustNewBits(217, []uint64{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x922C4CE7F432DD8, 0x13B2EF0}),
		},
	}
	for tname, tcase := range tcases {
		t.Run(tname, func(t *testing.T) {
			if err := tcase.vint.SetBits(tcase.at, tcase.bits); err != nil {
				if err != tcase.err {
					t.Fatalf("expected SetBits error %v doesn't match actual error %d", tcase.err, err)
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

func FuzzVarIntSetAt(f *testing.F) {
	const l = 10
	b62s := []string{
		"15",
		"Jj",
		"4kmkU49SllO",
		"2erdLVDT8PFu",
		"XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
		"3rNk68AgS73raYcuFFPjD3MPzU5ELtIwjHVcu",
	}
	for _, b62 := range b62s {
		f.Add(b62)
	}
	f.Fuzz(func(t *testing.T, b62 string) {
		bits, err := NewBitsString(b62, 62)
		if err != nil || bits == nil {
			return
		}
		vint, zero := mustNewVarInt(bits.Bits(), l, fixture0), mustNewBits(bits.Bits(), fixture0)
		for i := 0; i < l; i++ {
			if err := vint.SetBits(i, bits); err != nil {
				t.Fatalf("SetBits error %v is not expected on %v", err, bits)
			}
		}
		for i := 0; i < l; i++ {
			b, err := vint.AtBits(i)
			if err != nil {
				t.Fatalf("AtBits error %v is not expected on %v", err, bits)
			}
			if !(bits.Equal(zero) || b.Equal(bits)) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", bits, b)
			}
		}
	})
}
