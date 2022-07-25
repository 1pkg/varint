package varint

import (
	"reflect"
	"testing"
)

func mustNewVarInt(bits, length int) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		panic(err)
	}
	return vint
}

func TestVarIntAt(t *testing.T) {
	tcases := map[string]struct {
		vint    VarInt
		at      int
		ruint   uint64
		erruint error
		rbits   []uint64
		errbits error
		rbin    string
		roct    string
		rdec    string
		rhex    string
	}{
		"should return index is negative error for negative index": {
			vint:    mustNewVarInt(8, 100),
			at:      -1,
			erruint: ErrorIndexIsNegative{Index: -1},
			errbits: ErrorIndexIsNegative{Index: -1},
		},
		"should return index is out of range error for out of lenght index": {
			vint:    mustNewVarInt(8, 100),
			at:      1000,
			erruint: ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
			errbits: ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return expected correct results for same small word varint": {
			vint:  mustNewVarInt(8, 100),
			at:    19,
			ruint: 0x43,
			rbits: []uint64{0x43},
			rbin:  "0b1000011",
			roct:  "0o103",
			rdec:  "67",
			rhex:  "0X43",
		},
		"should return expected correct results for different odd small word varint": {
			vint:  mustNewVarInt(11, 100),
			at:    17,
			ruint: 0x4C7,
			rbits: []uint64{0x4C7},
			rbin:  "0b10011000111",
			roct:  "0o2307",
			rdec:  "1223",
			rhex:  "0X4C7",
		},
		"should return expected correct results for close to cap word varint": {
			vint:  mustNewVarInt(63, 100),
			at:    2,
			ruint: 0x376145C86129FCE6,
			rbits: []uint64{0x376145C86129FCE6},
			rbin:  "0b11011101100001010001011100100001100001001010011111110011100110",
			roct:  "0o335412134414112376346",
			rdec:  "3990547471752887526",
			rhex:  "0X376145C86129FCE6",
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint:    mustNewVarInt(67, 100),
			at:      1,
			erruint: ErrorBitsUint64Oveflow{Bits: 67},
			rbits:   []uint64{0x8049162673FA196E, 0x7},
			rhex:    "0X78049162673FA196E",
		},
		"should return expected correct results for more than 2 word even varint": {
			vint:    mustNewVarInt(190, 100),
			at:      1,
			erruint: ErrorBitsUint64Oveflow{Bits: 190},
			rbits:   []uint64{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76},
			rhex:    "0X31C0B204899DFE765DE01245899CFE865BB0A2E43094FE73",
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint:    mustNewVarInt(217, 100),
			at:      2,
			erruint: ErrorBitsUint64Oveflow{Bits: 217},
			rbits:   []uint64{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x922C4CE7F432DD8, 0x13B2EF0},
			rhex:    "0X13B2EF0922C4CE7F432DD85172184A7F3998E0590244CEFF3B2EF0",
		},
	}
	for tname, tcase := range tcases {
		// fixture
		tcase.vint[1] = 0x1C0B204899DFE765  // 0001110000001011001000000100100010011001110111111110011101100101
		tcase.vint[2] = 0xDE01245899CFE865  // 1101111000000001001001000101100010011001110011111110100001100101
		tcase.vint[3] = 0xBB0A2E43094FE733  // 1011101100001010001011100100001100001001010011111110011100110011
		tcase.vint[4] = 0x1C0B204899DFE765  // 0001110000001011001000000100100010011001110111111110011101100101
		tcase.vint[5] = 0xDE01245899CFE865  // 1101111000000001001001000101100010011001110011111110100001100101
		tcase.vint[6] = 0xBB0A2E43094FE733  // 1011101100001010001011100100001100001001010011111110011100110011
		tcase.vint[7] = 0x1C0B204899DFE765  // 0001110000001011001000000100100010011001110111111110011101100101
		tcase.vint[8] = 0xDE01245899CFE865  // 1101111000000001001001000101100010011001110011111110100001100101
		tcase.vint[9] = 0xBB0A2E43094FE733  // 1011101100001010001011100100001100001001010011111110011100110011
		tcase.vint[10] = 0x1C0B204899DFE765 // 0001110000001011001000000100100010011001110111111110011101100101
		tcase.vint[11] = 0xDE01245899CFE865 // 1101111000000001001001000101100010011001110011111110100001100101
		tcase.vint[12] = 0xBB0A2E43094FE733 // 1011101100001010001011100100001100001001010011111110011100110011
		t.Run(tname, func(t *testing.T) {
			ruint, erruint := tcase.vint.AtUint(tcase.at)
			if ruint != tcase.ruint {
				t.Fatalf("expected AtUint result %d doesn't match actual result %d", tcase.ruint, ruint)
			}
			if erruint != tcase.erruint {
				t.Fatalf("expected AtUint error %v doesn't match actual error %d", tcase.erruint, erruint)
			}
			rbits, errbits := tcase.vint.AtBits(tcase.at)
			if !reflect.DeepEqual(rbits.Value(), tcase.rbits) {
				t.Fatalf("expected AtBits result %v doesn't match actual result %v", tcase.rbits, rbits.Value())
			}
			if errbits != tcase.errbits {
				t.Fatalf("expected AtBits error %v doesn't match actual error %d", tcase.errbits, errbits)
			}
			// if fmt.Sprintf("%#b", rbits) != tcase.rbin {
			// 	t.Fatalf("expected binary AtBits result %s doesn't match actual result %#b", tcase.rbin, rbits)
			// }
			// if fmt.Sprintf("%O", rbits) != tcase.roct {
			// 	t.Fatalf("expected octal AtBits result %s doesn't match actual result %O", tcase.roct, rbits)
			// }
			// if fmt.Sprintf("%d", rbits) != tcase.rdec {
			// 	t.Fatalf("expected decimal AtBits result %s doesn't match actual result %d", tcase.rdec, rbits)
			// }
			// if fmt.Sprintf("%#X", rbits) != tcase.rhex {
			// 	t.Fatalf("expected hexadecimal AtBits result %s doesn't match actual result %#X", tcase.rhex, rbits)
			// }
		})
	}
}
