package varint

import (
	"fmt"
	"testing"
)

func mustNewVarInt(bits, length int) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		panic(err)
	}
	// fixture
	vint[1] = 0x1C0B204899DFE765  // 0001110000001011001000000100100010011001110111111110011101100101
	vint[2] = 0xDE01245899CFE865  // 1101111000000001001001000101100010011001110011111110100001100101
	vint[3] = 0xBB0A2E43094FE733  // 1011101100001010001011100100001100001001010011111110011100110011
	vint[4] = 0x1C0B204899DFE765  // 0001110000001011001000000100100010011001110111111110011101100101
	vint[5] = 0xDE01245899CFE865  // 1101111000000001001001000101100010011001110011111110100001100101
	vint[6] = 0xBB0A2E43094FE733  // 1011101100001010001011100100001100001001010011111110011100110011
	vint[7] = 0x1C0B204899DFE765  // 0001110000001011001000000100100010011001110111111110011101100101
	vint[8] = 0xDE01245899CFE865  // 1101111000000001001001000101100010011001110011111110100001100101
	vint[9] = 0xBB0A2E43094FE733  // 1011101100001010001011100100001100001001010011111110011100110011
	vint[10] = 0x1C0B204899DFE765 // 0001110000001011001000000100100010011001110111111110011101100101
	vint[11] = 0xDE01245899CFE865 // 1101111000000001001001000101100010011001110011111110100001100101
	vint[12] = 0xBB0A2E43094FE733 // 1011101100001010001011100100001100001001010011111110011100110011
	return vint
}

func mustNewVarIntFF(bits, length int) VarInt {
	vint, err := NewVarInt(bits, length)
	if err != nil {
		panic(err)
	}
	// fixture
	vint[1] = 0xFFFFFFFFFFFFFFFF
	vint[2] = 0xFFFFFFFFFFFFFFFF
	vint[3] = 0xFFFFFFFFFFFFFFFF
	vint[4] = 0xFFFFFFFFFFFFFFFF
	vint[5] = 0xFFFFFFFFFFFFFFFF
	vint[6] = 0xFFFFFFFFFFFFFFFF
	vint[7] = 0xFFFFFFFFFFFFFFFF
	vint[8] = 0xFFFFFFFFFFFFFFFF
	vint[9] = 0xFFFFFFFFFFFFFFFF
	vint[10] = 0xFFFFFFFFFFFFFFF
	vint[11] = 0xFFFFFFFFFFFFFFF
	vint[12] = 0xFFFFFFFFFFFFFFF
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
			vint:    mustNewVarInt(8, 100),
			at:      -1,
			errbits: ErrorIndexIsNegative{Index: -1},
		},
		"should return index is out of range error for out of lenght index": {
			vint:    mustNewVarInt(8, 100),
			at:      1000,
			errbits: ErrorIndexIsOutOfRange{Index: 1000, Length: 100},
		},
		"should return expected correct results for same small word varint": {
			vint:  mustNewVarInt(8, 100),
			at:    19,
			rbits: mustNewBits(8, []uint64{0x43}),
			rbin:  "0b1000011",
			roct:  "0o103",
			rdec:  "67",
			rhex:  "0X43",
			rb62:  "15",
		},
		"should return expected correct results for different odd small word varint": {
			vint:  mustNewVarInt(11, 100),
			at:    17,
			rbits: mustNewBits(11, []uint64{0x4C7}),
			rbin:  "0b10011000111",
			roct:  "0o2307",
			rdec:  "1223",
			rhex:  "0X4C7",
			rb62:  "Jj",
		},
		"should return expected correct results for close to cap word varint": {
			vint:  mustNewVarInt(63, 100),
			at:    2,
			rbits: mustNewBits(63, []uint64{0x376145C86129FCE6}),
			rbin:  "0b11011101100001010001011100100001100001001010011111110011100110",
			roct:  "0o335412134414112376346",
			rdec:  "3990547471752887526",
			rhex:  "0X376145C86129FCE6",
			rb62:  "4kmkU49SllO",
		},
		"should return expected correct results for more than 1 word odd varint": {
			vint:  mustNewVarInt(67, 100),
			at:    1,
			rbits: mustNewBits(67, []uint64{0x8049162673FA196E, 0x7}),
			rbin:  "0b1111000000001001001000101100010011001110011111110100001100101101110",
			roct:  "0o17001110542316376414556",
			rdec:  "138371152580531853678",
			rhex:  "0X78049162673FA196E",
			rb62:  "2erdLVDT8PFu",
		},
		"should return expected correct results for more than 2 word even varint": {
			vint:  mustNewVarInt(190, 100),
			at:    1,
			rbits: mustNewBits(190, []uint64{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76}),
			rbin:  "0b1100011100000010110010000001001000100110011101111111100111011001011101111000000001001001000101100010011001110011111110100001100101101110110000101000101110010000110000100101001111111001110011",
			roct:  "0o1434026201104635774731357001110542316376414556605056206045177163",
			rdec:  "1219933054867519094558795547060405704302187833031700840051",
			rhex:  "0X31C0B204899DFE765DE01245899CFE865BB0A2E43094FE73",
			rb62:  "XHPM4p4ZzSAKHOqUVckuRNpvF0eBpnGt",
		},
		"should return expected correct results for more than 3 word odd varint": {
			vint:  mustNewVarInt(217, 100),
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
	n := mustNewVarIntFF(217, 100)
	b := mustNewBits(217, []uint64{0x590244CEFF3B2EF0, 0x5172184A7F3998E0, 0x922C4CE7F432DD8, 0x13B2EF0})
	if err := n.SetBits(2, b); err != nil {
		t.Fatal(err)
	}
	nb, _ := n.AtBits(2)
	if !b.Equal(nb) {
		t.Fatalf("expected result %#v doesn't match actual result %#v", b, nb)
	}

	n = mustNewVarIntFF(190, 100)
	b = mustNewBits(190, []uint64{0x5BB0A2E43094FE73, 0x5DE01245899CFE86, 0x31C0B204899DFE76})
	if err := n.SetBits(1, b); err != nil {
		t.Fatal(err)
	}
	nb, _ = n.AtBits(1)
	if !b.Equal(nb) {
		t.Fatalf("expected result %#v doesn't match actual result %#v", b, nb)
	}

	n = mustNewVarIntFF(67, 100)
	b = mustNewBits(67, []uint64{0x8049162673FA196E, 0x7})
	if err := n.SetBits(1, b); err != nil {
		t.Fatal(err)
	}
	nb, _ = n.AtBits(1)
	if !b.Equal(nb) {
		t.Fatalf("expected result %#v doesn't match actual result %#v", b, nb)
	}

	n = mustNewVarIntFF(63, 100)
	b = mustNewBits(63, []uint64{0x376145C86129FCE6})
	if err := n.SetBits(2, b); err != nil {
		t.Fatal(err)
	}
	nb, _ = n.AtBits(2)
	if !b.Equal(nb) {
		t.Fatalf("expected result %#v doesn't match actual result %#v", b, nb)
	}

	n = mustNewVarIntFF(11, 100)
	b = mustNewBits(11, []uint64{0x4C7})
	if err := n.SetBits(17, b); err != nil {
		t.Fatal(err)
	}
	nb, _ = n.AtBits(17)
	if !b.Equal(nb) {
		t.Fatalf("expected result %#v doesn't match actual result %#v", b, nb)
	}

	n = mustNewVarIntFF(8, 100)
	b = mustNewBits(8, []uint64{0x43})
	if err := n.SetBits(19, b); err != nil {
		t.Fatal(err)
	}
	nb, _ = n.AtBits(19)
	if !b.Equal(nb) {
		t.Fatalf("expected result %#v doesn't match actual result %#v", b, nb)
	}
}
