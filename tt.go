package varint

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

type tt struct {
	*testing.T
	*rand.Rand
	VarInt
}

func newtt(t *testing.T) tt {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	return tt{T: t, Rand: rnd}
}

func (t *tt) NewVarInt(bits, length int) VarInt {
	t.Helper()
	vint, err := NewVarInt(bits, length)
	if err != nil {
		t.Fatal(err)
	}
	t.VarInt = vint
	return vint
}

func (t tt) NewBits(bsize int, bits []uint) Bits {
	t.Helper()
	b, err := NewBits(bsize, bits)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsRand(bsize int) Bits {
	t.Helper()
	b, err := NewBitsRand(bsize, t.Rand)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsBigInt(i *big.Int) Bits {
	t.Helper()
	b, err := NewBitsBigInt(i)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsB62(b62 string) Bits {
	t.Helper()
	bits, err := NewBitsString(b62, 62)
	if err != nil {
		return t.NewBits(8, []uint{0xFF})
	}
	if bits.BitLen() == 0 {
		return t.NewBits(8, []uint{0xFF})
	}
	return bits
}

func (t tt) VarIntGet(i int) Bits {
	t.Helper()
	b := t.NewBits(t.BitLen(), nil)
	if err := t.Get(i, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) VarIntSet(i int, b Bits) {
	t.Helper()
	err := t.Set(i, b)
	if err != nil {
		t.Fatal(err)
	}
}

func (t tt) VarIntCmp(i int, bits Bits) int {
	t.Helper()
	cmp, err := t.Cmp(i, bits)
	if err != nil {
		t.Fatal(err)
	}
	return cmp
}

func (t tt) VarIntEqual(i int, bits Bits) {
	t.Helper()
	cmp, err := t.Cmp(i, bits)
	if err != nil {
		t.Fatal(err)
	}
	if cmp == 0 {
		return
	}
	b := t.VarIntGet(i)
	t.Fatalf("bits %s are not equal %s", bits.String(), b.String())
}

func (t tt) VarIntNotEqual(i int, bits Bits) {
	t.Helper()
	cmp, err := t.Cmp(i, bits)
	if err != nil {
		t.Fatal(err)
	}
	if cmp != 0 {
		return
	}
	b := t.VarIntGet(i)
	t.Fatalf("bits %s are equal %s", bits.String(), b.String())
}

func (t tt) NoError(err error, exceptions ...error) bool {
	t.Helper()
	if err != nil {
		for _, except := range exceptions {
			if err == except {
				return true
			}
		}
		t.Fatal(err)
		return true
	}
	return false
}

func (t tt) Equal(i, j interface{}) {
	t.Helper()
	if !reflect.DeepEqual(i, j) {
		t.Fatalf("values %v are not equal %v", i, j)
	}
}
