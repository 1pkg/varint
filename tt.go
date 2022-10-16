package varint

import (
	"math/big"
	"math/rand"
	"reflect"
	"runtime/debug"
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
	vint, err := NewVarInt(bits, length)
	if err != nil {
		t.Fatal(err)
	}
	t.VarInt = vint
	return vint
}

func (t tt) NewBits(bsize int, bits []uint) Bits {
	b, err := NewBits(bsize, bits)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsZero(bsize int) Bits {
	return t.NewBits(bsize, []uint{0x0})
}

func (t tt) NewBitsUint(n uint) Bits {
	b, err := NewBitsUint(n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsRand(bsize int) Bits {
	b, err := NewBitsRand(bsize, t.Rand)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsBigInt(i *big.Int) Bits {
	b, err := NewBitsBigInt(i)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (t tt) NewBitsB62(b62 string) Bits {
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
	b := t.NewBits(t.BitLen(), nil)
	if err := t.Get(i, b); err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
	return b
}

func (t tt) VarIntSet(i int, b Bits) {
	err := t.Set(i, b)
	if err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
}

func (t tt) VarIntCmp(i int, bits Bits) int {
	cmp, err := t.Cmp(i, bits)
	if err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
	return cmp
}

func (t tt) VarIntEqual(i int, bits ...Bits) {
	for _, b := range bits {
		cmp, err := t.Cmp(i, b)
		if err != nil {
			debug.PrintStack()
			t.Fatal(err)
		}
		if cmp == 0 {
			return
		}
	}
	b := t.VarIntGet(i)
	debug.PrintStack()
	t.Fatalf("bits %v are not equal %v", bits, b)
}

func (t tt) VarIntNotEqual(i int, bits ...Bits) {
	for _, b := range bits {
		cmp, err := t.Cmp(i, b)
		if err != nil {
			debug.PrintStack()
			t.Fatal(err)
		}
		if cmp != 0 {
			return
		}
	}
	b := t.VarIntGet(i)
	debug.PrintStack()
	t.Fatalf("bits %v are equal %v", bits, b)
}

func (t tt) NoError(err error, exceptions ...error) bool {
	if err != nil {
		for _, except := range exceptions {
			if err == except {
				return true
			}
		}
		debug.PrintStack()
		t.Fatal(err)
		return true
	}
	return false
}

func (t tt) Equal(i, j interface{}) {
	if !reflect.DeepEqual(i, j) {
		debug.PrintStack()
		t.Fatalf("values %v are not equal %v", i, j)
	}
}
