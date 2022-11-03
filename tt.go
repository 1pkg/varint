package varint

import (
	"math/rand"
	"reflect"
	"strings"
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

func (t tt) NewBitsB62(b62 string) Bits {
	t.Helper()
	bits := NewBitsString(b62, 62)
	if bits.BitLen() == 0 {
		t.SkipNow()
	}
	return bits
}

func (t tt) NewBits2B62(b62 string) (Bits, Bits) {
	t.Helper()
	rb62 := []rune(b62)
	for i, j := 0, len(rb62)-1; i <= j; i, j = i+1, j-1 {
		rb62[i], rb62[j] = rb62[j], rb62[i]
	}
	rb62s := string(rb62)
	var b1, b2 Bits
	if strings.Compare(b62, rb62s) < 0 {
		b1, b2 = t.NewBitsB62(rb62s), t.NewBitsB62(b62)
	} else {
		b1, b2 = t.NewBitsB62(b62), t.NewBitsB62(rb62s)
	}
	return b1, NewBits(b1.BitLen(), b2.Bytes())
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

func (t tt) VarIntGet(i int) Bits {
	t.Helper()
	b := NewBits(BitLen(t.VarInt), nil)
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
