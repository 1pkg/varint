package varint

import "testing"

func TestVarInt(t *testing.T) {
	v, err := NewVarInt(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	i, err := v.AtInt(1)
	if err != nil {
		t.Fatal(err)
	}
	if i != 0 {
		t.Fatal()
	}
	_, err = v.AddInt(1, 10)
	if err != nil {
		t.Fatal(err)
	}
	i, err = v.AtInt(1)
	if err != nil {
		t.Fatal(err)
	}
	if i != 10 {
		t.Fatal()
	}
	f, err := v.SubInt(1, 11)
	if err != nil {
		t.Fatal(err)
	}
	if f != true {
		t.Fatal()
	}
	i, err = v.AtInt(1)
	if err != nil {
		t.Fatal(err)
	}
	if i != -1 {
		t.Fatal()
	}
}
