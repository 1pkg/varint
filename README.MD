<p align="center">
    <img src="https://raw.githubusercontent.com/1pkg/varint/master/h_gopher.png" alt="varint"/>
</p>

# VarInt: fast & memory efficient arbitrary bit width integers in Go.

## Introduction

VarInt Go library provides fast & memory efficient arbitrary bit width unsigned integer array type.

The purpose of VarInt to provide the maximum memory compact way to use and store unsigned custom bits integers. It does so by storing all the integers adjacent to each other inside a continuous numeric byte slice. It allocates the underlying numeric bytes slice only once on creation and doesn't expect to allocate any more memory afterwards. VarInt provides all the basic arithmetic and bitwise operations. To apply any of these operations, internal bits manipulations are required which implies certain computational overhead. Thus providing a tradeoff between CPU time and memory. Overhead grows lineraly, proportionally to bit len and is comparable with overhead from big.Int operations. Unlike big.Int however, VarInt uses exact number of bits to store the integers inside. Which makes VarInt extremely memory efficient. For example, to store a slice of 100 integers 100 bit each, big.Int requires 12400 bits, while VarInt needs exactly 10000 bits. In the same fashion VarInt also provides an efficient way to store integers smaller than 64 bits. For example, to store a slice of 1000 integers 2 bit each, []uin8 requires 8000 bits, while VarInt needs exactly 2000 bits. However, note that VarInt is no way close to be optimized as well as big.Int, and provides diminishing returns as bit length grows above certain threshold.

Currently, in a conscious decision multiple operations are implemented in favour of simplicity and not computational complexity, this includes Mul that uses standard long multiplication instead of fast multiplication algorithms like Karatsuba multiplication, and Div that uses standard slow division instead of fast division algorithms. The main rationale behind this choice is the fact that VarInt has the most efficiency when used for small and medium size integers in the range of 1 to 5000 bit width, therefore asymptotic complexity should be less significant for this library. Note that VarInt carries a small fixed overhead internaly, it allocates 2 separate uint cells at the beginning of the numeric bytes slice to store length and bit length. It also collocates extra Bits variable at the end of numeric bytes slice which is used internally for many operations as a computation temporary buffer, including: Mul, Div, Mod, Sort. Currently, for simplicity and consistency most VarInt operations apply changes in place on the provided index and require the provided Bits to have exactly the same bit len, otherwise ErrorUnequalBitLengthCardinality is returned. Currently, VarInt provides only unsigned arithmetic.

## Examples

**Allocate 10000 integers VarInt 25 bits in width. And then fills it with its max value.**

```go
vint, _ := varint.NewVarInt(25, 10000)
b := varint.NewBits(25, []uint{ 33554431 })
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, b)
}
```

**Allocate 10000 integers VarInt 25 bits in width. Fills it with increasing values, and rotates it right.**

```go
vint, _ := varint.NewVarInt(25, 10000)
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, varint.NewBitsBits(25, varint.NewBitsUint(uint(i))))
}
b := varint.NewBits(25, nil)
_ = vint.Get(0, b)
for i := 1; i < 10000; i++ {
    _ = vint.GetSet(i, b)
}
_ = vint.Set(0, b)
```

**Allocates 10000 integers VarInt 50 bits in width. Fills it with random values, then finds min and max values.**

```go
vint, _ := varint.NewVarInt(50, 10000)
rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, varint.NewBitsRand(50, rnd))
}
bmin, bmax, b := varint.NewBits(50, nil), varint.NewBits(50, nil), varint.NewBits(50, nil)
_, _ = vint.Get(0, bmin), vint.Get(0, bmax)
for i := 1; i < 10000; i++ {
    _ = vint.Get(i, b)
    switch {
        case varint.Compare(b, bmin) == -1:
            bmin = varint.NewBitsBits(50, b)
        case varint.Compare(b, bmax) == 1:
            bmax = varint.NewBitsBits(50, b)
    }
}
```

**Allocates 10000 integers VarInt 50 bits in width. Fills it from big.Int channel, then subtracts 1000 from even numbers and adds 1 to odd numbers. Finally, converts integers back to the big.Int channel.**

```go
ch := make(chan *big.Int)
vint, _ := varint.NewVarInt(50, 10000)
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, varint.NewBitsBits(50, varint.NewBitsBigInt(<-ch)))
}
b1000, b1 := varint.NewBitsBits(50, varint.NewBitsUint(1000)), varint.NewBitsBits(50, varint.NewBitsUint(1))
for i := 0; i < 10000; i++ {
    if i % 2 == 0 {
        _ = vint.Sub(i, b1000)
    } else {
        _ = vint.Add(i, b1)
    }
}
for i := 0; i < 10000; i++ {
    _ = vint.Get(i, b1)
    ch <- b1.BigInt()
}
```

**Allocates 10000 integers VarInt 50 bits in width. Fills it with random values, then if bitwise negation for a number is even multiply it by 2.**

```go
vint, _ := varint.NewVarInt(50, 10000)
rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, varint.NewBitsRand(50, rnd))
}
b, b2 := varint.NewBits(50, nil), varint.NewBitsBits(50, varint.NewBitsUint(2))
for i := 0; i < 10000; i++ {
    _ = vint.Get(i, b)
    _ = vint.Not(i)
    _ = vint.Mod(i, b2)
    _ = vint.GetSet(i, b)
    if b.Empty() {
        _ = vint.Mul(i, b2)
    }
}
```

**Allocates 10000 integers VarInt 100 bits in width. Fills it with random values, then sorts it in ascending order.**

```go
vint, _ := varint.NewVarInt(100, 10000)
rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, varint.NewBitsRand(100, rnd))
}
sort.Sort(varint.Sortable(vint))
```

**Allocates 10000 integers VarInt 100 bits in width. Fills it with random values, then flushes it to a file and reads it back.**

```go
vint, _ := varint.NewVarInt(100, 10000)
rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
for i := 0; i < 10000; i++ {
    _ = vint.Set(i, varint.NewBitsRand(100, rnd))
}
f, _ := os.Create("vint.bin")
defer os.Remove(f.Name())
_, _ = f.ReadFrom(varint.Encode(vint))
f, _ = os.Open(f.Name())
_ = varint.Decode(f, vint)
```

## Benchmarks

**Arithmetic Operations 100000000 integers, 4 bits width**

|             | ns/op | B/op | allocs/op | allocs/MB |
| :---------: | :---: | :--: | :-------: | :-------: |
|   VarInt    | 103.3 |  0   |     0     |   47.69   |
| Uint8 Slice | 1.555 |  0   |     0     |   95.38   |

**Arithmetic Operations 10000000 integers, 64 bits width**

|              | ns/op | B/op | allocs/op | allocs/MB |
| :----------: | :---: | :--: | :-------: | :-------: |
|    VarInt    | 99.46 |  0   |     0     |   76.30   |
| Uint64 Slice | 2.398 |  0   |     0     |   76.30   |

**Arithmetic Operations 10000000 integers, 100 bits width**

|              | ns/op | B/op | allocs/op | allocs/MB |
| :----------: | :---: | :--: | :-------: | :-------: |
|    VarInt    | 169.4 |  0   |     0     |   119.2   |
| BigInt Slice | 504.9 | 120  |     3     |   495.9   |

**Arithmetic Operations 100000 integers, 10000 bits width**

|              |  ns/op   | B/op | allocs/op | allocs/MB |
| :----------: | :------: | :--: | :-------: | :-------: |
|    VarInt    |  78451   |  0   |     0     |   119.2   |
| BigInt Slice | 657.8 .0 | 148  |     2     |   145.8   |

**Bitwise Operations 100000000 integers, 4 bits width**

|             | ns/op | B/op | allocs/op | allocs/MB |
| :---------: | :---: | :--: | :-------: | :-------: |
|   VarInt    | 76.84 |  0   |     0     |   47.69   |
| Uint8 Slice | 2.42  |  0   |     0     |   95.38   |

**Arithmetic Operations 10000000 integers, 64 bits width**

|              | ns/op | B/op | allocs/op | allocs/MB |
| :----------: | :---: | :--: | :-------: | :-------: |
|    VarInt    | 79.06 |  0   |     0     |   76.30   |
| Uint64 Slice | 2.451 |  0   |     0     |   76.30   |

**Arithmetic Operations 10000000 integers, 100 bits width**

|              | ns/op | B/op | allocs/op | allocs/MB |
| :----------: | :---: | :--: | :-------: | :-------: |
|    VarInt    | 134.5 |  0   |     0     |   119.2   |
| BigInt Slice | 186.9 |  48  |     1     |   427.2   |

**Arithmetic Operations 100000 integers, 10000 bits width**

|              | ns/op | B/op | allocs/op | allocs/MB |
| :----------: | :---: | :--: | :-------: | :-------: |
|    VarInt    | 5273  |  0   |     0     |   119.2   |
| BigInt Slice | 172.3 | 153  |     0     |   150.3   |

The benchmarks from above are run using, see `BenchmarkVarIntOperations` for more details.

```
go version go1.19.3 darwin/amd64
Intel(R) Core(TM) i5-1030NG7 CPU @ 1.10GHz
go test -run=^$ -bench ^BenchmarkVarIntOperations$ github.com/1pkg/varint -benchtime 1000000x
```

## Licence

VarInt is licensed under the MIT License.  
See [LICENSE](LICENSE) for the full license text.
