package varint

import (
	"runtime"
	"testing"
)

func mallocbench(b *testing.B, f func()) {
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	m := float64(after.TotalAlloc-before.TotalAlloc) / 1024 / 1024
	b.ReportMetric(m, "M_allocated")
}

func BenchmarkAddGetVarIntvsSlice(b *testing.B) {
	const len = 100000000
	b.Run("Benchmark VarInt Add/Get", func(b *testing.B) {
		mallocbench(b, func() {
			vint, _ := NewVarInt(4, len)
			bits := NewBits(4, []uint{10})
			tmp := NewBits(4, nil)
			for n := 0; n < b.N; n++ {
				_ = vint.Add(n%len, bits)
				_ = vint.Get(n%len, tmp)
			}
		})
	})
	b.Run("Benchmark Slice Add/Get", func(b *testing.B) {
		mallocbench(b, func() {
			slice := make([]uint8, len)
			for n := 0; n < b.N; n++ {
				slice[n%len] += 10
				_ = slice[n%len]
			}
		})
	})
}
