package astrobwtv3

import (
	"math/bits"
	"math/rand"
	"testing"
)

func TestPrimitivesAgainstScalar(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))

	t.Run("reverse8", func(t *testing.T) {
		var in, out [32]byte
		rnd.Read(in[:])
		reverse8Vec(&in, &out)
		for i := range in {
			want := bits.Reverse8(in[i])
			if out[i] != want {
				t.Fatalf("i=%d in=%#x got=%#x want=%#x", i, in[i], out[i], want)
			}
		}
	})

	t.Run("popcount8", func(t *testing.T) {
		var in, out [32]byte
		rnd.Read(in[:])
		popcount8Vec(&in, &out)
		for i := range in {
			want := byte(bits.OnesCount8(in[i]))
			if out[i] != want {
				t.Fatalf("i=%d in=%#x got=%d want=%d", i, in[i], out[i], want)
			}
		}
	})

	t.Run("mulSelf", func(t *testing.T) {
		var in, out [32]byte
		rnd.Read(in[:])
		mulSelfVec(&in, &out)
		for i := range in {
			want := in[i] * in[i]
			if out[i] != want {
				t.Fatalf("i=%d in=%#x got=%d want=%d", i, in[i], out[i], want)
			}
		}
	})

	t.Run("shlVar", func(t *testing.T) {
		for trial := 0; trial < 50; trial++ {
			var data, count, out [32]byte
			rnd.Read(data[:])
			for i := range count {
				count[i] = byte(rnd.Intn(8)) // valid domain: 0..7
			}
			shlVarVec(&data, &count, &out)
			for i := range data {
				want := data[i] << count[i]
				if out[i] != want {
					t.Fatalf("trial=%d i=%d data=%#x count=%d got=%d want=%d", trial, i, data[i], count[i], out[i], want)
				}
			}
		}
		// count=8 (out of the "documented" 0..7 domain, but needed by the
		// rolVar(x,0) composition: rolVar uses srlVar(x, 8-count), which
		// hits shlVar(reverse8(x), 8) when count==0) -- confirm the LUT's
		// index-8-maps-to-0 design actually produces "shifted out entirely".
		var data, count, out [32]byte
		rnd.Read(data[:])
		for i := range count {
			count[i] = 8
		}
		shlVarVec(&data, &count, &out)
		for i := range out {
			if out[i] != 0 {
				t.Fatalf("shlVar(data=%#x, count=8): got=%d, want 0", data[i], out[i])
			}
		}
	})
}
