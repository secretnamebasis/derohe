package astrobwtv3

import (
	"math/rand"
	"testing"
)

// srlVarComposed(x, count) = reverse8( shlVar( reverse8(x), count ) ), the
// identity used to derive right-shift from the verified reverse8+shlVar
// primitives (right-shift-by-k = reverse, left-shift-by-k, reverse again).
func srlVarComposed(data, count [32]byte) [32]byte {
	var rev, shifted, out [32]byte
	reverse8Vec(&data, &rev)
	shlVarVec(&rev, &count, &shifted)
	reverse8Vec(&shifted, &out)
	return out
}

func rolVarComposed(data, count [32]byte) [32]byte {
	var left [32]byte
	shlVarVec(&data, &count, &left)
	var rcount [32]byte
	for i := range rcount {
		rcount[i] = 8 - count[i]
	}
	right := srlVarComposed(data, rcount)
	var out [32]byte
	for i := range out {
		out[i] = left[i] | right[i]
	}
	return out
}

func TestCompositionAgainstScalar(t *testing.T) {
	rnd := rand.New(rand.NewSource(99))

	t.Run("srlVar", func(t *testing.T) {
		for trial := 0; trial < 100; trial++ {
			var data, count [32]byte
			rnd.Read(data[:])
			c := byte(rnd.Intn(8))
			for i := range count {
				count[i] = c
			}
			out := srlVarComposed(data, count)
			for i := range data {
				want := data[i] >> c
				if out[i] != want {
					t.Fatalf("trial=%d i=%d data=%#x count=%d got=%d want=%d", trial, i, data[i], c, out[i], want)
				}
			}
		}
	})

	t.Run("rolVar", func(t *testing.T) {
		for trial := 0; trial < 100; trial++ {
			var data, count [32]byte
			rnd.Read(data[:])
			c := byte(rnd.Intn(8))
			for i := range count {
				count[i] = c
			}
			out := rolVarComposed(data, count)
			for i := range data {
				want := rotl8Ref(data[i], c)
				if out[i] != want {
					t.Fatalf("trial=%d i=%d data=%#x count=%d got=%d want=%d", trial, i, data[i], c, out[i], want)
				}
			}
		}
	})
}

func rotl8Ref(x, k byte) byte {
	k &= 7
	if k == 0 {
		return x
	}
	return (x << k) | (x >> (8 - k))
}
