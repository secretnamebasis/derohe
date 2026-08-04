package astrobwtv3

import (
	"math/rand"
	"testing"
)

// TestBranchOpFastPathDifferential compares AstroBWTv3 with the opClass/opLUT
// fast paths enabled against forceScalarBranchOp (every op through the
// verbatim reference switch), on real end-to-end hashes rather than isolated
// per-op checks. Unlike TestOpLUTMatchesApplyBranchOp (which pins the tables
// against applyBranchOp directly), this exercises the fast paths exactly as
// the real wolf loop drives them: real pos1/pos2 spans up to 32 bytes, real
// op sequences chosen by the data itself, and -- critically -- ops 253/254/255
// mixed in among ordinary ops in situ, which is what actually caught the
// dropped-RC4-rekey bug during development (an isolated per-op check on a
// span of 1 couldn't see it, since the missing side effect only diverges
// output once a later op reads the stale state).
func TestBranchOpFastPathDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260804))
	iters := 20000
	if testing.Short() {
		iters = 500
	}

	lengths := []int{1, 4, 16, 48, 64, 128, 255, 512, 4096}
	for i := 0; i < iters; i++ {
		n := lengths[i%len(lengths)]
		buf := make([]byte, n)
		rnd.Read(buf)

		forceScalarBranchOp = false
		fast := AstroBWTv3(buf)
		forceScalarBranchOp = true
		scalar := AstroBWTv3(buf)
		forceScalarBranchOp = false

		if fast != scalar {
			t.Fatalf("iter %d (len=%d): fast-path hash %x != scalar-reference hash %x, input %x", i, n, fast, scalar, buf)
		}
	}
}
