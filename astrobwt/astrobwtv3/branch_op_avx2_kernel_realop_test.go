package astrobwtv3

import (
	"math/rand"
	"testing"
)

func TestWolfPermuteAVX2AgainstApplyBranchOpRealOps(t *testing.T) {
	rnd := rand.New(rand.NewSource(4242))

	iters := 2000
	if testing.Short() {
		iters = 50
	}
	for op, seq := range opSubSeq {
		for trial := 0; trial < iters; trial++ {
			var buf [64]byte
			rnd.Read(buf[:])

			pos1 := byte(rnd.Intn(224)) // keep pos1+32 <= 256 conceptually; buffer here is only 64 but window logic is the same
			maxSpan := byte(32)
			if 64-int(pos1) < 32 {
				pos1 = byte(rnd.Intn(32))
			}
			pos2 := pos1 + byte(rnd.Intn(int(maxSpan)+1))
			if pos2 < pos1 {
				pos2 = pos1
			}
			if int(pos2) >= 64 {
				pos2 = 63
			}
			n := uint64(pos2 - pos1)

			refBuf := buf
			applyBranchOp(op, pos1, pos2, refBuf[:], 0, 0, Cipher{})

			avxBuf := buf
			pos2byte := avxBuf[pos2]
			wolfPermuteAVX2Asm(&avxBuf[pos1], &seq, pos2byte, n)

			for i := pos1; i < pos2; i++ {
				if avxBuf[i] != refBuf[i] {
					t.Fatalf("op=%d trial=%d pos1=%d pos2=%d i=%d: AVX2=%#x applyBranchOp=%#x", op, trial, pos1, pos2, i, avxBuf[i], refBuf[i])
				}
			}
		}
	}
}
