package astrobwtv3

import (
	"math/rand"
	"testing"
)

func TestWolfPermuteAVX2AgainstSubOpSeq(t *testing.T) {
	rnd := rand.New(rand.NewSource(2026))

	iters := 200000
	if testing.Short() {
		iters = 2000
	}
	for trial := 0; trial < iters; trial++ {
		var buf [64]byte
		rnd.Read(buf[:])
		orig := buf

		n := uint64(rnd.Intn(33)) // 0..32
		var seq [4]byte
		for i := range seq {
			seq[i] = byte(rnd.Intn(16))
		}
		pos2byte := byte(rnd.Intn(256))

		wolfPermuteAVX2Asm(&buf[0], &seq, pos2byte, n)

		for i := uint64(0); i < n; i++ {
			want := applySubOpSeq(seq, orig[i], pos2byte)
			if buf[i] != want {
				t.Fatalf("trial=%d n=%d seq=%v pos2byte=%#x i=%d: got=%#x want=%#x", trial, n, seq, pos2byte, i, buf[i], want)
			}
		}
		for i := n; i < 32; i++ {
			if buf[i] != orig[i] {
				t.Fatalf("trial=%d n=%d: byte %d outside [0,n) was modified: got=%#x want unchanged=%#x", trial, n, i, buf[i], orig[i])
			}
		}
		// bytes at index 32..63 (outside the kernel's 32-byte window entirely) must be untouched
		for i := 32; i < 64; i++ {
			if buf[i] != orig[i] {
				t.Fatalf("trial=%d: byte %d outside the 32-byte window was modified: got=%#x want=%#x", trial, i, buf[i], orig[i])
			}
		}
	}
}
