//go:build amd64

package astrobwtv3

import "github.com/klauspost/cpuid/v2"

var useAVX2Branch = cpuid.CPU.Supports(cpuid.AVX2)

// tryWolfPermuteAVX2 applies op's transform to step_3[pos1:pos2] via the
// AVX2 kernel if possible, reporting whether it did. Declines (returns
// false, no side effect on step_3) when: AVX2 isn't available, op has no
// derived sub-op sequence (op 0's cross-iteration swap, or ops 253/254/255
// whose mandatory lhash/rc4s side effects this kernel doesn't model -- see
// branch_op_lut_gen_test.go's exclusion list, which is also why those never
// appear in opSubSeq), or pos1+32 would read/write past step_3's end (up to
// ~12.5% of iterations at high pos1; the wolf loop's own clamp guarantees
// pos2-pos1 <= 32, but pos1 itself can still be close to len(step_3)).
func tryWolfPermuteAVX2(op, pos1, pos2 byte, step_3 []byte) bool {
	if !useAVX2Branch {
		return false
	}
	seq, ok := opSubSeq[op]
	if !ok {
		return false
	}
	if int(pos1)+32 > len(step_3) {
		return false
	}
	pos2byte := step_3[pos2]
	n := uint64(pos2 - pos1)
	wolfPermuteAVX2Asm(&step_3[pos1], &seq, pos2byte, n)
	return true
}
