package astrobwtv3

import "testing"

// TestSubOpSeqMatchesApplyBranchOp guards against branch_op_subops.go going
// stale relative to applyBranchOp, the same way TestOpLUTMatchesApplyBranchOp
// guards branch_op_lut.go. Re-derives each opSubSeq entry's output directly
// via applySubOpSeq and compares against applyBranchOp, over a sampled (not
// exhaustive, for speed -- exhaustiveness already happened once at generation
// time) grid of inputs and step_3[pos2] bytes.
func TestSubOpSeqMatchesApplyBranchOp(t *testing.T) {
	pos2Samples := []byte{0x00, 0x3C, 0x7E, 0xA5, 0xFF}

	for op, seq := range opSubSeq {
		if opClass[op] != opClassScalar {
			t.Fatalf("op %d: in opSubSeq but opClass[%d] = %d, want opClassScalar", op, op, opClass[op])
		}
		for _, pos2byte := range pos2Samples {
			for input := 0; input < 256; input++ {
				got := applySubOpSeq(seq, byte(input), pos2byte)
				want := referenceTransform(op, byte(input), pos2byte)
				if got != want {
					t.Fatalf("op %d seq %v: applySubOpSeq(input=%d, pos2=%#x) = %d, want %d", op, seq, input, pos2byte, got, want)
				}
			}
		}
	}
}
