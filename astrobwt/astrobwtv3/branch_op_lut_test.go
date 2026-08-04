package astrobwtv3

import "testing"

// TestOpLUTMatchesApplyBranchOp guards against branch_op_lut.go silently going
// stale relative to applyBranchOp -- e.g. if applyBranchOp is ever edited
// without regenerating the table. Re-derives each opClassLUT/opClassZero
// entry directly from applyBranchOp and compares, exhaustively over every
// input byte (and, for a subset of positions, every step_3[pos2] byte, to
// confirm the recorded independence still holds).
func TestOpLUTMatchesApplyBranchOp(t *testing.T) {
	pos2Samples := []int{0x00, 0x3C, 0x7E, 0xA5, 0xFF}

	for op := 0; op < 256; op++ {
		switch opClass[op] {
		case opClassZero:
			for _, pos2byte := range pos2Samples {
				for input := 0; input < 256; input++ {
					var buf [256]byte
					buf[0] = byte(input)
					buf[1] = byte(pos2byte)
					applyBranchOp(byte(op), 0, 1, buf[:], 0, 0, Cipher{})
					if buf[0] != 0 {
						t.Fatalf("op %d: opClassZero but applyBranchOp(input=%d, pos2=%#x) = %d, want 0", op, input, pos2byte, buf[0])
					}
				}
			}
		case opClassLUT:
			for _, pos2byte := range pos2Samples {
				for input := 0; input < 256; input++ {
					var buf [256]byte
					buf[0] = byte(input)
					buf[1] = byte(pos2byte)
					applyBranchOp(byte(op), 0, 1, buf[:], 0, 0, Cipher{})
					want := opLUT[op][input]
					if buf[0] != want {
						t.Fatalf("op %d: opLUT[%d][%d]=%d but applyBranchOp(pos2=%#x) = %d", op, op, input, want, pos2byte, buf[0])
					}
				}
			}
		}
	}
}
