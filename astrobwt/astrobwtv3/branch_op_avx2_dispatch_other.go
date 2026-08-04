//go:build !amd64

package astrobwtv3

// tryWolfPermuteAVX2 has no kernel on this arch: always declines, routing
// every op through the untouched applyBranchOp scalar path. See
// branch_op_avx2_dispatch_amd64.go for the real (amd64) path.
func tryWolfPermuteAVX2(op, pos1, pos2 byte, step_3 []byte) bool {
	return false
}
