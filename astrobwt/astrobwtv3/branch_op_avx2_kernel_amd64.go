//go:build amd64

package astrobwtv3

//go:noescape
func wolfPermuteAVX2Asm(data *byte, seq *[4]byte, pos2byte byte, n uint64)
