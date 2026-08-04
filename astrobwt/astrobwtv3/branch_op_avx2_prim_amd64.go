//go:build amd64

package astrobwtv3

//go:noescape
func reverse8Vec(in, out *[32]byte)

//go:noescape
func popcount8Vec(in, out *[32]byte)

//go:noescape
func shlVarVec(data, count, out *[32]byte)

//go:noescape
func mulSelfVec(in, out *[32]byte)
