//go:build astrobwt_capture

package astrobwtv3

// ScratchCaptureHook, if non-nil, is called with a copy of scratch.data
// (truncated to dataLen) immediately before suffix-array construction, only
// when built with the astrobwt_capture tag. Used by the fixture generator
// (sa_fixture_gen_test.go) to extract realistic ~64-70KB suffix-array-
// construction inputs from real, unmodified AstroBWTv3() runs -- so
// benchmark/oracle fixtures are authentic rather than synthetically
// reconstructed. Nil by default; the generator sets it before calling
// AstroBWTv3().
var ScratchCaptureHook func(data []byte, dataLen uint32)

func maybeCaptureScratch(data []byte, dataLen uint32) {
	if ScratchCaptureHook == nil {
		return
	}
	// data aliases scratch.data, which is reused (sync.Pool) as soon as this
	// call returns, so the hook needs its own copy.
	cp := make([]byte, len(data))
	copy(cp, data)
	ScratchCaptureHook(cp, dataLen)
}
