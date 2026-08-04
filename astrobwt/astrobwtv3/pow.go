package astrobwtv3

import "fmt"

//import "os"
import "encoding/binary"
import "crypto/rand"

import "github.com/dchest/siphash"
import "github.com/cespare/xxhash"

//import "github.com/minio/highwayhash"
import "github.com/minio/sha256-simd"
import "github.com/segmentio/fasthash/fnv1a"
import "golang.org/x/crypto/salsa20/salsa"

var _ = fmt.Sprintf
var __ = rand.Read

// go test -bench=Benchmark_Tartarus_POW_128 -cpuprofile /tmp/profile.out ./ && go tool pprof -http :8080 /tmp/profile.out
// for coverage
// go test -coverprofile=/tmp/t.cov ./ && go tool cover -html=/tmp/t.cov && unlink /tmp/t.cov
// run this to generate random code which must be freezed before release
// go run random_code_gen.go -- ./pow.go ./pow.go

const CALCULATE_DISTRIBUTION = false
const REFERENCE_MODE = true

var ops [256]int
var steps = map[uint64]int{}

// this will generate a hash
func AstroBWTv3(input []byte) (outputhash [32]byte) {
	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)
	return astroBWTv3(input, scratch)
}

// astroBWTv3 is AstroBWTv3's body, taking scratch as an explicit parameter
// instead of pulling one from Pool internally. This gives callers a seam to
// force scratch.useTemplateSA = false (the divsufsort path) explicitly —
// used by this package's own differential tests, since AstroBWTv3 itself
// runs the template path by default (Pool.New sets useTemplateSA = true).
func astroBWTv3(input []byte, scratch *ScratchData) (outputhash [32]byte) {
	data_len := astroBWTv3Stream(input, scratch)
	if data_len == 0 {
		// astroBWTv3Stream panicked and recovered; preserve the original
		// behavior (return a random falsified hash which will fail the
		// check, rather than propagate the panic and crash the miner).
		var buf [16]byte
		rand.Read(buf[:])
		return sha256.Sum256(buf[:])
	}

	if LittleEndian {
		scratch.hasher.Reset()
		scratch.hasher.Write(scratch.sa_bytes[:data_len*4])
	} else {
		var s [MAX_LENGTH * 4]byte
		for i, c := range scratch.sa[:data_len] {
			binary.LittleEndian.PutUint32(s[i<<1:], uint32(c))
		}
		scratch.hasher.Reset()
		scratch.hasher.Write(s[:data_len*4])
	}

	_ = scratch.hasher.Sum(outputhash[:0])
	return outputhash
}

// AstroBWTv3Pair hashes two independent inputs, running their final SHA-256
// through the 2-way SHA-NI kernel (sha256mb_amd64.go) when available,
// falling back to two ordinary hashes otherwise -- see pairHashAvailable.
// Byte-identical to (AstroBWTv3(a), AstroBWTv3(b)) on every host, by
// construction: both the pairHashAvailable()==false branch and the rare
// mid-stream-panic branch call AstroBWTv3 directly, the exact same function
// any single-hash caller uses, rather than a separately maintained slow
// path that could drift from it.
func AstroBWTv3Pair(a, b []byte) (ha, hb [32]byte) {
	if !pairHashAvailable() {
		return AstroBWTv3(a), AstroBWTv3(b)
	}

	scratchA := Pool.Get().(*ScratchData)
	defer Pool.Put(scratchA)
	scratchB := Pool.Get().(*ScratchData)
	defer Pool.Put(scratchB)

	la := astroBWTv3Stream(a, scratchA)
	lb := astroBWTv3Stream(b, scratchB)
	if la == 0 || lb == 0 {
		// Rare: astroBWTv3Stream panicked and recovered on at least one
		// side. Rather than salvage a partial pair, fall back to two
		// independent, already-safe single hashes -- each gets its own
		// fresh scratch and its own Stream call/recover via AstroBWTv3.
		return AstroBWTv3(a), AstroBWTv3(b)
	}

	return sha256Sum256Pair(scratchA.sa_bytes[:la*4], scratchB.sa_bytes[:lb*4])
}

// astroBWTv3Stream runs every stage up to and including suffix-array
// construction: after it returns, scratch.sa[:data_len] holds the SA whose
// little-endian bytes are the final SHA-256 input. Split out of astroBWTv3
// so AstroBWTv3Pair can batch two nonces' final hashes through the 2-way
// SHA-NI path. Has its own panic recover, since it's now called from two
// places (astroBWTv3 and AstroBWTv3Pair) instead of one -- same reasoning
// as the original, undivided function's recover ("if something happens due
// to RAM issues in miner, we should continue, avoiding crashes if
// possible"). data_len == 0 on return is an unambiguous panic signal to the
// caller: the wolf loop's own minimum (261 tries) guarantees
// data_len >= 65792 on any real, non-panicking run.
func astroBWTv3Stream(input []byte, scratch *ScratchData) (data_len uint32) {

	//var static_key = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	defer func() {
		if recover() != nil { // if something happens due to RAM issues in miner, we should continue, avoiding crashes if possible
			data_len = 0
		}
	}()

	var step_3 [256]byte
	var counter [16]byte

	sha_key := sha256.Sum256(input)

	salsa.XORKeyStream(step_3[:], step_3[:], &counter, &sha_key)

	// https://docs.nvidia.com/cuda/ampere-tuning-guide/index.html
	// RC4 requires 256 bytes ( or registers ) on GPU ( assuming only registers are used)
	// each SM has 64K registers,expecting full occupancy, each SM can have 256 threads ( each with 256 registers) simultaneously
	// NVIDIA 3090Ti has 84 SMs, so max runnable instances = 84 * 256 = 21504
	// the below code should reduce GPUS as 84 core machine (running at 1Ghz)

	rc4s := NewCipher(step_3[:]) // new rc4 cipher, pkg from golang src, modified to avoid allocation
	rc4s.XORKeyStream(step_3[:], step_3[:])
	lhash := fnv1a.HashBytes64(step_3[:])
	prev_lhash := lhash // this is used to to randomly switch patterns

	tries := uint64(0)
	// Template-marker bookkeeping for sa_template.go: recorded unconditionally
	// (pure integer arithmetic on values already live below, no effect on
	// step_3/data/data_len/the final hash) so scratch.markers/nTemplates are
	// always populated. See sa_template.go's header.
	templateIdx := 0
	chunkCount := uint32(1)
	firstChunk := uint32(0)
	// the below for loop is branchy, TODO make it more branchy to avoid GPU/FPGA optimizations
	for { // keep the looop running n number of times,  n >= 1
		tries++

		random_switcher := prev_lhash ^ lhash ^ tries
		//	fmt.Printf("%d random_switcher %d %x\n",tries, random_switcher, random_switcher)

		// see https://github.com/golang/go/issues/5496
		op := byte(random_switcher)

		pos1 := byte(random_switcher >> 8)
		pos2 := byte(random_switcher >> 16)

		if pos1 > pos2 {
			pos1, pos2 = pos2, pos1
		}

		if pos2-pos1 > 32 { // give wave or wavefronts an optimization
			pos2 = pos1 + (pos2-pos1)&0x1f // max update 32 bytes
		}
		//pos_small := pos1 + (pos2-pos1)&0x7 // max update 8 bytes
		//_ = pos_small

		if CALCULATE_DISTRIBUTION {
			ops[op]++
		}

		_ = step_3[pos1:pos2] // bounds check elimination

		lhash, prev_lhash, rc4s = applyBranchOp(op, pos1, pos2, step_3[:], lhash, prev_lhash, rc4s)

		if step_3[pos1]-step_3[pos2] < 0x10 { // 6.25 % probability
			prev_lhash = lhash + prev_lhash
			lhash = xxhash.Sum64(step_3[:pos2]) // more deviations
		}

		if step_3[pos1]-step_3[pos2] < 0x20 { // 12.5 % probability
			prev_lhash = lhash + prev_lhash
			lhash = fnv1a.HashBytes64(step_3[:pos2]) // more deviations
		}

		if step_3[pos1]-step_3[pos2] < 0x30 { // 18.75 % probability
			prev_lhash = lhash + prev_lhash
			lhash = siphash.Hash(tries, prev_lhash, step_3[:pos2]) // more deviations
		}

		if step_3[pos1]-step_3[pos2] <= 0x40 { // 25% probablility
			rc4s.XORKeyStream(step_3[:], step_3[:]) // do the rc4

			// Close the template run that just ended and open a new one. See
			// sa_template.go's header for why this is safe to record
			// unconditionally.
			scratch.markers[templateIdx] = uint16(firstChunk<<7 | chunkCount)
			if tries > 1 {
				templateIdx++
			}
			firstChunk = uint32(tries) - 1
			chunkCount = 1
		} else {
			chunkCount++
		}

		step_3[255] = step_3[255] ^ step_3[pos1] ^ step_3[pos2]

		copy(scratch.data[(tries-1)*256:], step_3[:]) // copy all the tmp states

		if tries > 260+16 || (step_3[255] >= 0xf0 && tries > 260) { // keep looping until condition is satisfied
			break
		}

	}

	if CALCULATE_DISTRIBUTION {
		steps[tries]++
	}

	// Flush the final (unflushed) template.
	scratch.markers[templateIdx] = uint16(firstChunk<<7 | chunkCount)
	scratch.nTemplates = uint32(templateIdx + 1)

	// we may discard upto ~ 1KiB data from the stream
	data_len = uint32((tries-4)*256 + (uint64(step_3[253])<<8|uint64(step_3[254]))&0x3ff) // ensure wide  number of variants exists

	maybeCaptureScratch(scratch.data[:data_len], data_len)
	maybeCaptureScratchTemplate(scratch.data[:data_len], data_len, scratch.markers[:], scratch.nTemplates)
	if !scratch.useTemplateSA {
		text_32_0alloc(scratch.data[:data_len], scratch.sa[:data_len])
	} else if !buildTemplateSA(scratch, data_len) {
		// Decline falls back to this package's own production divsufsort
		// path (text_32_0alloc) — deliberately not SAIS, since divsufsort is
		// already faster than SAIS (see sa_template.go's header). The
		// template path is the default (Pool.New sets useTemplateSA = true),
		// so this is the real, live fallback for any hash it declines, not a
		// dead branch.
		templateSAFallbacks.Add(1)
		text_32_0alloc(scratch.data[:data_len], scratch.sa[:data_len])
	}

	return data_len
}
