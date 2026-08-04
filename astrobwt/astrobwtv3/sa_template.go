package astrobwtv3

// Template-descriptor suffix array construction: a pure-Go port of the
// technique Dirtybird-Go-Miner calls "v1.14" (internal/astrobwt/sa_v114*.go,
// MIT), itself derived from a Zig/C++ reference (vendor/v114/v114_stubs.cpp,
// stage_v114_sa_build_compact_fused_raw and callees). It exploits the repeat
// structure of AstroBWTv3's own wolf-loop output rather than treating the
// hash's data buffer as opaque text: each "template" is a run of 256-byte
// chunks between RC4 rescrambles, recorded as markers during the wolf loop
// (see pow.go's whitening branch, `step_3[pos1]-step_3[pos2] <= 0x40`). That
// trigger is AstroBWTv3's own protocol, identical in every implementation
// that computes the same hash — the structure this file exploits is real,
// not specific to any one miner's fork.
//
// Correctness does NOT depend on the marker/flags partition accurately
// reflecting real whitening boundaries: Stage 4 (sa_template_emit.go) only
// establishes relative suffix order *within* one reconstructed run, and
// Stage 5 (sa_template_merge.go) reconciles different runs' records purely
// by radix-sorting on the true 3-byte data key, breaking ties with a real
// full-suffix comparison. A wrong or degenerate partition can only make
// Stage 4 slower or trip emitFullGroupRun's own groupCount>stage4MaxGroupRun
// decline (a clean, safe fallback to text_32_0alloc) — never produce a
// wrong suffix array.
//
// Faithful-port rules: singleton behavior is the reference default
// (count1_singletons == false). On any decline, the caller falls back to
// text_32_0alloc (this package's own divsufsort-backed path) — deliberately
// NOT to text_32_0alloc_sais, since divsufsort is already faster than SAIS,
// unlike the upstream reference (whose fallback is SAIS).
//
// This is the production SA-construction path: Pool.New (sa_fast.go) sets
// ScratchData.useTemplateSA = true for every pooled scratch, so AstroBWTv3
// itself runs this code by default. Force scratch.useTemplateSA = false (via
// astroBWTv3(input, scratch) in pow.go, which takes an explicit scratch) to
// get the divsufsort path instead — this package's own differential tests
// use that as the independent reference to check this path against.
//
// Buffer sizing diverges from the upstream reference in two constants,
// because this package's own MAX_LENGTH (98303, sa_fast.go) is looser than
// the reference's own (277*256 = 70912):
//
//   - markers/flags stay sized [280]uint16 / [280]byte (ScratchData,
//     sa_fast.go) — bounded by the wolf loop's own protocol-level tries<=277
//     termination (pow.go:2457), shared by any implementation of this hash,
//     independent of this package's separately-chosen MAX_LENGTH.
//   - templateArenaCapacity and stage4MaxGroupRun below are derived from
//     this package's own MAX_LENGTH / the same protocol tries bound
//     respectively, rather than reusing the reference's
//     arenaIndexCount-derived constants (sized off its MAX_LENGTH, not
//     this package's).
//
// See divsufsort_go.go's header for this package's convention of
// documenting a port's provenance in file-level prose.

import (
	"sync/atomic"
)

const (
	// templateArenaCapacity bounds templateSAScratch.arena: total spilled positions
	// across one whole hash's Stage 4 emission sum to exactly the input's
	// logical length (every byte position is visited exactly once, across
	// either the literal or arena path), so MAX_LENGTH is sufficient
	// headroom — see this file's header for why this differs from the
	// upstream reference's separately-sized arenaIndexCount.
	templateArenaCapacity = MAX_LENGTH
	// stage4MaxGroupRun bounds a single reconstructed template's chunk
	// count. buildStage5Flags derives run boundaries from markers' 7-bit
	// groupCount field (posData&0x7f, see below), so any single
	// flags-reconstructed run is inherently <=127 chunks regardless of the
	// real (possibly truncated, astronomically rare) chunkCount — 280
	// matches ScratchData.markers/flags' own sizing as generous, intentional
	// slop, not a tight derivation.
	stage4MaxGroupRun = 280
	stage4ShortRunMax = 25

	// stage5RunsCapacity bounds templateSAScratch.runs/radixTmp. Unlike
	// arena (which really does need close to MAX_LENGTH -- see above),
	// runs' theoretical worst case (every column of every group forming a
	// singleton key, ~256*totalGroups ~= MAX_LENGTH) is far above what real
	// AstroBWTv3 output produces: measured across 200,000 random
	// MINIBLOCK-sized inputs plus every real captured fixture
	// (TestMeasureTemplateSAUsage), len(runs) peaked at 28,358 (p99.99 was
	// 27,097) -- consistent with this package's own ~87%-of-groups-are-
	// structured finding (study.md) meaning most columns collapse into a
	// handful of arena-run records, not one singleton per column. 49,152
	// (exactly half of MAX_LENGTH) keeps ~1.7x margin over the observed
	// max while still roughly halving this buffer's footprint. If a hash
	// ever does exceed it, writeFusedRunsToSA declines cleanly to the
	// divsufsort fallback (same shape as every other decline in this
	// file) rather than growing or panicking -- correctness never depends
	// on this constant being large enough, only performance does.
	stage5RunsCapacity = MAX_LENGTH / 2

	// stage5MergeCapacity bounds templateSAScratch.groupPos/mergePos/
	// runLens/nextLens -- scratch for the k-way-merge fallback in
	// writeFusedRunsToSA, reached only when one Stage-5 equal-key group is
	// neither a single run, an all-literal group of <=32, nor exactly two
	// runs. Measured across the same 200,064-hash run: this path fired
	// 1,923,184 times (most hashes have several small equal-key
	// collisions) but the largest single group ever expanded was 924
	// positions -- nowhere near MAX_LENGTH. 4,096 keeps a >4x margin over
	// that observed max at roughly 1/24th the memory. Same decline
	// contract as stage5RunsCapacity: writeFusedRunsToSA checks before
	// calling mergeEqualKeyRuns and falls back rather than risking an
	// out-of-bounds slice.
	stage5MergeCapacity = 4096
)

// templateSAFallbacks counts hashes where the descriptor SA declined and
// text_32_0alloc ran instead (observability only; correctness is
// unaffected either way). Unexported: nothing outside this package needs
// the process-wide count.
var templateSAFallbacks atomic.Uint64

// templateSAKWayMergeHits counts Stage-5 equal-key groups that needed the
// rare k-way-merge path in writeFusedRunsToSA (groupPos/mergePos/runLens/
// nextLens), i.e. neither a single run, an all-literal group of <=32, nor
// exactly two runs. Observability only, same convention as
// templateSAFallbacks -- lets buffer-sizing decisions for those four
// buffers be based on how often this path is actually reachable in
// practice, not just its theoretical worst case.
var templateSAKWayMergeHits atomic.Uint64

// stage5Run mirrors the reference's 8-byte descriptor record. key is the
// native little-endian 24-bit load. packed: count<<17 | arenaBegin, or a
// literal position when the count bits are zero.
type stage5Run struct {
	key    uint32
	packed uint32
}

func (r stage5Run) encodedCount() uint32 { return r.packed >> 17 }
func (r stage5Run) isLiteral() bool      { return r.packed>>17 == 0 }
func (r stage5Run) begin() uint32        { return r.packed & 0x1ffff }
func (r stage5Run) count() uint32 {
	c := r.packed >> 17
	if c == 0 {
		return 1
	}
	return c
}

// templateSAScratch holds the reusable, pre-sized (0-alloc after
// construction) buffers for one ScratchData's template-descriptor SA path.
// Lazily allocated on first use (see buildTemplateSA).
type templateSAScratch struct {
	order    []uint32
	arena    []uint32
	runs     []stage5Run
	radixTmp []stage5Run
	groupPos []uint32
	mergePos []uint32
	runLens  []uint32
	nextLens []uint32
}

func newTemplateSAScratch() *templateSAScratch {
	return &templateSAScratch{
		order:    make([]uint32, 0, stage4MaxGroupRun),
		arena:    make([]uint32, 0, templateArenaCapacity),
		runs:     make([]stage5Run, 0, stage5RunsCapacity),
		radixTmp: make([]stage5Run, stage5RunsCapacity),
		groupPos: make([]uint32, 0, stage5MergeCapacity),
		mergePos: make([]uint32, stage5MergeCapacity),
		runLens:  make([]uint32, 0, stage5MergeCapacity),
		nextLens: make([]uint32, 0, stage5MergeCapacity),
	}
}

// buildStage5Flags derives group-boundary flags from the wolf-loop template
// markers. Returns 0 (and leaves flags untouched) on failure.
func buildStage5Flags(markers []uint16, nTemplates, logicalLen uint32, flags []byte) uint32 {
	if logicalLen == 0 {
		return 0
	}
	flagsLen := (logicalLen >> 8) + 1
	if uint32(len(flags)) < flagsLen {
		return 0
	}
	for i := uint32(0); i < flagsLen; i++ {
		flags[i] = 0
	}
	flags[0] = 1
	limit := nTemplates
	if limit > 277 {
		limit = 277
	}
	for i := uint32(0); i < limit; i++ {
		posData := uint32(markers[i])
		startGroup := posData >> 7
		groupCount := posData & 0x7f
		boundary := startGroup + groupCount
		if groupCount != 0 && boundary > 0 && boundary < flagsLen {
			flags[boundary] = 1
		}
	}
	return flagsLen
}

// stage4View bundles what the emit/merge stages read. data extends at least
// 4 zero bytes past logicalLen (padding for the unaligned 32-bit loads
// behind the 24-bit keys), which buildTemplateSA ensures.
type stage4View struct {
	data       []byte
	logicalLen uint32
}

// buildTemplateSA builds the suffix array of s.data[:logicalLen] into
// s.sa[:logicalLen] using the descriptor path. Returns false on any
// decline; the caller falls back to text_32_0alloc. LittleEndian only (sa
// int32s are written directly via an unsafe uint32 alias in
// writeFusedRunsToSA).
func buildTemplateSA(s *ScratchData, logicalLen uint32) bool {
	if !LittleEndian || logicalLen == 0 || logicalLen > templateArenaCapacity || s.nTemplates == 0 {
		return false
	}
	// zero the key-load padding (stale bytes from the previous hash, since
	// scratch.data is sync.Pool-reused): 3 key bytes plus a 4th so the
	// unaligned 32-bit key reads never see stale data.
	s.data[logicalLen] = 0
	s.data[logicalLen+1] = 0
	s.data[logicalLen+2] = 0
	s.data[logicalLen+3] = 0

	flagsLen := buildStage5Flags(s.markers[:], s.nTemplates, logicalLen, s.flags[:])
	if flagsLen == 0 {
		return false
	}
	if s.templateSA == nil {
		s.templateSA = newTemplateSAScratch()
	}
	v := s.templateSA
	v.arena = v.arena[:0]
	v.runs = v.runs[:0]

	view := stage4View{data: s.data[:], logicalLen: logicalLen}
	fullGroups := logicalLen >> 8
	runStart := uint32(0)
	for group := uint32(1); group <= fullGroups; group++ {
		if s.flags[group] != 0 || group == fullGroups {
			if !emitFullGroupRun(&view, runStart, group, v) {
				return false
			}
			runStart = group
		}
	}
	if !emitLiteralRecords(&view, fullGroups<<8, logicalLen&0xff, v) {
		return false
	}
	return writeFusedRunsToSA(&view, v, s.sa[:logicalLen])
}
