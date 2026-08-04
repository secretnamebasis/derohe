#include "textflag.h"

// Building-block AVX2 primitives for the wolf-loop branch-op kernel,
// verified independently before being composed into the real dispatch
// kernel. Each operates on a 32-byte buffer via load/store (not the fastest
// possible shape -- the composed kernel keeps values register-resident --
// but this shape makes each primitive independently testable against a
// scalar Go reference before anything is trusted to run unverified.

GLOBL mask0f<>(SB), RODATA, $32
DATA mask0f<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0f<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0f<>+16(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA mask0f<>+24(SB)/8, $0x0F0F0F0F0F0F0F0F

GLOBL mask33<>(SB), RODATA, $32
DATA mask33<>+0(SB)/8, $0x3333333333333333
DATA mask33<>+8(SB)/8, $0x3333333333333333
DATA mask33<>+16(SB)/8, $0x3333333333333333
DATA mask33<>+24(SB)/8, $0x3333333333333333

GLOBL mask55<>(SB), RODATA, $32
DATA mask55<>+0(SB)/8, $0x5555555555555555
DATA mask55<>+8(SB)/8, $0x5555555555555555
DATA mask55<>+16(SB)/8, $0x5555555555555555
DATA mask55<>+24(SB)/8, $0x5555555555555555

GLOBL popcntNibbleLUT<>(SB), RODATA, $32
DATA popcntNibbleLUT<>+0(SB)/8, $0x0302020102010100
DATA popcntNibbleLUT<>+8(SB)/8, $0x0403030203020201
DATA popcntNibbleLUT<>+16(SB)/8, $0x0302020102010100
DATA popcntNibbleLUT<>+24(SB)/8, $0x0403030203020201

// shiftPow2LUT[i] = 2^i for i in 0..7, 0 for i in 8..15 (per 128-bit lane,
// index selects via VPSHUFB's low nibble). Used to turn a per-lane variable
// shift-left-by-count into a per-lane multiply-by-2^count.
GLOBL shiftPow2LUT<>(SB), RODATA, $32
DATA shiftPow2LUT<>+0(SB)/8, $0x8040201008040201
DATA shiftPow2LUT<>+8(SB)/8, $0x0000000000000000
DATA shiftPow2LUT<>+16(SB)/8, $0x8040201008040201
DATA shiftPow2LUT<>+24(SB)/8, $0x0000000000000000

GLOBL maskLo16<>(SB), RODATA, $32
DATA maskLo16<>+0(SB)/8, $0x00FF00FF00FF00FF
DATA maskLo16<>+8(SB)/8, $0x00FF00FF00FF00FF
DATA maskLo16<>+16(SB)/8, $0x00FF00FF00FF00FF
DATA maskLo16<>+24(SB)/8, $0x00FF00FF00FF00FF

GLOBL maskHi16<>(SB), RODATA, $32
DATA maskHi16<>+0(SB)/8, $0xFF00FF00FF00FF00
DATA maskHi16<>+8(SB)/8, $0xFF00FF00FF00FF00
DATA maskHi16<>+16(SB)/8, $0xFF00FF00FF00FF00
DATA maskHi16<>+24(SB)/8, $0xFF00FF00FF00FF00

// reverse8Vec(in, out *[32]byte): out[i] = bits.Reverse8(in[i]), per byte.
// Swap-nibbles, swap-bitpairs, swap-bits -- word-granularity ops are safe
// here because each stage masks both operands down to values whose upper
// bits are already zero, so the word-level shift can't leak bits across the
// byte boundary within the same 16-bit lane.
TEXT ·reverse8Vec(SB), NOSPLIT, $0-16
	MOVQ in+0(FP), AX
	MOVQ out+8(FP), BX
	VMOVDQU (AX), Y0
	VMOVDQU mask0f<>(SB), Y5

	// swap nibbles
	VPAND Y5, Y0, Y1  // Y1 = v & 0x0F
	VPSLLW $4, Y1, Y1 // Y1 = (v&0x0F) << 4
	VPANDN Y0, Y5, Y2 // Y2 = v & ^0x0F  (i.e. v & 0xF0)
	VPSRLW $4, Y2, Y2 // Y2 = (v&0xF0) >> 4
	VPOR Y1, Y2, Y0    // Y0 = nibble-swapped v

	// swap bit-pairs
	VMOVDQU mask33<>(SB), Y5
	VPAND Y5, Y0, Y1
	VPSLLW $2, Y1, Y1
	VPANDN Y0, Y5, Y2
	VPSRLW $2, Y2, Y2
	VPOR Y1, Y2, Y0

	// swap bits
	VMOVDQU mask55<>(SB), Y5
	VPAND Y5, Y0, Y1
	VPSLLW $1, Y1, Y1
	VPANDN Y0, Y5, Y2
	VPSRLW $1, Y2, Y2
	VPOR Y1, Y2, Y0

	VMOVDQU Y0, (BX)
	VZEROUPPER
	RET

// popcount8Vec(in, out *[32]byte): out[i] = bits.OnesCount8(in[i]), per byte.
// Standard nibble-LUT popcount: popcount(byte) = popcount(lowNibble) +
// popcount(highNibble), each via a VPSHUFB gather into the 16-entry table.
TEXT ·popcount8Vec(SB), NOSPLIT, $0-16
	MOVQ in+0(FP), AX
	MOVQ out+8(FP), BX
	VMOVDQU (AX), Y0
	VMOVDQU mask0f<>(SB), Y5
	VMOVDQU popcntNibbleLUT<>(SB), Y6

	VPAND Y5, Y0, Y1   // low nibble
	VPSRLW $4, Y0, Y2
	VPAND Y5, Y2, Y2   // high nibble (word-shift safe: mask0f zeroes the bits that would leak)

	VPSHUFB Y1, Y6, Y1 // popcount(low nibble)
	VPSHUFB Y2, Y6, Y2 // popcount(high nibble)
	VPADDB Y2, Y1, Y0

	VMOVDQU Y0, (BX)
	VZEROUPPER
	RET

// shlVarVec(data, count, out *[32]byte): out[i] = data[i] << (count[i] & 7),
// per byte, zero-fill (matches Go's byte << semantics for shift amounts
// 0..7; count[i] values outside 0..7 are not valid inputs to this
// function -- callers must mask first). Implemented as data[i] *
// 2^count[i] mod 256, since AVX2 has no per-byte variable shift: split into
// even/odd byte lanes (via 16-bit word masking) so VPMULLW's 16-bit
// multiply doesn't let one byte's product bleed into its neighbor, matching
// the standard SIMD byte-multiply-via-word-multiply technique.
TEXT ·shlVarVec(SB), NOSPLIT, $0-24
	MOVQ data+0(FP), AX
	MOVQ count+8(FP), BX
	MOVQ out+16(FP), CX
	VMOVDQU (AX), Y0
	VMOVDQU (BX), Y1
	VMOVDQU shiftPow2LUT<>(SB), Y7
	VPSHUFB Y1, Y7, Y2 // Y2 = 2^count[i] per byte (0 if count[i]>=8)

	VMOVDQU maskLo16<>(SB), Y5
	VMOVDQU maskHi16<>(SB), Y6

	// low (even-indexed) bytes: mask both operands to low-byte-of-word,
	// 16-bit multiply keeps the correct low byte in place, no cross-byte
	// contamination since the high byte of each word is zero going in.
	VPAND Y5, Y0, Y3
	VPAND Y5, Y2, Y4
	VPMULLW Y4, Y3, Y3 // Y3 = (data_lo * mult_lo) as words; low byte of each word is the wanted result

	// high (odd-indexed) bytes: shift down to low-byte position, multiply,
	// shift back up.
	VPSRLW $8, Y0, Y8
	VPSRLW $8, Y2, Y9
	VPMULLW Y9, Y8, Y8
	VPSLLW $8, Y8, Y8

	VPAND Y5, Y3, Y3   // keep only the low byte of each low-lane word
	VPAND Y6, Y8, Y8   // keep only the high byte of each high-lane word (already positioned)
	VPOR Y3, Y8, Y0

	VMOVDQU Y0, (CX)
	VZEROUPPER
	RET

// mulSelfVec(in, out *[32]byte): out[i] = in[i] * in[i] mod 256, per byte.
// Same even/odd-lane word-multiply technique as shlVarVec, both operands
// being the input itself.
TEXT ·mulSelfVec(SB), NOSPLIT, $0-16
	MOVQ in+0(FP), AX
	MOVQ out+8(FP), BX
	VMOVDQU (AX), Y0
	VMOVDQU maskLo16<>(SB), Y5
	VMOVDQU maskHi16<>(SB), Y6

	VPAND Y5, Y0, Y3
	VPMULLW Y3, Y3, Y3

	VPSRLW $8, Y0, Y8
	VPMULLW Y8, Y8, Y8
	VPSLLW $8, Y8, Y8

	VPAND Y5, Y3, Y3
	VPAND Y6, Y8, Y8
	VPOR Y3, Y8, Y0

	VMOVDQU Y0, (BX)
	VZEROUPPER
	RET
