# NOVA-ELF

The custom binary object format for the NovaDag SUBLEQ stack. ELF64 is
the container; it does not force the virtual CPU to use 64-bit arithmetic.
The SUBLEQ machine uses a 32-bit signed word (v1 serialization choice),
little-endian, instruction (a, b, c), word-addressed, entry at word
address 0, explicit halt.

This subsystem lives outside the DAG. The DAG records the artifacts,
hashes, and proof evidence. It does not contain the format tooling.

## Components

- `elf.rkt` — NOVA-ELF v1 writer and parser (Racket). ELF64 with the
  custom sections. e_machine is 0xFF01 (EM_NOVA_SUBLEQ, unregistered,
  v1 only, processor-specific reserved range). The object is relocatable
  (ET_REL) and is loaded by a dedicated NOVA loader, never executed as
  a native Linux binary.
- `codec.rkt` — the NOVA base-encoding family. NOVA-HEX16, NOVA-BASE32,
  NOVA-BASE64, NOVA-BASE256 (identity), NOVA-BASE512 (experimental
  9-bit symbols), NOVA-ROMHEX (word-addressed ROM initialization).
  These are encodings, not encryption. A custom alphabet does not add
  cryptographic security.
- `package.rkt` — the packaging pipeline. SUBLEQ image to NOVA-ELF,
  and NOVA-ELF back to a flat SUBLEQ image.
- `verify.rkt` — the verification contract, run by execution.

## Sections

| Section | Contents |
|---|---|
| .nova.text | SUBLEQ instruction triples (code) |
| .nova.data | Initial machine memory (data) |
| .nova.rodata | S-boxes, constants, tables (AES S-box, 256 bytes) |
| .nova.urom | Outer-ROM microprogram descriptors (digest + dispatch words) |
| .nova.proof | Proof metadata and evidence hashes |
| .nova.codec | Custom base encoding identifier |
| .nova.dag | Parent hashes and transformation lineage |
| .note.nova | Format, ISA, and ABI version information |

## The verification contract

The codec is bijective over its supported inputs: D_c(E_c(B)) = B. The
ELF loader preserves the SUBLEQ memory image: Load(ELF(M)) = M. The
packaged system preserves the tested machine semantics: the image loaded
from ELF computes GF(2^8) multiplication correctly for all 65,536 input
pairs, assuming the same defined machine model.

The SHA-256 digest is kept over the canonical binary image (the 731
cells), not over any textual base encoding. Encodings can change without
changing the identity of the underlying microcode.

## The 32-bit signed word

The v1 image values span -1..729 and sampled execution spans -256..510,
all well inside 32-bit signed range. The 32-bit signed word is a faithful
serialization for this image. Changing the arithmetic width can change
behavior; the width is part of the ABI recorded in .note.nova.

## Artifacts

`artifact/` holds the packaged outputs for the v1 731-cell image:
`gf256.nova.elf` (the NOVA-ELF file), `gf256.nova.romhex` (the ROM
initialization), `gf256.nova.hex16` and `gf256.nova.b64` (textual
encodings of the ELF).

## Running

Racket is at `~/workspace/.tools/racket/bin/racket`.

Run the full verification contract:

  racket verify.rkt

## Status

See `STATUS.md`.
