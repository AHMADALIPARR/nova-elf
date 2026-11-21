# NOVA-ELF STATUS

Running status of the custom binary object format.
Verification scope and open items, as plain facts.

## What is verified by execution

- Codec bijectivity: D_c(E_c(B)) = B for NOVA-HEX16, NOVA-BASE32,
  NOVA-BASE64, NOVA-BASE256, and NOVA-BASE512, each tested on all 256
  byte values. All pass.
- ELF loader preserves the image: Load(ELF(M)) = M. The 731-cell image
  written to NOVA-ELF and read back is byte-identical. Pass.
- ELF round-trips through HEX16, BASE64, and BASE32 (bytes to text and
  back). All pass.
- GF semantics from the ELF-loaded image: 0 mismatches / 65,536 pairs.
  The image loaded from ELF computes gf_mul correctly for every input
  pair. Pass.
- ROMHEX round-trip: decode(encode(cells)) = cells. 731 lines. Pass.
- 32-bit signed word is faithful: image values span -1..729, sampled
  execution spans -256..510, all inside 32-bit signed range.

## Artifacts (v1, 731-cell image)

- `artifact/gf256.nova.elf`: 4,440 bytes.
  SHA-256: 4c2605a56c05fab29b5f80e6244a84791b5db7a2021511203c0b6d6b4b79057f.
- `artifact/gf256.nova.romhex`: 13,158 bytes, 731 lines.
  SHA-256: 9c570b3596fe01039c72545064036ec32a7ee693a1c957e2b4e3380e944d422b.
- `artifact/gf256.nova.hex16`: 8,880 bytes.
  SHA-256: 3e25e2a716c55f5b8bab3fb90a35d92b93cfb36e9fdf3f3e6036e8a83448b5b8.
- `artifact/gf256.nova.b64`: 5,920 bytes.
  SHA-256: 5bd543bf6badacd0043c48885f61ef35980cc08c6a6c8479eb659a804309a38e.
- Canonical image SHA-256 (the microcode identity, not the ELF file):
  153be573ab87f6a62f9c102cef88ee1a4e0ccfb501115c5e0ed0f8fa454ca673.
  The ELF file hash differs because the ELF includes headers, section
  metadata, and proof records. The image hash is the identity.

## Baseline (subleq.gf256.mul.v1)

- Total cells: 731. Code cells: 705 (235 SUBLEQ triples). Data cells: 26.
- Dynamic steps: min 333, max 7,978, avg ~3,908. Steps vary by input
  (data-dependent branches), so v1 is NOT constant-time. See below.

## Not verified here

- The ELF loader and codec are verified by round-trip in Racket. A
  separate proof obligation covers the ELF loader and codec, not just
  the arithmetic kernel; that obligation is registered, not discharged.
- e_machine 0xFF01 is unregistered (v1 only, processor-specific reserved
  range). It is not a registered machine type and must not be treated
  as one.
- NOVA-BASE512 is experimental. Its 9-bit symbol alphabet and padding
  rule are specified and the codec round-trips, but it has not been
  used in a shipped artifact.
- Constant-time behavior: the v1 step count varies 333..7,978 by input
  because the conditional XOR and the xtime reduction branch on secret
  operand bits. Functional correctness does not establish resistance to
  timing or power analysis. A constant-time variant is a separate
  obligation (see the hardware-refinement obligations in NovaDag).
- The VHDL ROM loader (decoded SUBLEQ image to hardware memory) is not
  built here. The ROMHEX artifact is the input to that loader.
- The hardware refinement proof (VHDL state transitions implementing
  the SUBLEQ model) is a separate, still-required step. It is listed as
  a pending obligation in the DAG node record.
