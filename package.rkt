#lang racket

;; package.rkt — the NOVA-ELF packaging pipeline.
;;
;;   Cryptol GF(2^8) spec
;;     -> External Racket/Rosette compiler (subleq-lowering)
;;     -> SUBLEQ microcode, 731 cells
;;     -> NOVA-ELF writer
;;     -> Custom base encoder
;;     -> Decode + ELF loader
;;     -> VHDL SUBLEQ ROM (image)
;;   Artifact manifest -> NovaDag evidence ingestion.
;;
;; The SHA-256 digest is kept over the canonical binary image, not over
;; any textual base encoding, so encodings can change without changing
;; the identity of the underlying microcode.

(provide package-subleq-image
         load-subleq-image
         image->cells
         cells->image)

(require "elf.rkt"
         "codec.rkt"
         "../subleq-isa-racket/subleq/machine.rkt"
         "../subleq-isa-racket/subleq/asm.rkt")

;; The v1 image is 731 cells: 705 code cells (235 triples) + 26 data cells.
(define CODE-CELLS 705)
(define DATA-CELLS 26)

;; Split the flat image into code cells and data cells.
(define (image->cells image)
  (values (take image CODE-CELLS)
          (drop image CODE-CELLS)))

;; Reassemble the flat image from code cells and data cells.
(define (cells->image code-cells data-cells)
  (append code-cells data-cells))

;; Build the NOVA-ELF file (bytes) for a SUBLEQ image.
;; proof-json and dag-json are strings (UTF-8) placed in their sections.
(define (package-subleq-image image proof-json dag-json)
  (define-values (code-cells data-cells) (image->cells image))
  (define urom-content
    (bytes-append
     (u32 1) ; urom descriptor version
     (bytes
      #x13 #x76 #xfd #x6b #xd2 #x43 #x37 #x96 #x55 #x76 #x7a #x5e #xe2 #x2e #x26 #x0d
      #x37 #x3b #xb4 #x25 #xce #x43 #x71 #x56 #x2d #xb3 #xfa #x41 #x0d #x64 #x44 #x9f)
     (u32 #x20000000) ; VERIFY_MANIFEST
     (u32 #x40000000) ; LOCK_IMMUTABLE
     (u32 #x30040000) ; EXEC_INNER, inner_pc=0x040
     (u32 #xf0000000))) ; HALT
  (define sections
    (list
     (list ".nova.text" 1 6 4 (cells->bytes code-cells))
     (list ".nova.data" 1 3 4 (cells->bytes data-cells))
     (list ".nova.rodata" 1 2 1 SBOX)
     (list ".nova.urom" 1 2 4 urom-content)
     (list ".nova.proof" 1 0 1 (string->bytes/utf-8 proof-json))
     (list ".nova.codec" 1 0 1 (string->bytes/utf-8 "NOVA-BASE256 v1"))
     (list ".nova.dag" 1 0 1 (string->bytes/utf-8 dag-json))
     (list ".note.nova" 7 0 4 (note-nova-bytes))))
  (nova-elf-write sections))

;; Load a NOVA-ELF file (bytes) back into a flat SUBLEQ image.
;; Verifies Load(ELF(M)) = M is the caller's check; this returns the image.
(define (load-subleq-image elf-bytes)
  (define parsed (nova-elf-read elf-bytes))
  (define secs (nova-elf-sections parsed))
  (define text (hash-ref secs ".nova.text"))
  (define data (hash-ref secs ".nova.data"))
  (define (bytes->cells bs)
    (for/list ([i (in-range 0 (bytes-length bs) 4)])
      (integer-bytes->integer (subbytes bs i (+ i 4)) #t #f)))
  (cells->image (bytes->cells text) (bytes->cells data)))

;; Local u32 helper for the urom descriptor (elf.rkt exports cells->bytes
;; and note-nova-bytes; u32 is local to this module).
(define (u32 v) (integer->integer-bytes v 4 #f #f))
