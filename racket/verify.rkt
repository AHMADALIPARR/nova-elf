#lang racket

;; verify.rkt — the NOVA-ELF verification contract.
;;
;; Checks, by execution:
;;   1. Codec bijective: D_c(E_c(B)) = B, for each codec.
;;   2. ELF loader preserves the image: Load(ELF(M)) = M.
;;   3. Packaged system preserves GF semantics: the image loaded from
;;      ELF computes gf_mul correctly for all 65,536 input pairs.
;;   4. ROMHEX round-trip: decode(encode(cells)) = cells.
;; The SHA-256 digest is over the canonical binary image, not over any
;; textual base encoding.

(require "elf.rkt"
         "codec.rkt"
         "package.rkt"
         "../subleq-lowering/gf256.rkt"
         "../subleq-isa-racket/subleq/machine.rkt"
         "../subleq-isa-racket/subleq/asm.rkt")

(define (check name actual expected)
  (unless (equal? actual expected)
    (error 'verify "FAIL ~a: got ~e, want ~e" name actual expected))
  (printf "ok ~a\n" name))

;; The canonical image: the 731-cell SUBLEQ gf_mul from the lowering engine.
(define-values (image labels) (assemble/labels (gf-mul-items)))
(define in-a-addr (hash-ref labels 'in-a))
(define in-b-addr (hash-ref labels 'in-b))
(define out-r-addr (hash-ref labels 'out-r))

(define proof-json
  "{\"exhaustive\":\"0 mismatches / 65536 pairs\",\"rosette\":\"zeroIdentity PROVED, oneIdentity PROVED, commutative PROVED\",\"image_sha256\":\"153be573ab87f6a62f9c102cef88ee1a4e0ccfb501115c5e0ed0f8fa454ca673\"}")
(define dag-json
  "{\"schema\":\"rijndael.dag.v1\",\"id\":\"subleq.gf256.mul.v1\",\"parents\":[\"cryptol.gf256.mul.v1\"]}")

;; ---------- 1. Codec bijectivity ----------
(define test-bytes (list->bytes (for/list ([i (in-range 256)]) i)))
(check "HEX16 bijective"
       (nova-hex16-decode (nova-hex16-encode test-bytes)) test-bytes)
(check "BASE32 bijective"
       (nova-base32-decode (nova-base32-encode test-bytes)) test-bytes)
(check "BASE64 bijective"
       (nova-base64-decode (nova-base64-encode test-bytes)) test-bytes)
(check "BASE256 bijective"
       (nova-base256-decode (nova-base256-encode test-bytes)) test-bytes)
(check "BASE512 bijective"
       (nova-base512-decode (nova-base512-encode test-bytes)) test-bytes)

;; ---------- 2. ELF round-trip: Load(ELF(M)) = M ----------
(define elf-bytes (package-subleq-image image proof-json dag-json))
(printf "ELF file size = ~a bytes\n" (bytes-length elf-bytes))
(define loaded-image (load-subleq-image elf-bytes))
(check "ELF loader preserves image" loaded-image image)

;; The ELF itself round-trips through each codec (bytes -> text -> bytes).
(check "ELF via HEX16"
       (nova-hex16-decode (nova-hex16-encode elf-bytes)) elf-bytes)
(check "ELF via BASE64"
       (nova-base64-decode (nova-base64-encode elf-bytes)) elf-bytes)
(check "ELF via BASE32"
       (nova-base32-decode (nova-base32-encode elf-bytes)) elf-bytes)

;; ---------- 3. GF semantics from the ELF-loaded image ----------
(define mismatches 0)
(for ([a (in-range 256)])
  (for ([b (in-range 256)])
    (define m (make-machine))
    (machine-load! m loaded-image)
    (vector-set! (machine-mem m) in-a-addr a)
    (vector-set! (machine-mem m) in-b-addr b)
    (define status (machine-run m))
    (unless (eq? status 'halted)
      (error 'verify "loaded image did not halt: ~a (a=~a b=~a)" status a b))
    (define got (vector-ref (machine-mem m) out-r-addr))
    (unless (= got (gf-mul-ref a b))
      (set! mismatches (add1 mismatches)))))
(printf "GF from ELF-loaded image: mismatches = ~a / 65536\n" mismatches)
(check "GF semantics preserved through ELF" mismatches 0)

;; ---------- 4. ROMHEX round-trip ----------
(define romhex-text (nova-romhex-encode image))
(define romhex-cells (nova-romhex-decode romhex-text))
(check "ROMHEX round-trip" romhex-cells image)
(printf "ROMHEX lines = ~a\n" (length (string-split romhex-text "\n")))

;; Write the artifacts.
(call-with-output-file "artifact/gf256.nova.elf"
  #:exists 'replace
  (lambda (out) (write-bytes elf-bytes out)))
(call-with-output-file "artifact/gf256.nova.romhex"
  #:exists 'replace
  (lambda (out) (display romhex-text out)))
(call-with-output-file "artifact/gf256.nova.hex16"
  #:exists 'replace
  (lambda (out) (display (nova-hex16-encode elf-bytes) out)))
(call-with-output-file "artifact/gf256.nova.b64"
  #:exists 'replace
  (lambda (out) (display (nova-base64-encode elf-bytes) out)))
(printf "artifacts written to artifact/\n")
