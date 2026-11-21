#lang racket

;; codec.rkt — the NOVA base-encoding family.
;;
;; Versioned, reversible encodings. These are encodings, not encryption:
;; a custom alphabet does not add cryptographic security.
;;
;;   NOVA-HEX16   human-readable bytes (2 hex chars per byte)
;;   NOVA-BASE32  compact textual representation (RFC 4648)
;;   NOVA-BASE64  transport and storage (RFC 4648)
;;   NOVA-BASE256 one-byte-per-symbol binary identity
;;   NOVA-BASE512 experimental 9-bit symbol alphabet
;;   NOVA-ROMHEX word-addressed FPGA/ASIC ROM initialization
;;
;; Every codec is bijective over its supported inputs:
;;   D_c(E_c(B)) = B.
;; The SHA-256 digest is kept over the canonical binary image, not over
;; any textual base encoding, so encodings can change without changing
;; the identity of the underlying microcode.

(provide nova-hex16-encode
         nova-hex16-decode
         nova-base32-encode
         nova-base32-decode
         nova-base64-encode
         nova-base64-decode
         nova-base256-encode
         nova-base256-decode
         nova-base512-encode
         nova-base512-decode
         nova-romhex-encode
         nova-romhex-decode
         codec-names)

(require net/base64)

(define codec-names
  '("NOVA-HEX16" "NOVA-BASE32" "NOVA-BASE64"
    "NOVA-BASE256" "NOVA-BASE512" "NOVA-ROMHEX"))

;; Index of a character in a string, or #f.
(define (char-index str ch)
  (let loop ([i 0])
    (cond
      [(>= i (string-length str)) #f]
      [(char=? (string-ref str i) ch) i]
      [else (loop (add1 i))])))

;; ---------- NOVA-HEX16 ----------

(define (nova-hex16-encode bs)
  (apply string-append
         (for/list ([b (in-bytes bs)])
           (format "~a~a"
                   (string-ref "0123456789abcdef" (arithmetic-shift b -4))
                   (string-ref "0123456789abcdef" (bitwise-and b #xf))))))

(define (nova-hex16-decode s)
  (unless (even? (string-length s))
    (error 'nova-hex16-decode "odd-length hex string"))
  (define (hexval c)
    (cond
      [(char<=? #\0 c #\9) (- (char->integer c) (char->integer #\0))]
      [(char<=? #\a c #\f) (+ 10 (- (char->integer c) (char->integer #\a)))]
      [(char<=? #\A c #\F) (+ 10 (- (char->integer c) (char->integer #\A)))]
      [else (error 'nova-hex16-decode "bad hex digit: ~a" c)]))
  (apply bytes
         (for/list ([i (in-range 0 (string-length s) 2)])
           (+ (* 16 (hexval (string-ref s i)))
              (hexval (string-ref s (add1 i)))))))

;; ---------- NOVA-BASE32 (RFC 4648, alphabet A-Z2-7, = padding) ----------

(define B32-ALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(define (nova-base32-encode bs)
  (define bits
    (apply append
           (for/list ([b (in-bytes bs)])
             (for/list ([k (in-range 7 -1 -1)])
               (if (bitwise-bit-set? b k) 1 0)))))
  (define nbits (length bits))
  (define npad (modulo (- 8 (modulo (ceiling (/ nbits 5)) 8)) 8))
  (define padded
    (append bits (make-list (modulo (- 5 (modulo nbits 5)) 5) 0)))
  (define groups
    (for/list ([i (in-range 0 (length padded) 5)])
      (for/sum ([j (in-range 5)])
        (* (list-ref padded (+ i j)) (arithmetic-shift 1 (- 4 j))))))
  (define chars
    (apply string-append
           (map (lambda (g) (string (string-ref B32-ALPHA g))) groups)))
  (string-append chars (make-string npad #\=)))

(define (nova-base32-decode s)
  (define clean (string-replace s "=" ""))
  (define (val c)
    (define idx (char-index B32-ALPHA c))
    (unless idx (error 'nova-base32-decode "bad base32 char: ~a" c))
    idx)
  (define bits
    (apply append
           (for/list ([c (in-string clean)])
             (define v (val c))
             (for/list ([k (in-range 4 -1 -1)])
               (if (bitwise-bit-set? v k) 1 0)))))
  (define nbytes (floor (/ (length bits) 8)))
  (apply bytes
         (for/list ([i (in-range nbytes)])
           (for/sum ([j (in-range 8)])
             (* (list-ref bits (+ (* i 8) j))
                (arithmetic-shift 1 (- 7 j)))))))

;; ---------- NOVA-BASE64 (RFC 4648) ----------

(define (nova-base64-encode bs)
  (bytes->string/utf-8 (base64-encode bs #"")))

(define (nova-base64-decode s)
  (base64-decode (string->bytes/utf-8 s)))

;; ---------- NOVA-BASE256 (identity) ----------

(define (nova-base256-encode bs) bs)
(define (nova-base256-decode bs) bs)

;; ---------- NOVA-BASE512 (experimental, 9-bit symbols) ----------
;; Bit order: MSB first. Input bytes form a bit stream; consecutive
;; 9-bit groups form symbols. The final group is zero-padded on the
;; right to 9 bits. Alphabet: Unicode code points U+0100..U+02FF
;; (512 symbols, Latin Extended-A/B). Decoding verifies the padding
;; bits are zero and the total bit count is a multiple of 8 after
;; removing padding, so different alphabets and bit-packing orders
;; never decode ambiguously. EXPERIMENTAL.

(define B512-ALPHA
  (apply string (for/list ([cp (in-range #x100 #x300)]) (integer->char cp))))

(define (nova-base512-encode bs)
  (define bits
    (apply append
           (for/list ([b (in-bytes bs)])
             (for/list ([k (in-range 7 -1 -1)])
               (if (bitwise-bit-set? b k) 1 0)))))
  (define nbits (length bits))
  (define npad (modulo (- 9 (modulo nbits 9)) 9))
  (define padded (append bits (make-list npad 0)))
  (define syms
    (for/list ([i (in-range 0 (length padded) 9)])
      (for/sum ([j (in-range 9)])
        (* (list-ref padded (+ i j)) (arithmetic-shift 1 (- 8 j))))))
  (apply string (map (lambda (v) (string-ref B512-ALPHA v)) syms)))

(define (nova-base512-decode s)
  (define (val c)
    (define idx (char-index B512-ALPHA c))
    (unless idx (error 'nova-base512-decode "bad base512 char"))
    idx)
  (define bits
    (apply append
           (for/list ([c (in-string s)])
             (define v (val c))
             (for/list ([k (in-range 8 -1 -1)])
               (if (bitwise-bit-set? v k) 1 0)))))
  (define nbytes (floor (/ (length bits) 8)))
  ;; Verify padding bits (the trailing bits beyond nbytes*8) are zero.
  (for ([i (in-range (* nbytes 8) (length bits))])
    (unless (= (list-ref bits i) 0)
      (error 'nova-base512-decode "nonzero padding bit")))
  (apply bytes
         (for/list ([i (in-range nbytes)])
           (for/sum ([j (in-range 8)])
             (* (list-ref bits (+ (* i 8) j))
                (arithmetic-shift 1 (- 7 j)))))))

;; ---------- NOVA-ROMHEX (word-addressed ROM initialization) ----------
;; Text, UTF-8, one word per line. Each line: 8 hex digits for the word
;; address, a space, 8 hex digits for the 32-bit value (two's complement,
;; lowercase hex). Lines starting with # are comments. The address is
;; explicit, so the format is word-addressed and unambiguous.
;; Encode takes a list of (address value) pairs or a list of values
;; starting at address 0.

(define (nova-romhex-encode cells)
  ;; cells: list of exact integers (32-bit signed), address = index.
  (apply string-append
         (for/list ([v (in-list cells)] [i (in-naturals)])
           (format "~a ~a\n"
                   (~a (number->string i 16) #:width 8 #:align 'right #:pad-string "0")
                   (~a (number->string (modulo v (expt 2 32)) 16)
                       #:width 8 #:align 'right #:pad-string "0")))))

(define (nova-romhex-decode s)
  (define mem (make-hash))
  (for ([line (in-list (string-split s "\n"))])
    (define t (string-trim line))
    (unless (or (string=? t "") (string-prefix? t "#"))
      (define parts (string-split t))
      (unless (= (length parts) 2)
        (error 'nova-romhex-decode "bad line: ~a" line))
      (define addr (string->number (first parts) 16))
      (define uval (string->number (second parts) 16))
      (unless (and addr uval)
        (error 'nova-romhex-decode "bad hex in line: ~a" line))
      ;; Convert unsigned 32-bit to signed.
      (define v (if (>= uval (expt 2 31)) (- uval (expt 2 32)) uval))
      (hash-set! mem addr v)))
  (define addrs (sort (hash-keys mem) <))
  (define max-addr (if (null? addrs) -1 (apply max addrs)))
  ;; Return the dense list from address 0..max-addr (missing = 0).
  (for/list ([i (in-range (add1 max-addr))])
    (hash-ref mem i 0)))
