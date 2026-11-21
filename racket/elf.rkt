#lang racket

;; elf.rkt — NOVA-ELF v1 writer and parser (Racket).
;;
;; NOVA-ELF is the custom binary object format for the NovaDag SUBLEQ
;; stack. ELF64 is the container; it does not force the virtual CPU to
;; use 64-bit arithmetic. The SUBLEQ machine uses a 32-bit signed word
;; (v1 serialization choice), little-endian, instruction (a, b, c),
;; word-addressed, entry at word address 0, explicit halt.
;;
;; The 32-bit signed word is faithful for the v1 731-cell image: image
;; values span -1..729 and sampled execution spans -256..510, all well
;; inside 32-bit signed range. Changing the arithmetic width can change
;; behavior; the width is part of the ABI recorded in .note.nova.
;;
;; e_machine is 0xFF01 (EM_NOVA_SUBLEQ, unregistered, v1 only). It is in
;; the processor-specific reserved range and is not a registered machine
;; type. The object is relocatable (ET_REL) and is loaded by a dedicated
;; NOVA loader, never executed as a native Linux binary.

(provide nova-elf-write
         nova-elf-read
         nova-elf-sections
         EM-NOVA-SUBLEQ
         NOVA-ELF-VERSION
         SBOX
         note-nova-bytes
         cells->bytes)

(define EM-NOVA-SUBLEQ #xFF01)
(define NOVA-ELF-VERSION 1)

;; Section names in order (index 0 is NULL).
(define SECTION-NAMES
  '(".nova.text" ".nova.data" ".nova.rodata" ".nova.urom"
    ".nova.proof" ".nova.codec" ".nova.dag" ".note.nova" ".shstrtab"))

;; ---------- byte helpers (little-endian) ----------

(define (u16 v) (integer->integer-bytes v 2 #f #f))
(define (u32 v) (integer->integer-bytes v 4 #f #f))
(define (u64 v) (integer->integer-bytes v 8 #f #f))
(define (i32 v) (integer->integer-bytes v 4 #t #f))

(define (pad-to n align)
  (define r (modulo n align))
  (if (= r 0) 0 (- align r)))

;; ---------- section content builders ----------

;; Cells (exact integers) -> 32-bit signed little-endian bytes.
(define (cells->bytes cells)
  (apply bytes-append (map i32 cells)))

;; The AES S-box (256 bytes), standard, from aes_custom_lowered.c.
(define SBOX
  (bytes
   #x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5 #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76
   #xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0 #xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0
   #xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc #x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15
   #x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a #x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75
   #x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0 #x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84
   #x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b #x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf
   #xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85 #x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8
   #x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5 #xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2
   #xcd #x0c #x13 #xec #x5f #x97 #x44 #x17 #xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73
   #x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88 #x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb
   #xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c #xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79
   #xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9 #x6c #x56 #xf4 #xea #x65 #x7a #xae #x08
   #xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6 #xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a
   #x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e #x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e
   #xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94 #x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf
   #x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68 #x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16))

;; Build the .note.nova content: one note, name "NOVA", type 1 (version).
;; Note layout: namesz u32, descsz u32, type u32, name (padded to 4),
;; desc (padded to 4). Desc is a UTF-8 version string.
(define (note-nova-bytes)
  (define name (string->bytes/utf-8 "NOVA"))
  (define desc (string->bytes/utf-8
                "NOVA-ELF v1; ISA SUBLEQ; ABI word=32-bit signed LE; entry=0; halt=explicit"))
  (define (pad4 b)
    (bytes-append b (make-bytes (pad-to (bytes-length b) 4) 0)))
  (bytes-append (u32 (bytes-length name))
                (u32 (bytes-length desc))
                (u32 1)
                (pad4 name)
                (pad4 desc)))

;; ---------- writer ----------
;; sections: a list of (name type flags align content-bytes), in order,
;; NOT including the NULL section or .shstrtab (both added here).
;; Returns the full ELF file as bytes.

(define (nova-elf-write sections)
  ;; Build .shstrtab: NUL-separated section names.
  (define shstr
    (apply bytes-append
           (cons (bytes 0)
                 (map (lambda (n)
                        (bytes-append (string->bytes/utf-8 n) (bytes 0)))
                      SECTION-NAMES))))
  (define name-offsets
    (let loop ([names SECTION-NAMES] [off 1] [acc (make-hash)])
      (if (null? names)
          acc
          (begin
            (hash-set! acc (car names) off)
            (loop (cdr names)
                  (+ off (bytes-length (string->bytes/utf-8 (car names))) 1)
                  acc)))))
  ;; Full section list: NULL + given + .shstrtab.
  (define all
    (append (list (list "" 0 0 0 (bytes)))
            sections
            (list (list ".shstrtab" 3 0 1 shstr))))
  (define shnum (length all))
  (define shstrndx (sub1 shnum))
  ;; Lay out contents after the 64-byte ELF header, 8-byte aligned.
  (define offset 64)
  (define laid
    (for/list ([s (in-list all)] [i (in-naturals)])
      (define content (list-ref s 4))
      (define align (list-ref s 3))
      (define pad (pad-to offset (max align 1)))
      (define off (+ offset pad))
      (set! offset (+ off (bytes-length content)))
      (list (list-ref s 0) (list-ref s 1) (list-ref s 2) off
            (bytes-length content) align)))
  ;; Section header table follows the contents, 8-byte aligned.
  (define shoff (+ offset (pad-to offset 8)))
  ;; ELF header.
  (define ehdr
    (bytes-append
     (bytes #x7f (char->integer #\E) (char->integer #\L) (char->integer #\F))
     (bytes 2 1 1 0 0)
     (make-bytes 7 0)
     (u16 1)                 ; e_type ET_REL
     (u16 EM-NOVA-SUBLEQ)   ; e_machine
     (u32 1)                 ; e_version
     (u64 0)                 ; e_entry (word address 0)
     (u64 0)                 ; e_phoff
     (u64 shoff)             ; e_shoff
     (u32 0)                 ; e_flags
     (u16 64)                ; e_ehsize
     (u16 0)                 ; e_phentsize
     (u16 0)                 ; e_phnum
     (u16 64)                ; e_shentsize
     (u16 shnum)             ; e_shnum
     (u16 shstrndx)))        ; e_shstrndx
  ;; Section contents blob.
  (define body
    (let loop ([secs all] [ls laid] [pos 64] [acc (list)])
      (if (null? secs)
          (apply bytes-append (reverse acc))
          (let* ([content (list-ref (car secs) 4)]
                 [off (list-ref (car ls) 3)]
                 [pad (make-bytes (- off pos) 0)])
            (loop (cdr secs) (cdr ls) (+ off (bytes-length content))
                  (cons content (cons pad acc)))))))
  ;; Section headers.
  (define shdrs
    (apply bytes-append
           (for/list ([s (in-list laid)] [i (in-naturals)])
             (define name (list-ref s 0))
             (bytes-append
              (u32 (if (= i 0) 0 (hash-ref name-offsets name)))
              (u32 (list-ref s 1))
              (u64 (list-ref s 2))
              (u64 0)
              (u64 (list-ref s 3))
              (u64 (list-ref s 4))
              (u32 0) (u32 0)
              (u64 (max (list-ref s 5) 1))
              (u64 0)))))
  (bytes-append ehdr body
                (make-bytes (- shoff (+ 64 (bytes-length body))) 0)
                shdrs))

;; ---------- reader ----------
;; Returns a hash: 'sections -> (hash name -> bytes), plus header fields.

(define (nova-elf-read data)
  (define (u16at b o) (integer-bytes->integer (subbytes b o (+ o 2)) #f #f))
  (define (u32at b o) (integer-bytes->integer (subbytes b o (+ o 4)) #f #f))
  (define (u64at b o) (integer-bytes->integer (subbytes b o (+ o 8)) #f #f))
  (unless (and (>= (bytes-length data) 64)
               (= (bytes-ref data 0) #x7f)
               (= (bytes-ref data 1) (char->integer #\E))
               (= (bytes-ref data 2) (char->integer #\L))
               (= (bytes-ref data 3) (char->integer #\F)))
    (error 'nova-elf-read "not an ELF file"))
  (unless (= (bytes-ref data 4) 2)
    (error 'nova-elf-read "not ELF64"))
  (unless (= (bytes-ref data 5) 1)
    (error 'nova-elf-read "not little-endian"))
  (define e-type (u16at data 16))
  (define e-machine (u16at data 18))
  (define e-entry (u64at data 24))
  (define e-shoff (u64at data 40))
  (define e-shentsize (u16at data 58))
  (define e-shnum (u16at data 60))
  (define e-shstrndx (u16at data 62))
  (unless (= e-machine EM-NOVA-SUBLEQ)
    (error 'nova-elf-read "not a NOVA-ELF (e_machine=~a)" e-machine))
  ;; Read section headers.
  (define shdrs
    (for/list ([i (in-range e-shnum)])
      (define o (+ e-shoff (* i e-shentsize)))
      (list (u32at data o)
            (u32at data (+ o 4))
            (u64at data (+ o 8))
            (u64at data (+ o 24))
            (u64at data (+ o 32)))))
  ;; .shstrtab content.
  (define shstr-hdr (list-ref shdrs e-shstrndx))
  (define shstr (subbytes data (list-ref shstr-hdr 3)
                          (+ (list-ref shstr-hdr 3) (list-ref shstr-hdr 4))))
  (define (sec-name off)
    (define end (or (for/first ([i (in-range off (bytes-length shstr))]
                                #:when (= (bytes-ref shstr i) 0))
                      i)
                    (bytes-length shstr)))
    (bytes->string/utf-8 (subbytes shstr off end)))
  (define sections (make-hash))
  (for ([h (in-list shdrs)] [i (in-naturals)])
    (when (> i 0)
      (define nm (sec-name (list-ref h 0)))
      (define off (list-ref h 3))
      (define sz (list-ref h 4))
      (hash-set! sections nm (subbytes data off (+ off sz)))))
  (hash 'type e-type
        'machine e-machine
        'entry e-entry
        'shnum e-shnum
        'sections sections))

(define (nova-elf-sections parsed)
  (hash-ref parsed 'sections))
