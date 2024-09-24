/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#include "st7.hpp"

//--------------------------------------------------------------------------
static const uchar primary[256] =
{
  ST7_btjt,  // btjt short, #0, brl   ; 5 3    00 XX XX
  ST7_btjf,  // btjf short, #0, brl   ; 5 3    01 XX XX
  ST7_btjt,  // btjt short, #1, brl   ; 5 3    02 XX XX
  ST7_btjf,  // btjf short, #1, brl   ; 5 3    03 XX XX
  ST7_btjt,  // btjt short, #2, brl   ; 5 3    04 XX XX
  ST7_btjf,  // btjf short, #2, brl   ; 5 3    05 XX XX
  ST7_btjt,  // btjt short, #3, brl   ; 5 3    06 XX XX
  ST7_btjf,  // btjf short, #3, brl   ; 5 3    07 XX XX
  ST7_btjt,  // btjt short, #4, brl   ; 5 3    08 XX XX
  ST7_btjf,  // btjf short, #4, brl   ; 5 3    09 XX XX
  ST7_btjt,  // btjt short, #5, brl   ; 5 3    0A XX XX
  ST7_btjf,  // btjf short, #5, brl   ; 5 3    0B XX XX
  ST7_btjt,  // btjt short, #6, brl   ; 5 3    0C XX XX
  ST7_btjf,  // btjf short, #6, brl   ; 5 3    0D XX XX
  ST7_btjt,  // btjt short, #7, brl   ; 5 3    0E XX XX
  ST7_btjf,  // btjf short, #7, brl   ; 5 3    0F XX XX
  ST7_bset,  // bset short, #0        ; 5 2    10 XX
  ST7_bres,  // bres short, #0        ; 5 2    11 XX
  ST7_bset,  // bset short, #1        ; 5 2    12 XX
  ST7_bres,  // bres short, #1        ; 5 2    13 XX
  ST7_bset,  // bset short, #2        ; 5 2    14 XX
  ST7_bres,  // bres short, #2        ; 5 2    15 XX
  ST7_bset,  // bset short, #3        ; 5 2    16 XX
  ST7_bres,  // bres short, #3        ; 5 2    17 XX
  ST7_bset,  // bset short, #4        ; 5 2    18 XX
  ST7_bres,  // bres short, #4        ; 5 2    19 XX
  ST7_bset,  // bset short, #5        ; 5 2    1A XX
  ST7_bres,  // bres short, #5        ; 5 2    1B XX
  ST7_bset,  // bset short, #6        ; 5 2    1C XX
  ST7_bres,  // bres short, #6        ; 5 2    1D XX
  ST7_bset,  // bset short, #7        ; 5 2    1E XX
  ST7_bres,  // bres short, #7        ; 5 2    1F XX
  ST7_jra,   // jra   rel             ; 3 2    20 XX
  ST7_jrf,   // jrf   rel             ; 3 2    21 XX
  ST7_jrugt, // jrugt rel             ; 3 2    22 XX
  ST7_jrule, // jrule rel             ; 3 2    23 XX
  ST7_jrnc,  // jrnc  rel             ; 3 2    24 XX
  ST7_jrc,   // jrc   rel             ; 3 2    25 XX
  ST7_jrne,  // jrne  rel             ; 3 2    26 XX
  ST7_jreq,  // jreq  rel             ; 3 2    27 XX
  ST7_jrnh,  // jrnh  rel             ; 3 2    28 XX
  ST7_jrh,   // jrh   rel             ; 3 2    29 XX
  ST7_jrpl,  // jrpl  rel             ; 3 2    2A XX
  ST7_jrmi,  // jrmi  rel             ; 3 2    2B XX
  ST7_jrnm,  // jrnm  rel             ; 3 2    2C XX
  ST7_jrm,   // jrm   rel             ; 3 2    2D XX
  ST7_jril,  // jril  rel             ; 3 2    2E XX
  ST7_jrih,  // jrih  rel             ; 3 2    2F XX
  ST7_neg,   // neg short             ; 5 2    30 XX
  ST7_null,  //                                31
  ST7_null,  //                                32
  ST7_cpl,   // cpl short             ; 5 2    33 XX
  ST7_srl,   // srl short             ; 5 2    34 XX
  ST7_null,  //                                35
  ST7_rrc,   // rrc short             ; 5 2    36 XX
  ST7_sra,   // sra short             ; 5 2    37 XX
  ST7_sll,   // sll short             ; 5 2    38 XX
  ST7_rlc,   // rlc short             ; 5 2    39 XX
  ST7_dec,   // dec short             ; 5 2    3A XX
  ST7_null,  //                                3B
  ST7_inc,   // inc short             ; 5 2    3C XX
  ST7_tnz,   // tnz short             ; 4 2    3D XX
  ST7_swap,  // swap short            ; 5 2    3E XX
  ST7_clr,   // clr short             ; 5 2    3F XX
  ST7_neg,   // neg a                 ; 3 1    40
  ST7_null,  //                                41
  ST7_mul,   // mul x, a              ;11 1    42
  ST7_cpl,   // cpl a                 ; 3 1    43
  ST7_srl,   // srl a                 ; 3 1    44
  ST7_null,  //                                45
  ST7_rrc,   // rrc a                 ; 3 1    46
  ST7_sra,   // sra a                 ; 3 1    47
  ST7_sll,   // sll a                 ; 3 1    48
  ST7_rlc,   // rlc a                 ; 3 1    49
  ST7_dec,   // dec a                 ; 3 1    4A
  ST7_null,  //                                4B
  ST7_inc,   // inc a                 ; 3 1    4C
  ST7_tnz,   // tnz a                 ; 3 1    4D
  ST7_swap,  // swap a                ; 3 1    4E
  ST7_clr,   // clr a                 ; 3 1    4F
  ST7_neg,   // neg x                 ; 3 1    50
  ST7_null,  //                                51
  ST7_null,  //                                52
  ST7_cpl,   // cpl x                 ; 3 1    53
  ST7_srl,   // srl x                 ; 3 1    54
  ST7_null,  //                                55
  ST7_rrc,   // rrc x                 ; 3 1    56
  ST7_sra,   // sra x                 ; 3 1    57
  ST7_sll,   // sll x                 ; 3 1    58
  ST7_rlc,   // rlc x                 ; 3 1    59
  ST7_dec,   // dec x                 ; 3 1    5A
  ST7_null,  //                                5B
  ST7_inc,   // inc x                 ; 3 1    5C
  ST7_tnz,   // tnz x                 ; 3 1    5D
  ST7_swap,  // swap x                ; 3 1    5E
  ST7_clr,   // clr x                 ; 3 1    5F
  ST7_neg,   // neg (short,x)         ; 6 2    60 XX
  ST7_null,  //                                61
  ST7_null,  //                                62
  ST7_cpl,   // cpl (short,x)         ; 6 2    63 XX
  ST7_srl,   // srl (short,x)         ; 6 2    64 XX
  ST7_null,  //                                65
  ST7_rrc,   // rrc (short,x)         ; 6 2    66 XX
  ST7_sra,   // sra (short,x)         ; 6 2    67 XX
  ST7_sll,   // sll (short,x)         ; 6 2    68 XX
  ST7_rlc,   // rlc (short,x)         ; 6 2    69 XX
  ST7_dec,   // dec (short,x)         ; 6 2    6A XX
  ST7_null,  //                                6B
  ST7_inc,   // inc (short,x)         ; 6 2    6C XX
  ST7_tnz,   // tnz (short,x)         ; 5 2    6D XX
  ST7_swap,  // swap (short,x)        ; 6 2    6E XX
  ST7_clr,   // clr (short,x)         ; 6 2    6F XX
  ST7_neg,   // neg (x)               ; 5 1    70
  ST7_null,  //                                71
  ST7_null,  //                                72
  ST7_cpl,   // cpl (x)               ; 5 1    73
  ST7_srl,   // srl (x)               ; 5 1    74
  ST7_null,  //                                75
  ST7_rrc,   // rrc (x)               ; 5 1    76
  ST7_sra,   // sra (x)               ; 5 1    77
  ST7_sll,   // sll (x)               ; 5 1    78
  ST7_rlc,   // rlc (x)               ; 5 1    79
  ST7_dec,   // dec (x)               ; 5 1    7A
  ST7_null,  //                                7B
  ST7_inc,   // inc (x)               ; 5 1    7C
  ST7_tnz,   // tnz (x)               ; 4 1    7D
  ST7_swap,  // swap (x)              ; 5 1    7E
  ST7_clr,   // clr (x)               ; 5 1    7F
  ST7_iret,  // iret                  ; 9 1    80
  ST7_ret,   // ret                   ; 6 1    81
  ST7_null,  //                                82
  ST7_trap,  // trap                  ; 1 1    83
  ST7_pop,   // pop a                 ; 4 1    84
  ST7_pop,   // pop x                 ; 4 1    85
  ST7_pop,   // pop cc                ; 4 1    86
  ST7_null,  //                                87
  ST7_push,  // push a                ; 3 1    88
  ST7_push,  // push x                ; 3 1    89
  ST7_push,  // push cc               ; 3 1    8A
  ST7_null,  //                                8B
  ST7_null,  //                                8C
  ST7_null,  //                                8D
  ST7_halt,  // halt                  ; 2 1    8E
  ST7_wfi,   // wfi                   ; 2 1    8F
  ST7_null,  //                                90
  ST7_null,  //                                91
  ST7_null,  //                                92
  ST7_ld,    // ld x, y               ; 2 1    93
  ST7_ld,    // ld s, x               ; 2 1    94
  ST7_ld,    // ld s, a               ; 2 1    95
  ST7_ld,    // ld x, s               ; 2 1    96
  ST7_ld,    // ld x, a               ; 2 1    97
  ST7_rcf,   // rcf                   ; 2 1    98
  ST7_scf,   // scf                   ; 2 1    99
  ST7_rim,   // rim                   ; 2 1    9A
  ST7_sim,   // sim                   ; 2 1    9B
  ST7_rsp,   // rsp                   ; 2 1    9C
  ST7_nop,   // nop                   ; 2 1    9D
  ST7_ld,    // ld a, s               ; 2 1    9E
  ST7_ld,    // ld a, x               ; 2 1    9F
  ST7_sub,   // sub a, #byte          ; 2 2    A0 XX
  ST7_cp,    // cp a, #byte           ; 2 2    A1 XX
  ST7_sbc,   // sbc a, #byte          ; 2 2    A2 XX
  ST7_cp,    // cp x, #byte           ; 2 2    A3 XX
  ST7_and,   // and a, #byte          ; 2 2    A4 XX
  ST7_bcp,   // bcp a, #byte          ; 2 2    A5 XX
  ST7_ld,    // ld a, #byte           ; 2 2    A6 XX
  ST7_null,  //                                A7
  ST7_xor,   // xor a, #byte          ; 2 2    A8 XX
  ST7_adc,   // adc a, #byte          ; 2 2    A9 XX
  ST7_or,    // or a, #byte           ; 2 2    AA XX
  ST7_add,   // add a, #byte          ; 2 2    AB XX
  ST7_null,  //                                AC
  ST7_callr, // callr callrl          ; 6 2    AD XX
  ST7_ld,    // ld x, #byte           ; 2 2    AE XX
  ST7_null,  //                                AF
  ST7_sub,   // sub a, short          ; 3 2    B0 XX
  ST7_cp,    // cp a, short           ; 3 2    B1 XX
  ST7_sbc,   // sbc a, short          ; 3 2    B2 XX
  ST7_cp,    // cp x, short           ; 3 2    B3 XX
  ST7_and,   // and a, short          ; 3 2    B4 XX
  ST7_bcp,   // bcp a, short          ; 3 2    B5 XX
  ST7_ld,    // ld a, short           ; 3 2    B6 XX
  ST7_ld,    // ld short, a           ; 4 2    B7 XX
  ST7_xor,   // xor a, short          ; 3 2    B8 XX
  ST7_adc,   // adc a, short          ; 3 2    B9 XX
  ST7_or,    // or a, short           ; 3 2    BA XX
  ST7_add,   // add a, short          ; 3 2    BB XX
  ST7_jp,    // jp short              ; 2 2    BC XX
  ST7_call,  // call short            ; 5 2    BD XX
  ST7_ld,    // ld x, short           ; 3 2    BE XX
  ST7_ld,    // ld short, x           ; 4 2    BF XX
  ST7_sub,   // sub a, long           ; 4 3    C0 MS LS
  ST7_cp,    // cp a, long            ; 4 3    C1 MS LS
  ST7_sbc,   // sbc a, long           ; 4 3    C2 MS LS
  ST7_cp,    // cp x, long            ; 4 3    C3 MS LS
  ST7_and,   // and a, long           ; 4 3    C4 MS LS
  ST7_bcp,   // bcp a, long           ; 4 3    C5 MS LS
  ST7_ld,    // ld a, long            ; 4 3    C6 MS LS
  ST7_ld,    // ld long, a            ; 5 3    C7 MS LS
  ST7_xor,   // xor a, long           ; 4 3    C8 MS LS
  ST7_adc,   // adc a, long           ; 4 3    C9 MS LS
  ST7_or,    // or a, long            ; 4 3    CA MS LS
  ST7_add,   // add a, long           ; 4 3    CB MS LS
  ST7_jp,    // jp long               ; 3 3    CC MS LS
  ST7_call,  // call long             ; 6 3    CD MS LS
  ST7_ld,    // ld x, long            ; 4 3    CE MS LS
  ST7_ld,    // ld long, x            ; 5 3    CF MS LS
  ST7_sub,   // sub a, (long,x)       ; 5 3    D0 MS LS
  ST7_cp,    // cp a, (long,x)        ; 5 3    D1 MS LS
  ST7_sbc,   // sbc a, (long,x)       ; 5 3    D2 MS LS
  ST7_cp,    // cp x, (long,x)        ; 5 3    D3 MS LS
  ST7_and,   // and a, (long,x)       ; 5 3    D4 MS LS
  ST7_bcp,   // bcp a, (long,x)       ; 5 3    D5 MS LS
  ST7_ld,    // ld a, (long,x)        ; 5 3    D6 MS LS
  ST7_ld,    // ld (long,x), a        ; 6 3    D7 MS LS
  ST7_xor,   // xor a, (long,x)       ; 5 3    D8 MS LS
  ST7_adc,   // adc a, (long,x)       ; 5 3    D9 MS LS
  ST7_or,    // or a, (long,x)        ; 5 3    DA MS LS
  ST7_add,   // add a, (long,x)       ; 5 3    DB MS LS
  ST7_jp,    // jp (long,x)           ; 4 3    DC MS LS
  ST7_call,  // call (long,x)         ; 7 3    DD MS LS
  ST7_ld,    // ld x, (long,x)        ; 5 3    DE MS LS
  ST7_ld,    // ld (long,x), x        ; 6 3    DF MS LS
  ST7_sub,   // sub a, (short,x)      ; 4 2    E0 XX
  ST7_cp,    // cp a, (short,x)       ; 4 2    E1 XX
  ST7_sbc,   // sbc a, (short,x)      ; 4 2    E2 XX
  ST7_cp,    // cp x, (short,x)       ; 4 2    E3 XX
  ST7_and,   // and a, (short,x)      ; 4 2    E4 XX
  ST7_bcp,   // bcp a, (short,x)      ; 4 2    E5 XX
  ST7_ld,    // ld a, (short,x)       ; 4 2    E6 XX
  ST7_ld,    // ld (short,x), a       ; 5 2    E7 XX
  ST7_xor,   // xor a, (short,x)      ; 4 2    E8 XX
  ST7_adc,   // adc a, (short,x)      ; 4 2    E9 XX
  ST7_or,    // or a, (short,x)       ; 4 2    EA XX
  ST7_add,   // add a, (short,x)      ; 4 2    EB XX
  ST7_jp,    // jp (short,x)          ; 3 2    EC XX
  ST7_call,  // call (short,x)        ; 6 2    ED XX
  ST7_ld,    // ld x, (short,x)       ; 4 2    EE XX
  ST7_ld,    // ld (short,x), x       ; 5 2    EF XX
  ST7_sub,   // sub a, (x)            ; 3 1    F0
  ST7_cp,    // cp a, (x)             ; 3 1    F1
  ST7_sbc,   // sbc a, (x)            ; 3 1    F2
  ST7_cp,    // cp x, (x)             ; 3 1    F3
  ST7_and,   // and a, (x)            ; 3 1    F4
  ST7_bcp,   // bcp a, (x)            ; 3 1    F5
  ST7_ld,    // ld a, (x)             ; 3 1    F6
  ST7_ld,    // ld (x), a             ; 4 1    F7
  ST7_xor,   // xor a, (x)            ; 3 1    F8
  ST7_adc,   // adc a, (x)            ; 3 1    F9
  ST7_or,    // or a, (x)             ; 3 1    FA
  ST7_add,   // add a, (x)            ; 3 1    FB
  ST7_jp,    // jp (x)                ; 2 1    FC
  ST7_call,  // call (x)              ; 5 1    FD
  ST7_ld,    // ld x, (x)             ; 3 1    FE
  ST7_ld,    // ld (x), x             ; 4 1    FF
};

struct opcode_t
{
  nameNum itype;
  uchar opcode;
};

static const opcode_t pre90[] =
{
  { ST7_mul,   0x42 },  // mul y, a              ; 90 42
  { ST7_neg,   0x50 },  // neg y                 ; 90 50
  { ST7_cpl,   0x53 },  // cpl y                 ; 90 53
  { ST7_srl,   0x54 },  // srl y                 ; 90 54
  { ST7_rrc,   0x56 },  // rrc y                 ; 90 56
  { ST7_sra,   0x57 },  // sra y                 ; 90 57
//  { ST7_sla,   0x58 },  // sla y                 ; 90 58
  { ST7_sll,   0x58 },  // sll y                 ; 90 58
  { ST7_rlc,   0x59 },  // rlc y                 ; 90 59
  { ST7_dec,   0x5A },  // dec y                 ; 90 5A
  { ST7_inc,   0x5C },  // inc y                 ; 90 5C
  { ST7_tnz,   0x5D },  // tnz y                 ; 90 5D
  { ST7_swap,  0x5E },  // swap y                ; 90 5E
  { ST7_clr,   0x5F },  // clr y                 ; 90 5F
  { ST7_neg,   0x60 },  // neg (short,y)         ; 90 60 XX
  { ST7_cpl,   0x63 },  // cpl (short,y)         ; 90 63 XX
  { ST7_srl,   0x64 },  // srl (short,y)         ; 90 64 XX
  { ST7_rrc,   0x66 },  // rrc (short,y)         ; 90 66 XX
  { ST7_sra,   0x67 },  // sra (short,y)         ; 90 67 XX
//  { ST7_sla,   0x68 },  // sla (short,y)         ; 90 68 XX
  { ST7_sll,   0x68 },  // sll (short,y)         ; 90 68 XX
  { ST7_rlc,   0x69 },  // rlc (short,y)         ; 90 69 XX
  { ST7_dec,   0x6A },  // dec (short,y)         ; 90 6A XX
  { ST7_inc,   0x6C },  // inc (short,y)         ; 90 6C XX
  { ST7_tnz,   0x6D },  // tnz (short,y)         ; 90 6D XX
  { ST7_swap,  0x6E },  // swap (short,y)        ; 90 6E XX
  { ST7_clr,   0x6F },  // clr (short,y)         ; 90 6F XX
  { ST7_neg,   0x70 },  // neg (y)               ; 90 70
  { ST7_cpl,   0x73 },  // cpl (y)               ; 90 73
  { ST7_srl,   0x74 },  // srl (y)               ; 90 74
  { ST7_rrc,   0x76 },  // rrc (y)               ; 90 76
  { ST7_sra,   0x77 },  // sra (y)               ; 90 77
//  { ST7_sla,   0x78 },  // sla (y)               ; 90 78
  { ST7_sll,   0x78 },  // sll (y)               ; 90 78
  { ST7_rlc,   0x79 },  // rlc (y)               ; 90 79
  { ST7_dec,   0x7A },  // dec (y)               ; 90 7A
  { ST7_inc,   0x7C },  // inc (y)               ; 90 7C
  { ST7_tnz,   0x7D },  // tnz (y)               ; 90 7D
  { ST7_swap,  0x7E },  // swap (y)              ; 90 7E
  { ST7_clr,   0x7F },  // clr (y)               ; 90 7F
  { ST7_pop,   0x85 },  // pop y                 ; 90 85
  { ST7_push,  0x89 },  // push y                ; 90 89
  { ST7_ld,    0x93 },  // ld y, x               ; 90 93
  { ST7_ld,    0x94 },  // ld s, y               ; 90 94
  { ST7_ld,    0x96 },  // ld y, s               ; 90 96
  { ST7_ld,    0x97 },  // ld y, a               ; 90 97
  { ST7_ld,    0x9F },  // ld a, y               ; 90 9F
  { ST7_cp,    0xA3 },  // cp y, #byte           ; 90 A3 XX
  { ST7_ld,    0xAE },  // ld y, #byte           ; 90 AE XX
  { ST7_cp,    0xB3 },  // cp y, short           ; 90 B3 XX
  { ST7_ld,    0xBE },  // ld y, short           ; 90 BE XX
  { ST7_ld,    0xBF },  // ld short, y           ; 90 BF XX
  { ST7_cp,    0xC3 },  // cp y, long            ; 90 C3 MS LS
  { ST7_ld,    0xCE },  // ld y, long            ; 90 CE MS LS
  { ST7_ld,    0xCF },  // ld long, y            ; 90 CF MS LS
  { ST7_sub,   0xD0 },  // sub a, (long,y)       ; 90 D0 MS LS
  { ST7_cp,    0xD1 },  // cp a, (long,y)        ; 90 D1 MS LS
  { ST7_sbc,   0xD2 },  // sbc a, (long,y)       ; 90 D2 MS LS
  { ST7_cp,    0xD3 },  // cp y, (long,y)        ; 90 D3 MS LS
  { ST7_and,   0xD4 },  // and a, (long,y)       ; 90 D4 MS LS
  { ST7_bcp,   0xD5 },  // bcp a, (long,y)       ; 90 D5 MS LS
  { ST7_ld,    0xD6 },  // ld a, (long,y)        ; 90 D6 MS LS
  { ST7_ld,    0xD7 },  // ld (long,y), a        ; 90 D7 MS LS
  { ST7_xor,   0xD8 },  // xor a, (long,y)       ; 90 D8 MS LS
  { ST7_adc,   0xD9 },  // adc a, (long,y)       ; 90 D9 MS LS
  { ST7_or,    0xDA },  // or a, (long,y)        ; 90 DA MS LS
  { ST7_add,   0xDB },  // add a, (long,y)       ; 90 DB MS LS
  { ST7_jp,    0xDC },  // jp (long,y)           ; 90 DC MS LS
  { ST7_call,  0xDD },  // call (long,y)         ; 90 DD MS LS
  { ST7_ld,    0xDE },  // ld y, (long,y)        ; 90 DE MS LS
  { ST7_ld,    0xDF },  // ld (long,y), y        ; 90 DF MS LS
  { ST7_sub,   0xE0 },  // sub a, (short,y)      ; 90 E0 XX
  { ST7_cp,    0xE1 },  // cp a, (short,y)       ; 90 E1 XX
  { ST7_sbc,   0xE2 },  // sbc a, (short,y)      ; 90 E2 XX
  { ST7_cp,    0xE3 },  // cp y, (short,y)       ; 90 E3 XX
  { ST7_and,   0xE4 },  // and a, (short,y)      ; 90 E4 XX
  { ST7_bcp,   0xE5 },  // bcp a, (short,y)      ; 90 E5 XX
  { ST7_ld,    0xE6 },  // ld a, (short,y)       ; 90 E6 XX
  { ST7_ld,    0xE7 },  // ld (short,y), a       ; 90 E7 XX
  { ST7_xor,   0xE8 },  // xor a, (short,y)      ; 90 E8 XX
  { ST7_adc,   0xE9 },  // adc a, (short,y)      ; 90 E9 XX
  { ST7_or,    0xEA },  // or a, (short,y)       ; 90 EA XX
  { ST7_add,   0xEB },  // add a, (short,y)      ; 90 EB XX
  { ST7_jp,    0xEC },  // jp (short,y)          ; 90 EC XX
  { ST7_call,  0xED },  // call (short,y)        ; 90 ED XX
  { ST7_ld,    0xEE },  // ld y, (short,y)       ; 90 EE XX
  { ST7_ld,    0xEF },  // ld (short,y), y       ; 90 EF XX
  { ST7_sub,   0xF0 },  // sub a, (y)            ; 90 F0
  { ST7_cp,    0xF1 },  // cp a, (y)             ; 90 F1
  { ST7_sbc,   0xF2 },  // sbc a, (y)            ; 90 F2
  { ST7_cp,    0xF3 },  // cp y, (y)             ; 90 F3
  { ST7_and,   0xF4 },  // and a, (y)            ; 90 F4
  { ST7_bcp,   0xF5 },  // bcp a, (y)            ; 90 F5
  { ST7_ld,    0xF6 },  // ld a, (y)             ; 90 F6
  { ST7_ld,    0xF7 },  // ld (y), a             ; 90 F7
  { ST7_xor,   0xF8 },  // xor a, (y)            ; 90 F8
  { ST7_adc,   0xF9 },  // adc a, (y)            ; 90 F9
  { ST7_or,    0xFA },  // or a, (y)             ; 90 FA
  { ST7_add,   0xFB },  // add a, (y)            ; 90 FB
  { ST7_jp,    0xFC },  // jp (y)                ; 90 FC
  { ST7_call,  0xFD },  // call (y)              ; 90 FD
  { ST7_ld,    0xFE },  // ld y, (y)             ; 90 FE
  { ST7_ld,    0xFF },  // ld (y), y             ; 90 FF
};

static const opcode_t pre91[] =
{
  { ST7_neg,   0x60 },  // neg ([short],y)       ; 91 60 XX
  { ST7_cpl,   0x63 },  // cpl ([short],y)       ; 91 63 XX
  { ST7_srl,   0x64 },  // srl ([short],y)       ; 91 64 XX
  { ST7_rrc,   0x66 },  // rrc ([short],y)       ; 91 66 XX
  { ST7_sra,   0x67 },  // sra ([short],y)       ; 91 67 XX
//  { ST7_sla,   0x68 },  // sla ([short],y)       ; 91 68 XX
  { ST7_sll,   0x68 },  // sll ([short],y)       ; 91 68 XX
  { ST7_rlc,   0x69 },  // rlc ([short],y)       ; 91 69 XX
  { ST7_dec,   0x6A },  // dec ([short],y)       ; 91 6A XX
  { ST7_inc,   0x6C },  // inc ([short],y)       ; 91 6C XX
  { ST7_tnz,   0x6D },  // tnz ([short],y)       ; 91 6D XX
  { ST7_swap,  0x6E },  // swap ([short],y)      ; 91 6E XX
  { ST7_clr,   0x6F },  // clr ([short],y)       ; 91 6F XX
  { ST7_cp,    0xB3 },  // cp y, [short]         ; 91 B3 XX
  { ST7_ld,    0xBE },  // ld y, [short]         ; 91 BE XX
  { ST7_ld,    0xBF },  // ld [short], y         ; 91 BF XX
  { ST7_cp,    0xC3 },  // cp y, [short.w]       ; 91 C3 XX
  { ST7_ld,    0xCE },  // ld y, [short.w]       ; 91 CE XX
  { ST7_ld,    0xCF },  // ld [short.w], y       ; 91 CF XX
  { ST7_sub,   0xD0 },  // sub a, ([short.w],y)  ; 91 D0 XX
  { ST7_cp,    0xD1 },  // cp a, ([short.w],y)   ; 91 D1 XX
  { ST7_sbc,   0xD2 },  // sbc a, ([short.w],y)  ; 91 D2 XX
  { ST7_cp,    0xD3 },  // cp y, ([short.w],y)   ; 91 D3 XX
  { ST7_and,   0xD4 },  // and a, ([short.w],y)  ; 91 D4 XX
  { ST7_bcp,   0xD5 },  // bcp a, ([short.w],y)  ; 91 D5 XX
  { ST7_ld,    0xD6 },  // ld a, ([short.w],y)   ; 91 D6 XX
  { ST7_ld,    0xD7 },  // ld ([short.w],y), a   ; 91 D7 XX
  { ST7_xor,   0xD8 },  // xor a, ([short.w],y)  ; 91 D8 XX
  { ST7_adc,   0xD9 },  // adc a, ([short.w],y)  ; 91 D9 XX
  { ST7_or,    0xDA },  // or a, ([short.w],y)   ; 91 DA XX
  { ST7_add,   0xDB },  // add a, ([short.w],y)  ; 91 DB XX
  { ST7_jp,    0xDC },  // jp ([short.w],y)      ; 91 DC XX
  { ST7_call,  0xDD },  // call ([short.w],y)    ; 91 DD XX
  { ST7_ld,    0xDE },  // ld y, ([short.w],y)   ; 91 DE XX
  { ST7_ld,    0xDF },  // ld ([short.w],y), y   ; 91 DF XX
  { ST7_sub,   0xE0 },  // sub a, ([short],y)    ; 91 E0 XX
  { ST7_cp,    0xE1 },  // cp a, ([short],y)     ; 91 E1 XX
  { ST7_sbc,   0xE2 },  // sbc a, ([short],y)    ; 91 E2 XX
  { ST7_cp,    0xE3 },  // cp y, ([short],y)     ; 91 E3 XX
  { ST7_and,   0xE4 },  // and a, ([short],y)    ; 91 E4 XX
  { ST7_bcp,   0xE5 },  // bcp a, ([short],y)    ; 91 E5 XX
  { ST7_ld,    0xE6 },  // ld a, ([short],y)     ; 91 E6 XX
  { ST7_ld,    0xE7 },  // ld ([short],y), a     ; 91 E7 XX
  { ST7_xor,   0xE8 },  // xor a, ([short],y)    ; 91 E8 XX
  { ST7_adc,   0xE9 },  // adc a, ([short],y)    ; 91 E9 XX
  { ST7_or,    0xEA },  // or a, ([short],y)     ; 91 EA XX
  { ST7_add,   0xEB },  // add a, ([short],y)    ; 91 EB XX
  { ST7_jp,    0xEC },  // jp ([short],y)        ; 91 EC XX
  { ST7_call,  0xED },  // call ([short],y)      ; 91 ED XX
  { ST7_ld,    0xEE },  // ld y, ([short],y)     ; 91 EE XX
  { ST7_ld,    0xEF },  // ld ([short],y), y     ; 91 EF XX
};

static const opcode_t pre92[] =
{
  { ST7_btjt,  0x00 },  // btjt [short], #0, br  ; 92 00 XX XX
  { ST7_btjf,  0x01 },  // btjf [short], #0, br  ; 92 01 XX XX
  { ST7_btjt,  0x02 },  // btjt [short], #1, br  ; 92 02 XX XX
  { ST7_btjf,  0x03 },  // btjf [short], #1, br  ; 92 03 XX XX
  { ST7_btjt,  0x04 },  // btjt [short], #2, br  ; 92 04 XX XX
  { ST7_btjf,  0x05 },  // btjf [short], #2, br  ; 92 05 XX XX
  { ST7_btjt,  0x06 },  // btjt [short], #3, br  ; 92 06 XX XX
  { ST7_btjf,  0x07 },  // btjf [short], #3, br  ; 92 07 XX XX
  { ST7_btjt,  0x08 },  // btjt [short], #4, br  ; 92 08 XX XX
  { ST7_btjf,  0x09 },  // btjf [short], #4, br  ; 92 09 XX XX
  { ST7_btjt,  0x0A },  // btjt [short], #5, br  ; 92 0A XX XX
  { ST7_btjf,  0x0B },  // btjf [short], #5, br  ; 92 0B XX XX
  { ST7_btjt,  0x0C },  // btjt [short], #6, br  ; 92 0C XX XX
  { ST7_btjf,  0x0D },  // btjf [short], #6, br  ; 92 0D XX XX
  { ST7_btjt,  0x0E },  // btjt [short], #7, br  ; 92 0E XX XX
  { ST7_btjf,  0x0F },  // btjf [short], #7, br  ; 92 0F XX XX
  { ST7_bset,  0x10 },  // bset [short], #0      ; 92 10 XX
  { ST7_bres,  0x11 },  // bres [short], #0      ; 92 11 XX
  { ST7_bset,  0x12 },  // bset [short], #1      ; 92 12 XX
  { ST7_bres,  0x13 },  // bres [short], #1      ; 92 13 XX
  { ST7_bset,  0x14 },  // bset [short], #2      ; 92 14 XX
  { ST7_bres,  0x15 },  // bres [short], #2      ; 92 15 XX
  { ST7_bset,  0x16 },  // bset [short], #3      ; 92 16 XX
  { ST7_bres,  0x17 },  // bres [short], #3      ; 92 17 XX
  { ST7_bset,  0x18 },  // bset [short], #4      ; 92 18 XX
  { ST7_bres,  0x19 },  // bres [short], #4      ; 92 19 XX
  { ST7_bset,  0x1A },  // bset [short], #5      ; 92 1A XX
  { ST7_bres,  0x1B },  // bres [short], #5      ; 92 1B XX
  { ST7_bset,  0x1C },  // bset [short], #6      ; 92 1C XX
  { ST7_bres,  0x1D },  // bres [short], #6      ; 92 1D XX
  { ST7_bset,  0x1E },  // bset [short], #7      ; 92 1E XX
  { ST7_bres,  0x1F },  // bres [short], #7      ; 92 1F XX
  { ST7_jra,   0x20 },  // jra   [rel8]          ; 92 20 XX
  { ST7_jrf,   0x21 },  // jrf   [rel8]          ; 92 21 XX
  { ST7_jrugt, 0x22 },  // jrugt [rel8]          ; 92 22 XX
  { ST7_jrule, 0x23 },  // jrule [rel8]          ; 92 23 XX
  { ST7_jrnc,  0x24 },  // jrnc  [rel8]          ; 92 24 XX
  { ST7_jrc,   0x25 },  // jrc   [rel8]          ; 92 25 XX
  { ST7_jrne,  0x26 },  // jrne  [rel8]          ; 92 26 XX
  { ST7_jreq,  0x27 },  // jreq  [rel8]          ; 92 27 XX
  { ST7_jrnh,  0x28 },  // jrnh  [rel8]          ; 92 28 XX
  { ST7_jrh,   0x29 },  // jrh   [rel8]          ; 92 29 XX
  { ST7_jrpl,  0x2A },  // jrpl  [rel8]          ; 92 2A XX
  { ST7_jrmi,  0x2B },  // jrmi  [rel8]          ; 92 2B XX
  { ST7_jrnm,  0x2C },  // jrnm  [rel8]          ; 92 2C XX
  { ST7_jrm,   0x2D },  // jrm   [rel8]          ; 92 2D XX
  { ST7_jril,  0x2E },  // jril  [rel8]          ; 92 2E XX
  { ST7_jrih,  0x2F },  // jrih  [rel8]          ; 92 2F XX
  { ST7_neg,   0x30 },  // neg [short]           ; 92 30 XX
  { ST7_cpl,   0x33 },  // cpl [short]           ; 92 33 XX
  { ST7_srl,   0x34 },  // srl [short]           ; 92 34 XX
  { ST7_rrc,   0x36 },  // rrc [short]           ; 92 36 XX
  { ST7_sra,   0x37 },  // sra [short]           ; 92 37 XX
//  { ST7_sla,   0x38 },  // sla [short]           ; 92 38 XX
  { ST7_sll,   0x38 },  // sll [short]           ; 92 38 XX
  { ST7_rlc,   0x39 },  // rlc [short]           ; 92 39 XX
  { ST7_dec,   0x3A },  // dec [short]           ; 92 3A XX
  { ST7_inc,   0x3C },  // inc [short]           ; 92 3C XX
  { ST7_tnz,   0x3D },  // tnz [short]           ; 92 3D XX
  { ST7_swap,  0x3E },  // swap [short]          ; 92 3E XX
  { ST7_clr,   0x3F },  // clr [short]           ; 92 3F XX
  { ST7_neg,   0x60 },  // neg ([short],x)       ; 92 60 XX
  { ST7_cpl,   0x63 },  // cpl ([short],x)       ; 92 63 XX
  { ST7_srl,   0x64 },  // srl ([short],x)       ; 92 64 XX
  { ST7_rrc,   0x66 },  // rrc ([short],x)       ; 92 66 XX
  { ST7_sra,   0x67 },  // sra ([short],x)       ; 92 67 XX
//  { ST7_sla,   0x68 },  // sla ([short],x)       ; 92 68 XX
  { ST7_sll,   0x68 },  // sll ([short],x)       ; 92 68 XX
  { ST7_rlc,   0x69 },  // rlc ([short],x)       ; 92 69 XX
  { ST7_dec,   0x6A },  // dec ([short],x)       ; 92 6A XX
  { ST7_inc,   0x6C },  // inc ([short],x)       ; 92 6C XX
  { ST7_tnz,   0x6D },  // tnz ([short],x)       ; 92 6D XX
  { ST7_swap,  0x6E },  // swap ([short],x)      ; 92 6E XX
  { ST7_clr,   0x6F },  // clr ([short],x)       ; 92 6F XX
  { ST7_callr, 0xAD },  // callr [short]         ; 92 AD XX
  { ST7_sub,   0xB0 },  // sub a, [short]        ; 92 B0 XX
  { ST7_cp,    0xB1 },  // cp a, [short]         ; 92 B1 XX
  { ST7_sbc,   0xB2 },  // sbc a, [short]        ; 92 B2 XX
  { ST7_cp,    0xB3 },  // cp x, [short]         ; 92 B3 XX
  { ST7_and,   0xB4 },  // and a, [short]        ; 92 B4 XX
  { ST7_bcp,   0xB5 },  // bcp a, [short]        ; 92 B5 XX
  { ST7_ld,    0xB6 },  // ld a, [short]         ; 92 B6 XX
  { ST7_ld,    0xB7 },  // ld [short], a         ; 92 B7 XX
  { ST7_xor,   0xB8 },  // xor a, [short]        ; 92 B8 XX
  { ST7_adc,   0xB9 },  // adc a, [short]        ; 92 B9 XX
  { ST7_or,    0xBA },  // or a, [short]         ; 92 BA XX
  { ST7_add,   0xBB },  // add a, [short]        ; 92 BB XX
  { ST7_jp,    0xBC },  // jp [short]            ; 92 BC XX
  { ST7_call,  0xBD },  // call [short]          ; 92 BD XX
  { ST7_ld,    0xBE },  // ld x, [short]         ; 92 BE XX
  { ST7_ld,    0xBF },  // ld [short], x         ; 92 BF XX
  { ST7_sub,   0xC0 },  // sub a, [short.w]      ; 92 C0 XX
  { ST7_cp,    0xC1 },  // cp a, [short.w]       ; 92 C1 XX
  { ST7_sbc,   0xC2 },  // sbc a, [short.w]      ; 92 C2 XX
  { ST7_cp,    0xC3 },  // cp x, [short.w]       ; 92 C3 XX
  { ST7_and,   0xC4 },  // and a, [short.w]      ; 92 C4 XX
  { ST7_bcp,   0xC5 },  // bcp a, [short.w]      ; 92 C5 XX
  { ST7_ld,    0xC6 },  // ld a, [short.w]       ; 92 C6 XX
  { ST7_ld,    0xC7 },  // ld [short.w], a       ; 92 C7 XX
  { ST7_xor,   0xC8 },  // xor a, [short.w]      ; 92 C8 XX
  { ST7_adc,   0xC9 },  // adc a, [short.w]      ; 92 C9 XX
  { ST7_or,    0xCA },  // or a, [short.w]       ; 92 CA XX
  { ST7_add,   0xCB },  // add a, [short.w]      ; 92 CB XX
  { ST7_jp,    0xCC },  // jp [short.w]          ; 92 CC XX
  { ST7_call,  0xCD },  // call [short.w]        ; 92 CD XX
  { ST7_ld,    0xCE },  // ld x, [short.w]       ; 92 CE XX
  { ST7_ld,    0xCF },  // ld [short.w], x       ; 92 CF XX
  { ST7_sub,   0xD0 },  // sub a, ([short.w],x)  ; 92 D0 XX
  { ST7_cp,    0xD1 },  // cp a, ([short.w],x)   ; 92 D1 XX
  { ST7_sbc,   0xD2 },  // sbc a, ([short.w],x)  ; 92 D2 XX
  { ST7_cp,    0xD3 },  // cp x, ([short.w],x)   ; 92 D3 XX
  { ST7_and,   0xD4 },  // and a, ([short.w],x)  ; 92 D4 XX
  { ST7_bcp,   0xD5 },  // bcp a, ([short.w],x)  ; 92 D5 XX
  { ST7_ld,    0xD6 },  // ld a, ([short.w],x)   ; 92 D6 XX
  { ST7_ld,    0xD7 },  // ld ([short.w],x), a   ; 92 D7 XX
  { ST7_xor,   0xD8 },  // xor a, ([short.w],x)  ; 92 D8 XX
  { ST7_adc,   0xD9 },  // adc a, ([short.w],x)  ; 92 D9 XX
  { ST7_or,    0xDA },  // or a, ([short.w],x)   ; 92 DA XX
  { ST7_add,   0xDB },  // add a, ([short.w],x)  ; 92 DB XX
  { ST7_jp,    0xDC },  // jp ([short.w],x)      ; 92 DC XX
  { ST7_call,  0xDD },  // call ([short.w],x)    ; 92 DD XX
  { ST7_ld,    0xDE },  // ld x, ([short.w],x)   ; 92 DE XX
  { ST7_ld,    0xDF },  // ld ([short.w],x), x   ; 92 DF XX
  { ST7_sub,   0xE0 },  // sub a, ([short],x)    ; 92 E0 XX
  { ST7_cp,    0xE1 },  // cp a, ([short],x)     ; 92 E1 XX
  { ST7_sbc,   0xE2 },  // sbc a, ([short],x)    ; 92 E2 XX
  { ST7_cp,    0xE3 },  // cp x, ([short],x)     ; 92 E3 XX
  { ST7_and,   0xE4 },  // and a, ([short],x)    ; 92 E4 XX
  { ST7_bcp,   0xE5 },  // bcp a, ([short],x)    ; 92 E5 XX
  { ST7_ld,    0xE6 },  // ld a, ([short],x)     ; 92 E6 XX
  { ST7_ld,    0xE7 },  // ld ([short],x), a     ; 92 E7 XX
  { ST7_xor,   0xE8 },  // xor a, ([short],x)    ; 92 E8 XX
  { ST7_adc,   0xE9 },  // adc a, ([short],x)    ; 92 E9 XX
  { ST7_or,    0xEA },  // or a, ([short],x)     ; 92 EA XX
  { ST7_add,   0xEB },  // add a, ([short],x)    ; 92 EB XX
  { ST7_jp,    0xEC },  // jp ([short],x)        ; 92 EC XX
  { ST7_call,  0xED },  // call ([short],x)      ; 92 ED XX
  { ST7_ld,    0xEE },  // ld x, ([short],x)     ; 92 EE XX
  { ST7_ld,    0xEF },  // ld ([short],x), x     ; 92 EF XX
};

//--------------------------------------------------------------------------
static int NT_CDECL cmp_opcodes(const void *a, const void *b)
{
  const opcode_t *x = (const opcode_t *)a;
  const opcode_t *y = (const opcode_t *)b;
  return x->opcode - y->opcode;
}

static uchar find_opcode(uchar code, const opcode_t *table, size_t size)
{
  opcode_t key;
  key.opcode = code;
  opcode_t *op = (opcode_t *)bsearch(&key, table, size, sizeof(opcode_t), cmp_opcodes);
  return op ? op->itype : ST7_null;
}

//--------------------------------------------------------------------------
inline void opmem(insn_t &insn, op_t &x, char dtype)
{
  x.type = o_mem;
  x.dtype = dtype;
  x.offb = (uchar)insn.size;
  x.addr = insn.get_next_byte();
}

inline void opimm(op_t &x, uint32 value, char dtype)
{
  x.type = o_imm;
  x.dtype = dtype;
  x.value = value;
}

inline void oprel(insn_t &insn, op_t &x)
{
  x.type = o_near;
  x.dtype = dt_code;
  x.offb = (uchar)insn.size;
  int32 disp = char(insn.get_next_byte());
  x.addr = insn.ip + insn.size + disp;
}

inline void opreg(op_t &x, uchar reg)
{
  x.type = o_reg;
  x.dtype = dt_byte;
  x.reg = reg;
}

inline void opdsp(insn_t &insn, op_t &x, uchar reg, char dtype)
{
  x.type = o_displ;
  x.dtype = dtype;
  x.reg  = reg;
  x.offb = (uchar)insn.size;
  x.addr = insn.get_next_byte();
}

inline void oplng(insn_t &insn, op_t &x)
{
  opmem(insn, x, dt_word);
  if ( (insn.auxpref & aux_indir) == 0 )
  {
    insn.auxpref |= aux_16;
    x.dtype = dt_byte;
    x.addr <<= 8;
    x.addr |= insn.get_next_byte();
  }
  else
  {
    insn.auxpref |= aux_long;
  }
}

enum ndx_t { ndx_short, ndx_long, ndx_none };

static void opndx(insn_t &insn, op_t &x, int type, uchar index)
{
  switch ( type )
  {
    case ndx_short:
      opmem(insn, x, dt_byte);
      break;
    case ndx_long:
      oplng(insn, x);
      break;
    case ndx_none:
      x.type = o_phrase;
      x.dtype = dt_byte;
      break;
  }
  if ( index )
  {
    if ( type != ndx_none && (insn.auxpref & aux_indir) == 0 )
      x.type = o_displ;
    insn.auxpref |= aux_index;
    x.reg = index;
  }
}

//--------------------------------------------------------------------------
int idaapi st7_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  uchar code = insn.get_next_byte();
  bool y = false;
  switch ( code )
  {
    case 0x90:
      y = true;
      code = insn.get_next_byte();
      insn.itype = find_opcode(code, pre90, qnumber(pre90));
      break;
    case 0x91:
      y = true;
      insn.auxpref |= aux_indir;
      code = insn.get_next_byte();
      insn.itype = find_opcode(code, pre91, qnumber(pre91));
      break;
    case 0x92:
      insn.auxpref |= aux_indir;
      code = insn.get_next_byte();
      insn.itype = find_opcode(code, pre92, qnumber(pre92));
      break;
    default:
      insn.itype = primary[code];
      break;
  }
  if ( insn.itype == ST7_null )
    return 0;
  regnum_t xy = y ? Y : X;
  uchar index;
  int ndx;
  switch ( code >> 4 )
  {
    case 0x0:
//        btjt short, #p, brl   ; 5 3    0n XX XX (n=00+2*p)
//        btjt [short], #p, br  ; 7 4 92 0n XX XX (n=00+2*p)
//        btjf short, #p, brl   ; 5 3    0n XX XX (n=01+2*p)
//        btjf [short], #p, br  ; 7 4 92 0n XX XX (n=01+2*p)
      opmem(insn, insn.Op1, dt_byte);
      opimm(insn.Op2, (code>>1) & 7, dt_byte);
      oprel(insn, insn.Op3);
      break;

    case 0x1:
//        bset short, #p        ; 5 2    1n XX    (n=10+2*p)
//        bset [short], #p      ; 7 3 92 1n XX    (n=10+2*p)
//        bres short, #p        ; 5 2    1n XX    (n=11+2*p)
//        bres [short], #p      ; 7 3 92 1n XX    (n=11+2*p)
      opmem(insn, insn.Op1, dt_byte);
      opimm(insn.Op2, (code>>1) & 7, dt_byte);
      break;

    case 0x2:
//        jra   rel             ; 3 2    20 XX
//        jrt   rel             ; 3 2    20 XX
//        jra   [rel8]          ; 5 3 92 20 XX
//        jrt   [rel8]          ; 5 3 92 20 XX
//        jrf   rel             ; 3 2    21 XX
//        jrf   [rel8]          ; 5 3 92 21 XX
//        jrugt rel             ; 3 2    22 XX
//        jrugt [rel8]          ; 5 3 92 22 XX
//        jrule rel             ; 3 2    23 XX
//        jrule [rel8]          ; 5 3 92 23 XX
//        jrnc  rel             ; 3 2    24 XX
//        jruge rel             ; 3 2    24 XX
//        jrnc  [rel8]          ; 5 3 92 24 XX
//        jruge [rel8]          ; 5 3 92 24 XX
//        jrc   rel             ; 3 2    25 XX
//        jrult rel             ; 3 2    25 XX
//        jrc   [rel8]          ; 5 3 92 25 XX
//        jrult [rel8]          ; 5 3 92 25 XX
//        jrne  rel             ; 3 2    26 XX
//        jrne  [rel8]          ; 5 3 92 26 XX
//        jreq  rel             ; 3 2    27 XX
//        jreq  [rel8]          ; 5 3 92 27 XX
//        jrnh  rel             ; 3 2    28 XX
//        jrnh  [rel8]          ; 5 3 92 28 XX
//        jrh   rel             ; 3 2    29 XX
//        jrh   [rel8]          ; 5 3 92 29 XX
//        jrpl  rel             ; 3 2    2A XX
//        jrpl  [rel8]          ; 5 3 92 2A XX
//        jrmi  rel             ; 3 2    2B XX
//        jrmi  [rel8]          ; 5 3 92 2B XX
//        jrnm  rel             ; 3 2    2C XX
//        jrnm  [rel8]          ; 5 3 92 2C XX
//        jrm   rel             ; 3 2    2D XX
//        jrm   [rel8]          ; 5 3 92 2D XX
//        jril  rel             ; 3 2    2E XX
//        jril  [rel8]          ; 5 3 92 2E XX
//        jrih  rel             ; 3 2    2F XX
//        jrih  [rel8]          ; 5 3 92 2F XX
REL:
      if ( insn.auxpref & aux_indir )
        opmem(insn, insn.Op1, dt_word);
      else
        oprel(insn, insn.Op1);
      break;

    case 0x3:
//        neg short             ; 5 2    30 XX
//        neg [short]           ; 7 3 92 30 XX
//        cpl short             ; 5 2    33 XX
//        cpl [short]           ; 7 3 92 33 XX
//        srl short             ; 5 2    34 XX
//        srl [short]           ; 7 3 92 34 XX
//        rrc short             ; 5 2    36 XX
//        rrc [short]           ; 7 3 92 36 XX
//        sra short             ; 5 2    37 XX
//        sra [short]           ; 7 3 92 37 XX
//        sla short             ; 5 2    38 XX
//        sll short             ; 5 2    38 XX
//        sla [short]           ; 7 3 92 38 XX
//        sll [short]           ; 7 3 92 38 XX
//        rlc short             ; 5 2    39 XX
//        rlc [short]           ; 7 3 92 39 XX
//        dec short             ; 5 2    3A XX
//        dec [short]           ; 7 3 92 3A XX
//        inc short             ; 5 2    3C XX
//        inc [short]           ; 7 3 92 3C XX
//        tnz short             ; 4 2    3D XX
//        tnz [short]           ; 6 3 92 3D XX
//        swap short            ; 5 2    3E XX
//        swap [short]          ; 7 3 92 3E XX
//        clr short             ; 5 2    3F XX
//        clr [short]           ; 7 3 92 3F XX
      opmem(insn, insn.Op1, dt_byte);
      break;

    case 0x4:
//        neg a                 ; 3 1    40
//        mul x, a              ;11 1    42
//        mul y, a              ;12 2 90 42
//        cpl a                 ; 3 1    43
//        srl a                 ; 3 1    44
//        rrc a                 ; 3 1    46
//        sra a                 ; 3 1    47
//        sla a                 ; 3 1    48
//        sll a                 ; 3 1    48
//        rlc a                 ; 3 1    49
//        dec a                 ; 3 1    4A
//        inc a                 ; 3 1    4C
//        tnz a                 ; 3 1    4D
//        swap a                ; 3 1    4E
//        clr a                 ; 3 1    4F
      if ( insn.itype == ST7_mul )
      {
        opreg(insn.Op1, xy);
        opreg(insn.Op2, A);
      }
      else
      {
        opreg(insn.Op1, A);
      }
      break;

    case 0x5:
//        neg x                 ; 3 1    50
//        neg y                 ; 4 2 90 50
//        cpl x                 ; 3 1    53
//        cpl y                 ; 4 2 90 53
//        srl x                 ; 3 1    54
//        srl y                 ; 4 2 90 54
//        rrc x                 ; 3 1    56
//        rrc y                 ; 4 2 90 56
//        sra x                 ; 3 1    57
//        sra y                 ; 4 2 90 57
//        sla x                 ; 3 1    58
//        sll x                 ; 3 1    58
//        sla y                 ; 4 2 90 58
//        sll y                 ; 4 2 90 58
//        rlc x                 ; 3 1    59
//        rlc y                 ; 4 2 90 59
//        dec x                 ; 3 1    5A
//        dec y                 ; 4 2 90 5A
//        inc x                 ; 3 1    5C
//        inc y                 ; 4 2 90 5C
//        tnz x                 ; 3 1    5D
//        tnz y                 ; 4 2 90 5D
//        swap x                ; 3 1    5E
//        swap y                ; 4 2 90 5E
//        clr x                 ; 3 1    5F
//        clr y                 ; 4 2 90 5F
      opreg(insn.Op1, xy);
      break;

    case 0x6:
//        neg (short,x)         ; 6 2    60 XX
//        neg (short,y)         ; 7 3 90 60 XX
//        neg ([short],y)       ; 8 3 91 60 XX
//        neg ([short],x)       ; 8 3 92 60 XX
//        cpl (short,x)         ; 6 2    63 XX
//        cpl (short,y)         ; 7 3 90 63 XX
//        cpl ([short],y)       ; 8 3 91 63 XX
//        cpl ([short],x)       ; 8 3 92 63 XX
//        srl (short,x)         ; 6 2    64 XX
//        srl (short,y)         ; 7 3 90 64 XX
//        srl ([short],y)       ; 8 3 91 64 XX
//        srl ([short],x)       ; 8 3 92 64 XX
//        rrc (short,x)         ; 6 2    66 XX
//        rrc (short,y)         ; 7 3 90 66 XX
//        rrc ([short],y)       ; 8 3 91 66 XX
//        rrc ([short],x)       ; 8 3 92 66 XX
//        sra (short,x)         ; 6 2    67 XX
//        sra (short,y)         ; 7 3 90 67 XX
//        sra ([short],y)       ; 8 3 91 67 XX
//        sra ([short],x)       ; 8 3 92 67 XX
//        sla (short,x)         ; 6 2    68 XX
//        sll (short,x)         ; 6 2    68 XX
//        sla (short,y)         ; 7 3 90 68 XX
//        sll (short,y)         ; 7 3 90 68 XX
//        sla ([short],y)       ; 8 3 91 68 XX
//        sll ([short],y)       ; 8 3 91 68 XX
//        sla ([short],x)       ; 8 3 92 68 XX
//        sll ([short],x)       ; 8 3 92 68 XX
//        rlc (short,x)         ; 6 2    69 XX
//        rlc (short,y)         ; 7 3 90 69 XX
//        rlc ([short],y)       ; 8 3 91 69 XX
//        rlc ([short],x)       ; 8 3 92 69 XX
//        dec (short,x)         ; 6 2    6A XX
//        dec (short,y)         ; 7 3 90 6A XX
//        dec ([short],y)       ; 8 3 91 6A XX
//        dec ([short],x)       ; 8 3 92 6A XX
//        inc (short,x)         ; 6 2    6C XX
//        inc (short,y)         ; 7 3 90 6C XX
//        inc ([short],y)       ; 8 3 91 6C XX
//        inc ([short],x)       ; 8 3 92 6C XX
//        tnz (short,x)         ; 5 2    6D XX
//        tnz (short,y)         ; 6 3 90 6D XX
//        tnz ([short],y)       ; 7 3 91 6D XX
//        tnz ([short],x)       ; 7 3 92 6D XX
//        swap (short,x)        ; 6 2    6E XX
//        swap (short,y)        ; 7 3 90 6E XX
//        swap ([short],y)      ; 8 3 91 6E XX
//        swap ([short],x)      ; 8 3 92 6E XX
//        clr (short,x)         ; 6 2    6F XX
//        clr (short,y)         ; 7 3 90 6F XX
//        clr ([short],y)       ; 8 3 91 6F XX
//        clr ([short],x)       ; 8 3 92 6F XX
// o_displ Short     Direct   Indexed  ld A,($10,X)             00..1FE                + 1
// o_mem   Short     Indirect Indexed  ld A,([$10],X)           00..1FE    00..FF byte + 2
      if ( insn.auxpref & aux_indir )
      {
        opmem(insn, insn.Op1, dt_byte);
        insn.auxpref |= aux_index;
        insn.Op1.reg = xy;
      }
      else
      {
        opdsp(insn, insn.Op1, xy, dt_byte);
      }
      break;

    case 0x7:
//        neg (x)               ; 5 1    70
//        neg (y)               ; 6 2 90 70
//        cpl (x)               ; 5 1    73
//        cpl (y)               ; 6 2 90 73
//        srl (x)               ; 5 1    74
//        srl (y)               ; 6 2 90 74
//        rrc (x)               ; 5 1    76
//        rrc (y)               ; 6 2 90 76
//        sra (x)               ; 5 1    77
//        sra (y)               ; 6 2 90 77
//        sla (x)               ; 5 1    78
//        sll (x)               ; 5 1    78
//        sla (y)               ; 6 2 90 78
//        sll (y)               ; 6 2 90 78
//        rlc (x)               ; 5 1    79
//        rlc (y)               ; 6 2 90 79
//        dec (x)               ; 5 1    7A
//        dec (y)               ; 6 2 90 7A
//        inc (x)               ; 5 1    7C
//        inc (y)               ; 6 2 90 7C
//        tnz (x)               ; 4 1    7D
//        tnz (y)               ; 5 2 90 7D
//        swap (x)              ; 5 1    7E
//        swap (y)              ; 6 2 90 7E
//        clr (x)               ; 5 1    7F
//        clr (y)               ; 6 2 90 7F
      insn.Op1.type = o_phrase;
      insn.Op1.dtype = dt_byte;
      insn.Op1.reg = xy;
      break;

    case 0x8:
//        iret                  ; 9 1    80
//        ret                   ; 6 1    81
//        trap                  ; 1 1    83
//        pop a                 ; 4 1    84
//        pop x                 ; 4 1    85
//        pop y                 ; 5 2 90 85
//        pop cc                ; 4 1    86
//        push a                ; 3 1    88
//        push x                ; 3 1    89
//        push y                ; 4 2 90 89
//        push cc               ; 3 1    8A
//        halt                  ; 2 1    8E
//        wfi                   ; 2 1    8F
      if ( insn.itype == ST7_pop || insn.itype == ST7_push )
      {
        uchar c = (code - 0x84) & 3;
        if ( c == 2 )
          c = CC;
        else if ( c == 1 )
          c = xy;
        opreg(insn.Op1, c);
      }
      break;

    case 0x9:
      switch ( code )
      {
        case 0x93:
//        ld x, y               ; 2 1    93
//        ld y, x               ; 3 2 90 93
          opreg(insn.Op1, y ? Y : X);
          opreg(insn.Op2, y ? X : Y);
          break;
        case 0x94:
//        ld s, x               ; 2 1    94
//        ld s, y               ; 3 2 90 94
          opreg(insn.Op1, S);
          opreg(insn.Op2, xy);
          break;
        case 0x95:
//        ld s, a               ; 2 1    95
          opreg(insn.Op1, S);
          opreg(insn.Op2, A);
          break;
        case 0x96:
//        ld x, s               ; 2 1    96
//        ld y, s               ; 3 2 90 96
          opreg(insn.Op1, xy);
          opreg(insn.Op2, S);
          break;
        case 0x97:
//        ld x, a               ; 2 1    97
//        ld y, a               ; 3 2 90 97
          opreg(insn.Op1, xy);
          opreg(insn.Op2, A);
          break;
        default:
//        rcf                   ; 2 1    98
//        scf                   ; 2 1    99
//        rim                   ; 2 1    9A
//        sim                   ; 2 1    9B
//        rsp                   ; 2 1    9C
//        nop                   ; 2 1    9D
          break;
        case 0x9E:
//        ld a, s               ; 2 1    9E
          opreg(insn.Op1, A);
          opreg(insn.Op2, S);
          break;
        case 0x9F:
//        ld a, x               ; 2 1    9F
//        ld a, y               ; 3 2 90 9F
          opreg(insn.Op1, A);
          opreg(insn.Op2, xy);
          break;
      }
      break;

    case 0xA:
//        sub a, #byte          ; 2 2    A0 XX
//        cp a, #byte           ; 2 2    A1 XX
//        sbc a, #byte          ; 2 2    A2 XX
//        cp x, #byte           ; 2 2    A3 XX
//        cp y, #byte           ; 3 3 90 A3 XX
//        and a, #byte          ; 2 2    A4 XX
//        bcp a, #byte          ; 2 2    A5 XX
//        ld a, #byte           ; 2 2    A6 XX
//        xor a, #byte          ; 2 2    A8 XX
//        adc a, #byte          ; 2 2    A9 XX
//        or a, #byte           ; 2 2    AA XX
//        add a, #byte          ; 2 2    AB XX
//        callr callrl          ; 6 2    AD XX
//        callr [short]         ; 8 3 92 AD XX
//        ld x, #byte           ; 2 2    AE XX
//        ld y, #byte           ; 3 3 90 AE XX
      if ( insn.itype == ST7_callr )
        goto REL;
      opreg(insn.Op1, (code == 0xA3 || code == 0xAE) ? xy : A);
      opimm(insn.Op2, insn.get_next_byte(), dt_byte);
      break;

    case 0xB:
      switch ( code )
      {
        case 0xB0:
        case 0xB1:
        case 0xB2:
        case 0xB4:
        case 0xB5:
        case 0xB6:
        case 0xB8:
        case 0xB9:
        case 0xBA:
        case 0xBB:
//        sub a, short          ; 3 2    B0 XX
//        sub a, [short]        ; 5 3 92 B0 XX
//        cp a, short           ; 3 2    B1 XX
//        cp a, [short]         ; 5 3 92 B1 XX
//        sbc a, short          ; 3 2    B2 XX
//        sbc a, [short]        ; 5 3 92 B2 XX
//        and a, short          ; 3 2    B4 XX
//        and a, [short]        ; 5 3 92 B4 XX
//        bcp a, short          ; 3 2    B5 XX
//        bcp a, [short]        ; 5 3 92 B5 XX
//        ld a, short           ; 3 2    B6 XX
//        ld a, [short]         ; 5 3 92 B6 XX
//        xor a, short          ; 3 2    B8 XX
//        xor a, [short]        ; 5 3 92 B8 XX
//        adc a, short          ; 3 2    B9 XX
//        adc a, [short]        ; 5 3 92 B9 XX
//        or a, short           ; 3 2    BA XX
//        or a, [short]         ; 5 3 92 BA XX
//        add a, short          ; 3 2    BB XX
//        add a, [short]        ; 5 3 92 BB XX
          opreg(insn.Op1, A);
          opmem(insn, insn.Op2, dt_byte);
          break;
        case 0xB3:
        case 0xBE:
//        cp x, short           ; 3 2    B3 XX
//        cp y, short           ; 4 3 90 B3 XX
//        cp y, [short]         ; 5 3 91 B3 XX
//        cp x, [short]         ; 5 3 92 B3 XX
//        ld x, short           ; 3 2    BE XX
//        ld y, short           ; 4 3 90 BE XX
//        ld y, [short]         ; 5 3 91 BE XX
//        ld x, [short]         ; 5 3 92 BE XX
          opreg(insn.Op1, xy);
          opmem(insn, insn.Op2, dt_byte);
          break;
        case 0xB7:
//        ld short, a           ; 4 2    B7 XX
//        ld [short], a         ; 6 3 92 B7 XX
          opmem(insn, insn.Op1, dt_byte);
          opreg(insn.Op2, A);
          break;
        case 0xBC:
        case 0xBD:
//        jp short              ; 2 2    BC XX
//        jp [short]            ; 4 3 92 BC XX
//        call short            ; 5 2    BD XX
//        call [short]          ; 7 3 92 BD XX
          opmem(insn, insn.Op1, dt_word);
          if ( (insn.auxpref & aux_indir) == 0 )
          {
            insn.Op1.type = o_near;
            insn.Op1.dtype = dt_code;
          }
          break;
        case 0xBF:
//        ld short, x           ; 4 2    BF XX
//        ld short, y           ; 5 3 90 BF XX
//        ld [short], y         ; 6 3 91 BF XX
//        ld [short], x         ; 6 3 92 BF XX
          opmem(insn, insn.Op1, dt_byte);
          opreg(insn.Op2, xy);
          break;
      }
      break;

    case 0xC:
      index = 0;
      ndx = ndx_long;
      goto COMMON;
//        sub a, long           ; 4 3    C0 MS LS
//        sub a, [short.w]      ; 6 3 92 C0 XX
//        cp a, long            ; 4 3    C1 MS LS
//        cp a, [short.w]       ; 6 3 92 C1 XX
//        sbc a, long           ; 4 3    C2 MS LS
//        sbc a, [short.w]      ; 6 3 92 C2 XX
//        and a, long           ; 4 3    C4 MS LS
//        and a, [short.w]      ; 6 3 92 C4 XX
//        bcp a, long           ; 4 3    C5 MS LS
//        bcp a, [short.w]      ; 6 3 92 C5 XX
//        ld a, long            ; 4 3    C6 MS LS
//        ld a, [short.w]       ; 6 3 92 C6 XX
//        xor a, long           ; 4 3    C8 MS LS
//        xor a, [short.w]      ; 6 3 92 C8 XX
//        adc a, long           ; 4 3    C9 MS LS
//        adc a, [short.w]      ; 6 3 92 C9 XX
//        or a, long            ; 4 3    CA MS LS
//        or a, [short.w]       ; 6 3 92 CA XX
//        add a, long           ; 4 3    CB MS LS
//        add a, [short.w]      ; 6 3 92 CB XX
//        cp x, long            ; 4 3    C3 MS LS
//        cp y, long            ; 5 4 90 C3 MS LS
//        cp y, [short.w]       ; 6 3 91 C3 XX
//        cp x, [short.w]       ; 6 3 92 C3 XX
//        ld x, long            ; 4 3    CE MS LS
//        ld y, long            ; 5 4 90 CE MS LS
//        ld y, [short.w]       ; 6 3 91 CE XX
//        ld x, [short.w]       ; 6 3 92 CE XX
//        ld long, a            ; 5 3    C7 MS LS
//        ld [short.w], a       ; 7 3 92 C7 XX
//        jp long               ; 3 3    CC MS LS
//        jp [short.w]          ; 5 3 92 CC XX
//        call long             ; 6 3    CD MS LS
//        call [short.w]        ; 8 3 92 CD XX
//        ld long, x            ; 5 3    CF MS LS
//        ld long, y            ; 6 4 90 CF MS LS
//        ld [short.w], y       ; 7 3 91 CF XX
//        ld [short.w], x       ; 7 3 92 CF XX

    case 0xD:
      index = xy;
      ndx = ndx_long;
COMMON:
      switch ( code & 0xF )
      {
        case 0x0:
        case 0x1:
        case 0x2:
        case 0x4:
        case 0x5:
        case 0x6:
        case 0x8:
        case 0x9:
        case 0xA:
        case 0xB:
//        sub a, (long,x)       ; 5 3    D0 MS LS
//        sub a, (long,y)       ; 6 4 90 D0 MS LS
//        sub a, ([short.w],y)  ; 7 3 91 D0 XX
//        sub a, ([short.w],x)  ; 7 3 92 D0 XX
//        cp a, (long,x)        ; 5 3    D1 MS LS
//        cp a, (long,y)        ; 6 4 90 D1 MS LS
//        cp a, ([short.w],y)   ; 7 3 91 D1 XX
//        cp a, ([short.w],x)   ; 7 3 92 D1 XX
//        sbc a, (long,x)       ; 5 3    D2 MS LS
//        sbc a, (long,y)       ; 6 4 90 D2 MS LS
//        sbc a, ([short.w],y)  ; 7 3 91 D2 XX
//        sbc a, ([short.w],x)  ; 7 3 92 D2 XX
//        and a, (long,x)       ; 5 3    D4 MS LS
//        and a, (long,y)       ; 6 4 90 D4 MS LS
//        and a, ([short.w],y)  ; 7 3 91 D4 XX
//        and a, ([short.w],x)  ; 7 3 92 D4 XX
//        bcp a, (long,x)       ; 5 3    D5 MS LS
//        bcp a, (long,y)       ; 6 4 90 D5 MS LS
//        bcp a, ([short.w],y)  ; 7 3 91 D5 XX
//        bcp a, ([short.w],x)  ; 7 3 92 D5 XX
//        ld a, (long,x)        ; 5 3    D6 MS LS
//        ld a, (long,y)        ; 6 4 90 D6 MS LS
//        ld a, ([short.w],y)   ; 7 3 91 D6 XX
//        ld a, ([short.w],x)   ; 7 3 92 D6 XX
//        xor a, (long,x)       ; 5 3    D8 MS LS
//        xor a, (long,y)       ; 6 4 90 D8 MS LS
//        xor a, ([short.w],y)  ; 7 3 91 D8 XX
//        xor a, ([short.w],x)  ; 7 3 92 D8 XX
//        adc a, (long,x)       ; 5 3    D9 MS LS
//        adc a, (long,y)       ; 6 4 90 D9 MS LS
//        adc a, ([short.w],y)  ; 7 3 91 D9 XX
//        adc a, ([short.w],x)  ; 7 3 92 D9 XX
//        or a, (long,x)        ; 5 3    DA MS LS
//        or a, (long,y)        ; 6 4 90 DA MS LS
//        or a, ([short.w],y)   ; 7 3 91 DA XX
//        or a, ([short.w],x)   ; 7 3 92 DA XX
//        add a, (long,x)       ; 5 3    DB MS LS
//        add a, (long,y)       ; 6 4 90 DB MS LS
//        add a, ([short.w],y)  ; 7 3 91 DB XX
//        add a, ([short.w],x)  ; 7 3 92 DB XX
          opreg(insn.Op1, A);
          opndx(insn, insn.Op2, ndx, index);
          break;
        case 0x3:
        case 0xE:
//        cp x, (long,x)        ; 5 3    D3 MS LS
//        cp y, (long,y)        ; 6 4 90 D3 MS LS
//        cp y, ([short.w],y)   ; 7 3 91 D3 XX
//        cp x, ([short.w],x)   ; 7 3 92 D3 XX
//        ld x, (long,x)        ; 5 3    DE MS LS
//        ld y, (long,y)        ; 6 4 90 DE MS LS
//        ld y, ([short.w],y)   ; 7 3 91 DE XX
//        ld x, ([short.w],x)   ; 7 3 92 DE XX
          opreg(insn.Op1, xy);
          opndx(insn, insn.Op2, ndx, index);
          break;
        case 0x7:
//        ld (long,x), a        ; 6 3    D7 MS LS
//        ld (long,y), a        ; 7 4 90 D7 MS LS
//        ld ([short.w],y), a   ; 8 3 91 D7 XX
//        ld ([short.w],x), a   ; 8 3 92 D7 XX
          opndx(insn, insn.Op1, ndx, index);
          opreg(insn.Op2, A);
          break;
        case 0xC:
        case 0xD:
//        jp (long,x)           ; 4 3    DC MS LS
//        jp (long,y)           ; 5 4 90 DC MS LS
//        jp ([short.w],y)      ; 6 3 91 DC XX
//        jp ([short.w],x)      ; 6 3 92 DC XX
//        call (long,x)         ; 7 3    DD MS LS
//        call (long,y)         ; 8 4 90 DD MS LS
//        call ([short.w],y)    ; 9 3 91 DD XX
//        call ([short.w],x)    ; 9 3 92 DD XX
          opndx(insn, insn.Op1, ndx, index);
          if ( (insn.auxpref & aux_indir) == 0 && !index )
          {
            insn.Op1.type = o_near;
            insn.Op1.dtype = dt_code;
          }
          break;
        case 0xF:
//        ld (long,x), x        ; 6 3    DF MS LS
//        ld (long,y), y        ; 7 4 90 DF MS LS
//        ld ([short.w],y), y   ; 8 3 91 DF XX
//        ld ([short.w],x), x   ; 8 3 92 DF XX
          opndx(insn, insn.Op1, ndx, index);
          opreg(insn.Op2, xy);
          break;
      }
      break;

    case 0xE:
      index = xy;
      ndx = ndx_short;
      goto COMMON;
//        sub a, (short,x)      ; 4 2    E0 XX
//        sub a, (short,y)      ; 5 3 90 E0 XX
//        sub a, ([short],y)    ; 6 3 91 E0 XX
//        sub a, ([short],x)    ; 6 3 92 E0 XX
//        cp a, (short,x)       ; 4 2    E1 XX
//        cp a, (short,y)       ; 5 3 90 E1 XX
//        cp a, ([short],y)     ; 6 3 91 E1 XX
//        cp a, ([short],x)     ; 6 3 92 E1 XX
//        sbc a, (short,x)      ; 4 2    E2 XX
//        sbc a, (short,y)      ; 5 3 90 E2 XX
//        sbc a, ([short],y)    ; 6 3 91 E2 XX
//        sbc a, ([short],x)    ; 6 3 92 E2 XX
//        cp x, (short,x)       ; 4 2    E3 XX
//        cp y, (short,y)       ; 5 3 90 E3 XX
//        cp y, ([short],y)     ; 6 3 91 E3 XX
//        cp x, ([short],x)     ; 6 3 92 E3 XX
//        and a, (short,x)      ; 4 2    E4 XX
//        and a, (short,y)      ; 5 3 90 E4 XX
//        and a, ([short],y)    ; 6 3 91 E4 XX
//        and a, ([short],x)    ; 6 3 92 E4 XX
//        bcp a, (short,x)      ; 4 2    E5 XX
//        bcp a, (short,y)      ; 5 3 90 E5 XX
//        bcp a, ([short],y)    ; 6 3 91 E5 XX
//        bcp a, ([short],x)    ; 6 3 92 E5 XX
//        ld a, (short,x)       ; 4 2    E6 XX
//        ld a, (short,y)       ; 5 3 90 E6 XX
//        ld a, ([short],y)     ; 6 3 91 E6 XX
//        ld a, ([short],x)     ; 6 3 92 E6 XX
//        ld (short,x), a       ; 5 2    E7 XX
//        ld (short,y), a       ; 6 3 90 E7 XX
//        ld ([short],y), a     ; 7 3 91 E7 XX
//        ld ([short],x), a     ; 7 3 92 E7 XX
//        xor a, (short,x)      ; 4 2    E8 XX
//        xor a, (short,y)      ; 5 3 90 E8 XX
//        xor a, ([short],y)    ; 6 3 91 E8 XX
//        xor a, ([short],x)    ; 6 3 92 E8 XX
//        adc a, (short,x)      ; 4 2    E9 XX
//        adc a, (short,y)      ; 5 3 90 E9 XX
//        adc a, ([short],y)    ; 6 3 91 E9 XX
//        adc a, ([short],x)    ; 6 3 92 E9 XX
//        or a, (short,x)       ; 4 2    EA XX
//        or a, (short,y)       ; 5 3 90 EA XX
//        or a, ([short],y)     ; 6 3 91 EA XX
//        or a, ([short],x)     ; 6 3 92 EA XX
//        add a, (short,x)      ; 4 2    EB XX
//        add a, (short,y)      ; 5 3 90 EB XX
//        add a, ([short],y)    ; 6 3 91 EB XX
//        add a, ([short],x)    ; 6 3 92 EB XX
//        jp (short,x)          ; 3 2    EC XX
//        jp (short,y)          ; 4 3 90 EC XX
//        jp ([short],y)        ; 5 3 91 EC XX
//        jp ([short],x)        ; 5 3 92 EC XX
//        call (short,x)        ; 6 2    ED XX
//        call (short,y)        ; 7 3 90 ED XX
//        call ([short],y)      ; 8 3 91 ED XX
//        call ([short],x)      ; 8 3 92 ED XX
//        ld x, (short,x)       ; 4 2    EE XX
//        ld y, (short,y)       ; 5 3 90 EE XX
//        ld y, ([short],y)     ; 6 3 91 EE XX
//        ld x, ([short],x)     ; 6 3 92 EE XX
//        ld (short,x), x       ; 5 2    EF XX
//        ld (short,y), y       ; 6 3 90 EF XX
//        ld ([short],y), y     ; 7 3 91 EF XX
//        ld ([short],x), x     ; 7 3 92 EF XX

    case 0xF:
      index = xy;
      ndx = ndx_none;
      goto COMMON;
//        sub a, (x)            ; 3 1    F0
//        sub a, (y)            ; 4 2 90 F0
//        cp a, (x)             ; 3 1    F1
//        cp a, (y)             ; 4 2 90 F1
//        sbc a, (x)            ; 3 1    F2
//        sbc a, (y)            ; 4 2 90 F2
//        cp x, (x)             ; 3 1    F3
//        cp y, (y)             ; 4 2 90 F3
//        and a, (x)            ; 3 1    F4
//        and a, (y)            ; 4 2 90 F4
//        bcp a, (x)            ; 3 1    F5
//        bcp a, (y)            ; 4 2 90 F5
//        ld a, (x)             ; 3 1    F6
//        ld a, (y)             ; 4 2 90 F6
//        ld (x), a             ; 4 1    F7
//        ld (y), a             ; 5 2 90 F7
//        xor a, (x)            ; 3 1    F8
//        xor a, (y)            ; 4 2 90 F8
//        adc a, (x)            ; 3 1    F9
//        adc a, (y)            ; 4 2 90 F9
//        or a, (x)             ; 3 1    FA
//        or a, (y)             ; 4 2 90 FA
//        add a, (x)            ; 3 1    FB
//        add a, (y)            ; 4 2 90 FB
//        jp (x)                ; 2 1    FC
//        jp (y)                ; 3 2 90 FC
//        call (x)              ; 5 1    FD
//        call (y)              ; 6 2 90 FD
//        ld x, (x)             ; 3 1    FE
//        ld y, (y)             ; 4 2 90 FE
//        ld (x), x             ; 4 1    FF
//        ld (y), y             ; 5 2 90 FF
  }
  return insn.size;
}


