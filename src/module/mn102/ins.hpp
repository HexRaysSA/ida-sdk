/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

// List of instructions
extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
mn102_null = 0,           // Unknown Operation
mn102_add,
mn102_addc,
mn102_addnf,
mn102_and,
mn102_asr,
mn102_bcc,
mn102_bccx,
mn102_bclr,
mn102_bcs,
mn102_bcsx,
mn102_beq,
mn102_beqx,
mn102_bge,
mn102_bgex,
mn102_bgt,
mn102_bgtx,
mn102_bhi,
mn102_bhix,
mn102_ble,
mn102_blex,
mn102_bls,
mn102_blsx,
mn102_blt,
mn102_bltx,
mn102_bnc,
mn102_bncx,
mn102_bne,
mn102_bnex,
mn102_bns,
mn102_bnsx,
mn102_bra,
mn102_bset,
mn102_btst,
mn102_bvc,
mn102_bvcx,
mn102_bvs,
mn102_bvsx,
mn102_cmp,
mn102_divu,
mn102_ext,
mn102_extx,
mn102_extxb,
mn102_extxbu,
mn102_extxu,
mn102_jmp,
mn102_jsr,
mn102_lsr,
mn102_mov,
mn102_movb,
mn102_movbu,
mn102_movx,
mn102_mul,
mn102_mulq,
mn102_mulqh,
mn102_mulql,
mn102_mulu,
mn102_nop,
mn102_not,
mn102_or,
mn102_pxst,
mn102_rol,
mn102_ror,
mn102_rti,
mn102_rts,
mn102_sub,
mn102_subc,
mn102_tbnz,
mn102_tbz,
mn102_xor,
mn102_last
};

#endif
