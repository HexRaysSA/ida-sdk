
#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum
{
KR1878_null = 0,     // Unknown Operation

KR1878_mov,
KR1878_cmp,      // Compare
KR1878_add,      // Addition
KR1878_sub,      // Subtract
KR1878_and,      // Logical AND
KR1878_or,       // Logical Inclusive OR
KR1878_xor,      // Logical Exclusive OR

KR1878_movl,
KR1878_cmpl,     // Compare
KR1878_addl,     // Addition
KR1878_subl,     // Subtract
KR1878_bic,
KR1878_bis,
KR1878_btg,
KR1878_btt,

KR1878_swap,
KR1878_neg,
KR1878_not,
KR1878_shl,      // Shift Left
KR1878_shr,      // Shift Right
KR1878_shra,     // Arithmetic Shift Right
KR1878_rlc,      // Rotate Left
KR1878_rrc,      // Rotate Right
KR1878_adc,      // Add with Carry
KR1878_sbc,      // Subtract with Carry

KR1878_ldr,
KR1878_mtpr,
KR1878_mfpr,
KR1878_push,
KR1878_pop,
KR1878_sst,
KR1878_cst,
KR1878_tof,
KR1878_tdc,

KR1878_jmp,      // Jump
KR1878_jsr,      // Jump to Subroutine
KR1878_jnz,      // Jump
KR1878_jz,       // Jump
KR1878_jns,      // Jump
KR1878_js,       // Jump
KR1878_jnc,      // Jump
KR1878_jc,       // Jump
KR1878_ijmp,     // Jump
KR1878_ijsr,     // Jump to Subroutine
KR1878_rts,      // Return from Subroutine
KR1878_rtsc,     // Return from Subroutine
KR1878_rti,      // Return from Interrupt

KR1878_nop,      // No Operation
KR1878_wait,
KR1878_stop,
KR1878_reset,
KR1878_sksp,

KR1878_last,

};

#endif
