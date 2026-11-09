
#ifndef __INS_HPP
#define __INS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
  // 7700 :

  m7700_null = 0,         // null instruction
  m7700_adc,              // addition with carry
  m7700_and,              // logical AND
  m7700_asl,              // arithmetic shift left
  m7700_bbc,              // branch on bit clear
  m7700_bbs,              // branch on bit set
  m7700_bcc,              // branch on carry clear
  m7700_bcs,              // branch on carry set
  m7700_beq,              // branch on equal
  m7700_bmi,              // branch on result minus
  m7700_bne,              // branch on not equal
  m7700_bpl,              // branch on result plus
  m7700_bra,              // branch always
  m7700_brk,              // force break
  m7700_bvc,              // branch on overflow clear
  m7700_bvs,              // branch on overflow set
  m7700_clb,              // clear bit
  m7700_clc,              // clear carry flag
  m7700_cli,              // clear interrupt disable status
  m7700_clm,              // clear m flag
  m7700_clp,              // clear processor status
  m7700_clv,              // clear overflow flag
  m7700_cmp,              // compare
  m7700_cpx,              // compare memory and index register X
  m7700_cpy,              // compare memory and index register Y
  m7700_dec,              // decrement by one
  m7700_dex,              // decrement index register X by one
  m7700_dey,              // decrement index register Y by one
  m7700_div,              // divide
  m7700_eor,              // exclusive OR memory with accumulator
  m7700_inc,              // increment by one
  m7700_inx,              // increment index register X by one
  m7700_iny,              // increment index register Y by one
  m7700_jmp,              // jump
  m7700_jsr,              // jump to subroutine
  m7700_lda,              // load accumulator from memory
  m7700_ldm,              // load immediate to memory
  m7700_ldt,              // load immediate to data bank register
  m7700_ldx,              // load index register X from memory
  m7700_ldy,              // load index register Y from memory
  m7700_lsr,              // logical shift right
  m7700_mpy,              // multiply
  m7700_mvn,              // move negative
  m7700_mvp,              // move positive
  m7700_nop,              // no operation
  m7700_ora,              // OR memory with accumulator
  m7700_pea,              // push effective address
  m7700_pei,              // push effective indirect address
  m7700_per,              // push effective program counter relative address
  m7700_pha,              // push accumulator A on stack
  m7700_phb,              // push accumulator B on stack
  m7700_phd,              // push direct page register on stack
  m7700_phg,              // push program bank register on stack
  m7700_php,              // push processor status on stack
  m7700_pht,              // push data bank register on stack
  m7700_phx,              // push index register X on stack
  m7700_phy,              // push index register Y on stack
  m7700_pla,              // pull accumulator A from stack
  m7700_plb,              // pull accumulator B from stack
  m7700_pld,              // pull direct page register from stack
  m7700_plp,              // pull processor status from stack
  m7700_plt,              // pull data bank register from stack
  m7700_plx,              // pull index register X from stack
  m7700_ply,              // pull index register Y from stack
  m7700_psh,              // push
  m7700_pul,              // pull
  m7700_rla,              // rotate left accumulator A
  m7700_rol,              // rotate one bit left
  m7700_ror,              // rotate one bit right
  m7700_rti,              // return from interrupt
  m7700_rtl,              // return from subroutine long
  m7700_rts,              // return from subroutine
  m7700_sbc,              // subtract with carry
  m7700_seb,              // set bit
  m7700_sec,              // set carry flag
  m7700_sei,              // set interrupt disable status
  m7700_sem,              // set m flag
  m7700_sep,              // set processor status
  m7700_sta,              // store accumulator in memory
  m7700_stp,              // stop
  m7700_stx,              // store index register X in memory
  m7700_sty,              // store index register Y in memory
  m7700_tad,              // transfer accumulator A to direct page register
  m7700_tas,              // transfer accumulator A to stack pointer
  m7700_tax,              // transfer accumulator A to index register X
  m7700_tay,              // transfer accumulator A to index register Y
  m7700_tbd,              // transfer accumulator B to direct page register
  m7700_tbs,              // transfer accumulator B to stack pointer
  m7700_tbx,              // transfer accumulator B to index register X
  m7700_tby,              // transfer accumulator B to index register Y
  m7700_tda,              // transfer direct page register to accumulator A
  m7700_tdb,              // transfer direct page register to accumulator B
  m7700_tsa,              // transfer stack pointer to accumulator A
  m7700_tsb,              // transfer stack pointer to accumulator B
  m7700_tsx,              // transfer stack pointer to index register X
  m7700_txa,              // transfer index register X to accumulator A
  m7700_txb,              // transfer index register X to accumulator B
  m7700_txs,              // transfer index register X to stack pointer
  m7700_txy,              // transfer index register X to Y
  m7700_tya,              // transfer index register Y to accumulator A
  m7700_tyb,              // transfer index register Y to accumulator B
  m7700_tyx,              // transfer index register Y to X
  m7700_wit,              // wait
  m7700_xab,              // exchange accumulator A and B

  // 7750 :

  m7750_asr,              // arithmetic shift right
  m7750_divs,             // divide with sign
  m7750_exts,             // extention with sign
  m7750_extz,             // extention zero
  m7750_mpys,             // multiply with sign

  m7700_last
};

#endif /* __INS_HPP */

