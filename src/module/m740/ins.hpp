
#ifndef __INS_HPP
#define __INS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
  m740_null = 0,           // null instruction
  m740_adc,                // add with carry
  m740_and,                // logical and
  m740_asl,                // arithmetic shift left
  m740_bbc,                // branch on bit clear
  m740_bbs,                // branch on bit set
  m740_bcc,                // branch on carry clear
  m740_bcs,                // branch on carry set
  m740_beq,                // branch on equal
  m740_bit,                // test bit in memory with accumulator
  m740_bmi,                // branch on result minus
  m740_bne,                // branch on not equal
  m740_bpl,                // branch on result plus
  m740_bra,                // branch always
  m740_brk,                // force break
  m740_bvc,                // branch on overflow clear
  m740_bvs,                // branch on overflow set
  m740_clb,                // clear bit
  m740_clc,                // clear carry flag
  m740_cld,                // clear decimal mode
  m740_cli,                // clear interrupt disable status
  m740_clt,                // clear transfer flag
  m740_clv,                // clear overflow flag
  m740_cmp,                // compare
  m740_com,                // complement
  m740_cpx,                // compare memory and index register X
  m740_cpy,                // compare memory and index register Y
  m740_dec,                // decrement by one
  m740_dex,                // decrement index register X by one
  m740_dey,                // decrement index register Y by one
  m740_div,                // divide memory by accumulator
  m740_eor,                // exclusive or memory with accumulator
  m740_inc,                // increment by one
  m740_inx,                // increment index register X by one
  m740_iny,                // increment index register Y by one
  m740_jmp,                // jump
  m740_jsr,                // jump to subroutine
  m740_lda,                // load accumulator with memory
  m740_ldm,                // load immediate data to memory
  m740_ldx,                // load index register X from memory
  m740_ldy,                // load index register Y from memory
  m740_lsr,                // logical shift right
  m740_mul,                // multiply accumulator and memory
  m740_nop,                // no operation
  m740_ora,                // or memory with accumulator
  m740_pha,                // push accumulator on stack
  m740_php,                // push processor status on stack
  m740_pla,                // pull accumulator from stack
  m740_plp,                // pull processor status from stack
  m740_rol,                // rotate one bit left
  m740_ror,                // rotate one bit right
  m740_rrf,                // rotate right of four bits
  m740_rti,                // return from interrupt
  m740_rts,                // return from subroutine
  m740_sbc,                // subtract with carry
  m740_seb,                // set bit
  m740_sec,                // set carry flag
  m740_sed,                // set decimal mode
  m740_sei,                // set interrupt disable flag
  m740_set,                // set transfert flag
  m740_sta,                // store accumulator in memory
  m740_stp,                // stop
  m740_stx,                // store index register X in memory
  m740_sty,                // store index register Y in memory
  m740_tax,                // transfert accumulator to index register X
  m740_tay,                // transfert accumulator to index register Y
  m740_tst,                // test for negative or zero
  m740_tsx,                // transfert stack pointer to index register X
  m740_txa,                // transfert index register X to accumulator
  m740_txs,                // transfert index register X to stack pointer
  m740_tya,                // transfert index register Y to accumulator
  m740_wit,                // wait

  m740_last
};

#endif /* __INS_HPP */

