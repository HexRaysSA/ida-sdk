
#ifndef __ins_hpp
#define __ins_hpp

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
  fr_null = 0,            // null instruction

  fr_add,                 // add word data of source register / 4-bit immediate data to destination register
  fr_add2,                // add 4-bit immediate data to destination register
  fr_addc,                // add word data of source register and carry bit to destination register
  fr_addn,                // add word data of source register / immediate data to destination register
  fr_addn2,               // add immediate data to destination register
  fr_sub,                 // subtract word data in source register from destination register
  fr_subc,                // subtract word data in source register and carry bit from destination register
  fr_subn,                // subtract word data in source register from destination register
  fr_cmp,                 // compare word / immediate data in source register and destination register
  fr_cmp2,                // compare immediate data and destination register
  fr_and,                 // and word data of source register to destination register / data in memory
  fr_andh,                // and half-word data of source register to data in memory
  fr_andb,                // and byte data of source register to data in memory
  fr_or,                  // or word data of source register to destination register / data in memory
  fr_orh,                 // or half-word data of source register to data in memory
  fr_orb,                 // or byte data of source register to data in memory
  fr_eor,                 // exclusive or word data of source register to destination register / data in memory
  fr_eorh,                // exclusive or half-word data of source register to data in memory
  fr_eorb,                // exclusive or byte data of source register to data in memory
  fr_bandl,               // and 4-bit immediate data to lower 4 bits of byte data in memory
  fr_bandh,               // and 4-bit immediate data to higher 4 bits of byte data in memory
  fr_borl,                // or 4-bit immediate data to lower 4 bits of byte data in memory
  fr_borh,                // or 4-bit immediate data to higher 4 bits of byte data in memory
  fr_beorl,               // eor 4-bit immediate data to lower 4 bits of byte data in memory
  fr_beorh,               // eor 4-bit immediate data to higher 4 bits of byte data in memory
  fr_btstl,               // test lower 4 bits of byte data in memory
  fr_btsth,               // test higher 4 bits of byte data in memory
  fr_mul,                 // multiply word data
  fr_mulu,                // multiply unsigned word data
  fr_mulh,                // multiply half-word data
  fr_muluh,               // multiply unsigned half-word data
  fr_div0s,               // initial setting up for signed division
  fr_div0u,               // initial setting up for unsigned division
  fr_div1,                // main process of division
  fr_div2,                // correction when remainder is 0
  fr_div3,                // correction when remainder is 0
  fr_div4s,               // correction answer for signed division
  fr_lsl,                 // logical shift to the left direction
  fr_lsl2,                // logical shift to the left direction
  fr_lsr,                 // logical shift to the right direction
  fr_lsr2,                // logical shift to the right direction
  fr_asr,                 // arithmetic shift to the right direction
  fr_asr2,                // arithmetic shift to the right direction
  fr_ldi_32,              // load immediate 32-bit data to destination register
  fr_ldi_20,              // load immediate 20-bit data to destination register
  fr_ldi_8,               // load immediate 8-bit data to destination register
  fr_ld,                  // load word data in memory to register / program status register
  fr_lduh,                // load half-word data in memory to register
  fr_ldub,                // load byte data in memory to register
  fr_st,                  // store word data in register / program status register to memory
  fr_sth,                 // store half-word data in register to memory
  fr_stb,                 // store byte data in register to memory
  fr_mov,                 // move word data in source register / program status register to destination register / program status register
  fr_jmp,                 // jump
  fr_call,                // call subroutine
  fr_ret,                 // return from subroutine
  fr_int,                 // software interrupt
  fr_inte,                // software interrupt for emulator
  fr_reti,                // return from interrupt
  fr_bra,                 // branch relative if condition satisfied
  fr_bno,                 // branch relative if condition satisfied
  fr_beq,                 // branch relative if condition satisfied
  fr_bne,                 // branch relative if condition satisfied
  fr_bc,                  // branch relative if condition satisfied
  fr_bnc,                 // branch relative if condition satisfied
  fr_bn,                  // branch relative if condition satisfied
  fr_bp,                  // branch relative if condition satisfied
  fr_bv,                  // branch relative if condition satisfied
  fr_bnv,                 // branch relative if condition satisfied
  fr_blt,                 // branch relative if condition satisfied
  fr_bge,                 // branch relative if condition satisfied
  fr_ble,                 // branch relative if condition satisfied
  fr_bgt,                 // branch relative if condition satisfied
  fr_bls,                 // branch relative if condition satisfied
  fr_bhi,                 // branch relative if condition satisfied
  fr_dmov,                // move word data from register / address to register / address
  fr_dmovh,               // move half-word data from register / address to register / address
  fr_dmovb,               // move byte data from register / address to register / address
  fr_ldres,               // load word data in memory to resource
  fr_stres,               // store word data in resource to memory
  fr_copop,               // coprocessor operation
  fr_copld,               // load 32-bit data from register to coprocessor register
  fr_copst,               // store 32-bit data from coprocessor register to register
  fr_copsv,               // save 32-bit data from coprocessor register to register
  fr_nop,                 // no operation
  fr_andccr,              // and condition code register and immediate data
  fr_orccr,               // or condition code register and immediate data
  fr_stilm,               // set immediate data to interrupt level mask register
  fr_addsp,               // add stack pointer and immediate data
  fr_extsb,               // sign extend from byte data to word data
  fr_extub,               // unsign extend from byte data to word data
  fr_extsh,               // sign extend from byte data to word data
  fr_extuh,               // unsigned extend from byte data to word data
  fr_ldm0,                // load multiple registers
  fr_ldm1,                // load multiple registers
  fr_stm0,                // store multiple registers
  fr_stm1,                // store multiple registers
  fr_enter,               // enter function
  fr_leave,               // leave function
  fr_xchb,                // exchange byte data
  fr_last                 // last instruction
};

#endif /* __ins_hpp */
