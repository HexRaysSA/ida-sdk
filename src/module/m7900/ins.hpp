/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      MITSUBISHI 7900 Family
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
m7900_null = 0,           // Unknown Operation


m7900_abs,   // ABSolute
m7900_absd,  // ABSolute at Double-word

m7900_adc,   // ADd with Carry
m7900_adcb,  // ADd with Carry at Byte
m7900_adcd,  // ADd with Carry at Double-word

m7900_add,    // Addition

m7900_addb,   // ADD at Byte
m7900_addd,   // ADD at Double-word
m7900_addm,   // ADD immediate and Memory
m7900_addmb,  // ADD immediate and Memory at Byte
m7900_addmd,  // ADD immediate and Memory at Double-word
m7900_adds,   // ADD Stack pointer and immediate
m7900_addx,   // ADD index register X and immediate
m7900_addy,   // ADD index register Y and immediate

m7900_and,    // Logical AND
m7900_andb,   // logical AND between immediate (Byte)

m7900_andm,   // logical AND between immediate value and Memory
m7900_andmb,  // logical AND between immediate value and Memory (Byte)
m7900_andmd,  // logical AND between immediate value and Memory (Double word)

m7900_asl,    // Arithmetic Shift to Left
m7900_asln,   // Arithmetic Shift to Left by n bits
m7900_asldn,  // Arithmetic Shift to Left by n bits (Double word)


m7900_asr,    // Arithmeticshift to the right
m7900_asrn,   // Arithmetic Shift to Right by n bits
m7900_asrdn,  // Arithmetic Shift to Right by n bits (Double word)

m7900_bbc,    // Branch on Bit Clear
m7900_bbcb,   // Branch on Bit Clear (Byte)
m7900_bbs,    // Branch on Bit Set
m7900_bbsb,   // Branch on Bit Set (Byte)

m7900_bcc,    // Branch on Carry Clear
m7900_bcs,    // Branch on Carry Set
m7900_beq,    // Branch on EQual
m7900_bge,    // Branch on Greater or Equal
m7900_bgt,    // Branch on Greater Than
m7900_bgtu,   // Branch on Greater Than with Unsign
m7900_ble,    // Branch on Less or Equal
m7900_bleu,   // Branch on Less Equal with Unsign
m7900_blt,    // Branch on Less Than
m7900_bmi,    // Branch on result MInus
m7900_bne,    // Branch on Not Equal
m7900_bpl,    // Branch on result PLus
m7900_bra,    // BRanch Always
m7900_bral,   // BRanch Always

m7900_brk,    // force BReaK

m7900_bsc,    // Branch on Single bit Clear
m7900_bsr,    // Branch to SubRoutine
m7900_bss,    // Branch on Single bit Set

m7900_bvc,    // Branch on oVerflow Clear
m7900_bvs,    // Branch on oVerflow Set

m7900_cbeq,   // Compare immediate and Branch on EQual
m7900_cbeqb,  // Compare immediate and Branch on EQual at Byte
m7900_cbne,   // Compare immediate and Branch on Not Equal
m7900_cbneb,  // Compare immediate and Branch on Not Equal at Byte

m7900_clc,    // CLear Carry flag
m7900_cli,    // CLear Interrupt disable status
m7900_clm,    // CLear M flag
m7900_clp,    // CLear Processor status

m7900_clr,    // CLeaR accumulator
m7900_clrb,   // CLeaR accumulator at Byte
m7900_clrm,   // CLeaR Memory
m7900_clrmb,  // CLeaR Memory at Byte
m7900_clrx,   // CLeaR index register X
m7900_clry,   // CLeaR index register Y

m7900_clv,    // CLear oVerflow flag

m7900_cmp,    // CoMPare
m7900_cmpb,   // CoMPare at Byte
m7900_cmpd,   // CoMPare at Double-word
m7900_cmpm,   // CoMPare immediate with Memory
m7900_cmpmb,  // CoMPare immediate with Memory at Byte
m7900_cmpmd,  // CoMPare immediate with Memory at Double-word

m7900_cpx,    // ComPare memory and index register X
m7900_cpy,    // ComPare memory and index register Y

m7900_debne,   // DEcrement memory and Branch on Not Equal

m7900_dec,    // DECrement by one
m7900_dex,    // DEcrement index register X by one
m7900_dey,    // DEcrement index register Y by one

m7900_div,    // DIVide unsigned
m7900_divs,   // DIVide with Sign
m7900_dxbne,  // Decrement index register X and Branch on Not Equal
m7900_dybne,  // Decrement index register Y and Branch on Not Equal

m7900_eor,    // Exclusive OR memory with accumulator
m7900_eorb,   // Exclusive OR immediate with accumulator at Byte
m7900_eorm,   // Exclusive OR immediate with Memory
m7900_eormb,  // Exclusive OR immediate with Memory at Byte
m7900_eormd,  // Exclusive OR immediate with Memory at Double-word

m7900_exts,   // EXTension Sign
m7900_extsd,  // EXTension Sign at Double-word
m7900_extz,   // EXTension Zero
m7900_extzd,  // EXTension Zero at Double-word

m7900_inc,    // INCrement by one
m7900_inx,    // INcrement index register X by one
m7900_iny,    // INcrement index register y by one

m7900_jmp,    // Jump
m7900_jmpl,   // Jump

m7900_jsr,    // Jump to SubRoutine
m7900_jsrl,   // Jump to SubRoutine


m7900_lda,    // LoaD Accumulator from memory
m7900_ldab,   // LoaD Accumulator from memory at Byte
m7900_ldad,   // LoaD Accumulator from memory at Double-word
m7900_lddn,   // LoaD immediate to Direct page register n

m7900_ldt,    // LoaD immediate to DaTa bank register
m7900_ldx,    // LoaD index register X from memory
m7900_ldxb,   // LoaD index register X from memory at Byte
m7900_ldy,    // LoaD index register Y from memory
m7900_ldyb,   // LoaD index register Y from memory at Byte

m7900_lsr,    // Logical Shift Right
m7900_lsrn,   // Logical n bits Shift Right
m7900_lsrdn,  // Logical n bits Shift Right at Double-word

m7900_movm,   // MOVe Memory to memory
m7900_movmb,  // MOVe Memory to memory at Byte
m7900_movr,   // MOVe Repeat memory to memory
m7900_movrb,  // MOVe Repeat memory to memory at Byte

m7900_mpy,    // MultiPlY
m7900_mpys,   // MultiPlY with Sign

m7900_mvn,    // MoVe Negative
m7900_mvp,    // MoVe Positive

m7900_neg,    // NEGative
m7900_negd,   // NEGative at Double-word

m7900_nop,    // No OPeration

m7900_ora,    // OR memory with Accumulator
m7900_orab,   // OR immediate with Accumulator at Byte
m7900_oram,   // OR immediAte with Memory
m7900_oramb,  // OR immediAte with Memory at Byte
m7900_oramd,  // OR immediAte with Memory at Double-word

m7900_pea,    // Push Effective Address
m7900_pei,    // Push Effective Indirect address
m7900_per,    // Push Effective program counter Relative address
m7900_pha,    // PusH accumulator A on stack
m7900_phb,    // PusH accumulator B on stack
m7900_phd,    // PusH Direct page register on stack
m7900_phdn,   // PusH Direct page register n on stack
m7900_phg,    // PusH proGram bank register on stack

m7900_phldn,  // PusH dpr n to stack and Load immediate to Dpr n

m7900_php,    // PusH Processor status on stack
m7900_pht,    // PusH daTa bank register on stack
m7900_phx,    // PusH index register X on stack
m7900_phy,    // PusH index register Y on stack

m7900_pla,    // PuLl accumulator A from stack
m7900_plb,    // PuLl accumulator B from stack
m7900_pld,    // PuLl Direct page register from stack
m7900_pldn,   // PuLl Direct page register n from stack
m7900_plp,    // PuLl Processor status from stack
m7900_plt,    // PuLl daTa bank register from stack
m7900_plx,    // PuLl index register X from stack
m7900_ply,    // PuLl index register Y from stack

m7900_psh,    // PuSH
m7900_pul,    // PuLl

m7900_rla,    // Rotate Left accumulator A
m7900_rmpa,   // Repeat Multiply and Accumulate

m7900_rol,    // ROtate one bit Left
m7900_roln,   // n bits ROtate Left

m7900_roldn,  // n bits ROtate Left at Double-word

m7900_ror,    // ROtate one bit Right
m7900_rorn,   // n bits ROtate Right
m7900_rordn,  // n bits ROtate Right at Double-word

m7900_rti,    // Return from Interrupt
m7900_rtl,    // ReTurn from subroutine Long
m7900_rtld,  // ReTurn from subroutine Long and pull Direct page register n
m7900_rts,    // ReTurn from Subroutine
m7900_rtsdn,  // ReTurn from Subroutine and pull Direct page register n


m7900_sbc,    // SuBtract with Carry
m7900_sbcb,   // SuBtract with Carry at Byte
m7900_sbcd,   // SuBtract with Carry at Double-word


m7900_sec,    // SEt Carry flag
m7900_sei,    // SEt Interrupt disable status
m7900_sem,    // SEt M flag
m7900_sep,    // SEt Processor status


m7900_sta,    // STore Accumulator in memory
m7900_stab,   // STore Accumulator in memory at Byte
m7900_stad,   // STore Accumulator in memory at Double-word


m7900_stp,   // SToP
m7900_stx,   // STore index register X in memory
m7900_sty,   // STore index register Y in memory

m7900_sub,   // SUBtract
m7900_subb,  // SUBtract at Byte
m7900_subd,  // SUBtract at Double-word
m7900_subm,  // SUBtract immediate from Memory
m7900_submb, // SUBtract immediate from Memory at Byte
m7900_submd, // SUBtract immediate from Memory at Double-word
m7900_subs,  // SUBtract Stack pointer
m7900_subx,  // SUBtract immediate from index register X
m7900_suby,  // SUBtract immediate from index register Y



m7900_tadn,  // Transfer accumulator A to Direct page register n


m7900_tas,   // Transfer accumulator A to Stack pointer
m7900_tax,   // Transfer accumulator A to index register X
m7900_tay,   // Transfer accumulator A to index register Y

m7900_tbdn,  // Transfer accumulator B to Direct page register n

m7900_tbs,   // Transfer accumulator B to Stack pointer
m7900_tbx,   // Transfer accumulator B to index register X
m7900_tby,   // Transfer accumulator B to index register Y

m7900_tdan,  // Transfer Direct page register n to accumulator A
m7900_tdbn,  // Transfer Direct page register n to accumulator B

m7900_tds,   // Transfer Direct page register to Stack pointer


m7900_tsa,   // Transfer Stack pointer to accumulator A
m7900_tsb,   // Transfer Stack pointer to accumulator B
m7900_tsd,   // Transfer Stack pointer to Direct page register
m7900_tsx,   // Transfer Stack pointer to index register X
m7900_txa,   // Transfer index register X to accumulator A
m7900_txb,   // Transfer index register X to accumulator B
m7900_txs,   // Transfer index register X to Stack pointer
m7900_txy,   // Transfer index register X to Y
m7900_tya,   // Transfer index register Y to accumulator A
m7900_tyb,   // Transfer index register Y to accumulator B
m7900_tyx,   // Transfer index register Y to X

m7900_wit,   // WaIT

m7900_xab,   // eXchange accumulator A and B

m7900_last   //

    };

#endif
