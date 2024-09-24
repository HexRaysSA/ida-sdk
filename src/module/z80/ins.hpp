/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
I5_null = 0,            // Unknown Operation

//
//      Intel 8080-8085 instructions
//

I5_aci,
I5_adc, Z80_adc = I5_adc,
I5_add, Z80_add = I5_add,
I5_adi,
I5_ana,
I5_ani,
I5_call,
I5_cnz,
I5_cz,
I5_cnc,
I5_cc,
I5_cpo,
I5_cpe,
I5_cp,
I5_cm,
I5_cmc,
I5_cmp,
I5_cpi,
I5_cma,
I5_daa,
I5_dad,
I5_dcr,
I5_dcx,
I5_di, Z80_di = I5_di,
I5_ei, Z80_ei = I5_ei,
I5_halt,
I5_in, Z80_in = I5_in,
I5_inr,
I5_inx,
I5_jmp,
I5_jnz,
I5_jz,
I5_jnc,
I5_jc,
I5_jpo,
I5_jpe,
I5_jp,
I5_jm,
I5_lda,
I5_ldax,
I5_lhld,
I5_lxi,
I5_mov,
I5_mvi,
I5_nop,
I5_ora,
I5_ori,
I5_out, Z80_out = I5_out,
I5_pchl,
I5_pop, Z80_pop = I5_pop,
I5_push, Z80_push = I5_push,
I5_ret,
I5_rnz,
I5_rz,
I5_rnc,
I5_rc,
I5_rpo,
I5_rpe,
I5_rp,
I5_rm,
I5_ral,
I5_rlc,
I5_rar,
I5_rrc,
I5_rst,
I5_sbb,
I5_sbi,
I5_stc,
I5_sphl,
I5_sta,
I5_stax,
I5_shld,
I5_sui,
I5_sub, Z80_sub = I5_sub,
I5_xra,
I5_xri,
I5_xchg,
I5_xthl,

I5_rim,
I5_sim,

//
//      Z80 extensions
//

Z80_and,
Z80_bit,
Z80_call,
Z80_ccf,
Z80_cp,
Z80_cpd,
Z80_cpdr,
Z80_cpi,
Z80_cpir,
Z80_cpl,
Z80_dec,
Z80_djnz,
Z80_ex,
Z80_exx,
Z80_halt,
Z80_im,
Z80_inc,
Z80_ind,
Z80_indr,
Z80_ini,
Z80_inir,
Z80_jp,
Z80_jr,
Z80_ld,
Z80_ldd,
Z80_lddr,
Z80_ldi,
Z80_ldir,
Z80_neg,
Z80_or,
Z80_otdr,
Z80_otir,
Z80_outd,
Z80_outi,
Z80_res,
Z80_ret,
Z80_reti,
Z80_retn,
Z80_rl,
Z80_rla,
Z80_rlc,
Z80_rlca,
Z80_rld,
Z80_rr,
Z80_rra,
Z80_rrc,
Z80_rrca,
Z80_rrd,
Z80_scf,
Z80_sbc,
Z80_set,
Z80_sla,
Z80_sra,
Z80_srl,
Z80_xor,
Z80_inp,                // undocumented
Z80_outp,               // undocumented
Z80_srr,                // undocumented

//
//      HD64180 extensions
//

HD_in0,   Z80_in0   = HD_in0,
HD_mlt,   Z80_mlt   = HD_mlt,
HD_otim,  Z80_otim  = HD_otim,
HD_otimr, Z80_otimr = HD_otimr,
HD_otdm,  Z80_otdm  = HD_otdm,
HD_otdmr, Z80_otdmr = HD_otdmr,
HD_out0,  Z80_out0  = HD_out0,
HD_slp,   Z80_slp   = HD_slp,
HD_tst,   Z80_tst   = HD_tst,
HD_tstio, Z80_tstio = HD_tstio,

//
//      A80 special instructions
//

A80_lbcd,
A80_lded,
A80_lspd,
A80_lixd,
A80_liyd,
A80_sbcd,
A80_sded,
A80_sspd,
A80_sixd,
A80_siyd,
A80_xtix,
A80_xtiy,
A80_spix,
A80_spiy,
A80_pcix,
A80_pciy,
A80_mvra,
A80_mvia,
A80_mvar,
A80_mvai,
A80_addix,
A80_addiy,
A80_addc,
A80_addcix,
A80_addciy,
A80_subc,
A80_subcix,
A80_subciy,
A80_jrc,
A80_jrnc,
A80_jrz,
A80_jrnz,
A80_cmpi,
A80_cmpd,
A80_im0,
A80_im1,
A80_im2,
A80_otd,
A80_oti,

// Intel 8085 undocumented instructions
// (info from http://oak.oakland.edu/pub/cpm/maclib/i8085.lib)

I5_dsub,        // (HL) <- (HL)-(BC), affects all flags
I5_arhl,        // SHIFT HL RIGHT ONE BIT, (H7 IS DUPLICATED, L0 IS SHIFTED INTO CY)
I5_rdel,        // ROTATE DE LEFT ONE BIT THRU CY, (E0 RECEIVES CY, CY RECEIVES D7)
I5_ldhi,        // (DE) <- (HL)+arg
I5_ldsi,        // (DE) <- (SP)+arg
I5_shlx,        // ((DE)) <- (HL)
I5_lhlx,        // (HL) <- ((DE))
I5_rstv,        // RESTART 40H ON V (OVERFLOW)
I5_jx5,         // JUMP IF X5 SET
I5_jnx5,        // JUMP IF NOT X5 SET

// Z380 instructions

Z80_cplw,       // Complement HL register
Z80_swap,       // Swap upper register word with lower register word
Z80_inw,        // Input word
Z80_outw,       // Output word
Z80_ldw,        // Load word
Z80_addw,       // Add word
Z80_subw,       // Subtract word
Z80_adcw,       // Add with carry word
Z80_sbcw,       // Subtract with borrow word
Z80_andw,       // AND logical word
Z80_xorw,       // XOR logical word
Z80_orw,        // OR logical word
Z80_cpw,        // Compare word
Z80_ddir,       // Decoder directive
Z80_calr,       // Call relative
Z80_ldctl,      // Load control register
Z80_mtest,      // Mode test
Z80_exxx,       // Exchange Index Register with Alternate Bank
Z80_exxy,       // Exchange Index Register with Alternate Bank
Z80_exall,      // Exchange all registers with Alternate Bank
Z80_setc,       // Set control bit
Z80_resc,       // Reset control bit
Z80_rlcw,       // Rotate Left Circular Word
Z80_rrcw,       // Rotate Right Circular Word
Z80_rlw,        // Rotate Left Word
Z80_rrw,        // Rotate Right Word
Z80_slaw,       // Shift Left Arithmetic Word
Z80_sraw,       // Shift Right Arithmetic Word
Z80_srlw,       // Shift Right Logical Word
Z80_multw,      // Multiply Word
Z80_multuw,     // Multiply Word Unsigned
Z80_divuw,      // Divide unsigned
Z80_outaw,      // Output word direct to port address
Z80_inaw,       // Input word direct from port address
Z80_outa,       // Output byte direct to port address
Z80_ina,        // Input byte direct from port address
Z80_negw,       // Negate word
Z80_exts,       // Extend byte sign
Z80_extsw,      // Extend word sign
Z80_btest,      // Bank test
Z80_ldiw,       // Load and increment (word)
Z80_ldirw,      // Load and increment, repeat (word)
Z80_lddw,       // Load and decrement (word)
Z80_lddrw,      // Load and decrement, repeat (word)
Z80_iniw,       // Input and increment (word)
Z80_inirw,      // Input and increment, repeat (word)
Z80_indw,       // Input and decrement (word)
Z80_indrw,      // Input and decrement, repeat (word)
Z80_outiw,      // Output and increment (word)
Z80_otirw,      // Output and increment, repeat (word)
Z80_outdw,      // Output and decrement (word)
Z80_otdrw,      // Output and decrement, repeat (word)

// Gameboy instructions

GB_ldh,
GB_stop,

I5_last,

    };

#endif
