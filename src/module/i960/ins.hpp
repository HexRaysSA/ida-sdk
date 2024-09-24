/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum
{
I960_null = 0,          // Unknown Operation

I960_addc,              // Add ordinal with carry
I960_addi,              // Add integer
I960_addo,              // Add ordinal
I960_alterbit,          // Alter bit
I960_and,               // Src2 AND src1
I960_andnot,            // Src2 AND (NOT src1)
I960_atadd,             // Atomic add
I960_atmod,             // Atomic modify
I960_b,                 // Branch
I960_bal,               // Branch and Link
I960_balx,              // Branch and Link Extended
I960_bbc,               // Check bit and branch if clear
I960_bbs,               // Check bit and branch if set
I960_bno,               // Branch if unordered/false
I960_bg,                // Branch if greater
I960_be,                // Branch if equal/true
I960_bge,               // Branch if greater or equal
I960_bl,                // Branch if less
I960_bne,               // Branch if not equal
I960_ble,               // Branch if less or equal
I960_bo,                // Branch if ordered
I960_bx,                // Branch Extended
I960_call,              // Call
I960_calls,             // Call system
I960_callx,             // Call extended
I960_chkbit,            // Check bit
I960_clrbit,            // Clear bit
I960_cmpdeci,           // Compare and decrement integer
I960_cmpdeco,           // Compare and decrement ordinal
I960_cmpi,              // Compare integer
I960_cmpibno,           // Compare integer and branch if unordered
I960_cmpibg,            // Compare integer and branch if greater
I960_cmpibe,            // Compare integer and branch if equal
I960_cmpibge,           // Compare integer and branch if greater or equal
I960_cmpibl,            // Compare integer and branch if less
I960_cmpibne,           // Compare integer and branch if not equal
I960_cmpible,           // Compare integer and branch if less or equal
I960_cmpibo,            // Compare integer and branch if ordered
I960_cmpinci,           // Compare and increment integer
I960_cmpinco,           // Compare and increment ordinal
I960_cmpo,              // Compare ordinal
I960_cmpobg,            // Compare ordinal and branch if greater
I960_cmpobe,            // Compare ordinal and branch if equal
I960_cmpobge,           // Compare ordinal and branch if greater or equal
I960_cmpobl,            // Compare ordinal and branch if less
I960_cmpobne,           // Compare ordinal and branch if not equal
I960_cmpoble,           // Compare ordinal and branch if less or equal
I960_concmpi,           // Conditional compare integer
I960_concmpo,           // Conditional compare ordinal
I960_divi,              // Divide integer
I960_divo,              // Divide ordinal
I960_ediv,              // Extended divide
I960_emul,              // Extended multiply
I960_eshro,             // Extended shift right ordinal
I960_extract,           // Extract
I960_faultno,           // Fault if unordered
I960_faultg,            // Fault if greater
I960_faulte,            // Fault if equal
I960_faultge,           // Fault if greater or equal
I960_faultl,            // Fault if less
I960_faultne,           // Fault if not equal
I960_faultle,           // Fault if less or equal
I960_faulto,            // Fault if ordered
I960_flushreg,          // Flush cached local register sets to memory
I960_fmark,             // Force mark
I960_ld,                // Load word
I960_lda,               // Load address
I960_ldib,              // Load integer byte
I960_ldis,              // Load integer short
I960_ldl,               // Load long
I960_ldob,              // Load ordinal byte
I960_ldos,              // Load ordinal short
I960_ldq,               // Load quad
I960_ldt,               // Load triple
I960_mark,              // Mark
I960_modac,             // Modify the AC register
I960_modi,              // Modulo integer
I960_modify,            // Modify
I960_modpc,             // Modify the process controls register
I960_modtc,             // Modify trace controls
I960_mov,               // Move word
I960_movl,              // Move long word
I960_movq,              // Move quad word
I960_movt,              // Move triple word
I960_muli,              // Multiply integer
I960_mulo,              // Multiply ordinal
I960_nand,              // NOT (src2 AND src1)
I960_nor,               // NOT (src2 OR src1)
I960_not,               // NOT src1
I960_notand,            // (NOT src2) AND src1
I960_notbit,            // Not bit
I960_notor,             // (NOT src2) or src1
I960_or,                // Src2 OR src1
I960_ornot,             // Src2 or (NOT src1)
I960_remi,              // Remainder integer
I960_remo,              // Remainder ordinal
I960_ret,               // Return
I960_rotate,            // Rotate left
I960_scanbit,           // Scan for bit
I960_scanbyte,          // Scan byte equal
I960_setbit,            // Set bit
I960_shli,              // Shift left integer
I960_shlo,              // Shift left ordinal
I960_shrdi,             // Shift right dividing integer
I960_shri,              // Shift right integer
I960_shro,              // Shift right ordinal
I960_spanbit,           // Span over bit
I960_st,                // Store word
I960_stib,              // Store integer byte
I960_stis,              // Store integer short
I960_stl,               // Store long
I960_stob,              // Store ordinal byte
I960_stos,              // Store ordinal short
I960_stq,               // Store quad
I960_stt,               // Store triple
I960_subc,              // Subtract ordinal with carry
I960_subi,              // Subtract integer
I960_subo,              // Subtract ordinal
I960_syncf,             // Synchronize faults
I960_testno,            // Test for unordered
I960_testg,             // Test for greater
I960_teste,             // Test for equal
I960_testge,            // Test for greater or equal
I960_testl,             // Test for less
I960_testne,            // Test for not equal
I960_testle,            // Test for less or equal
I960_testo,             // Test for ordered
I960_xnor,              // Src2 XNOR src1
I960_xor,               // Src2 XOR src1

// Cx instructions

I960_sdma,              // Set up a DMA controller channel
I960_sysctl,            // Perform system control function
I960_udma,              // Copy current DMA pointers to internal data RAM

// Unknown instructions

I960_dcinva,
I960_cmpob,
I960_cmpib,
I960_cmpos,
I960_cmpis,
I960_bswap,
I960_intdis,
I960_inten,
I960_synmov,
I960_synmovl,
I960_synmovq,
I960_cmpstr,
I960_movqstr,
I960_movstr,
I960_inspacc,
I960_ldphy,
I960_synld,
I960_fill,
I960_daddc,
I960_dsubc,
I960_dmovt,
I960_condrec,
I960_receive,
I960_intctl,
I960_icctl,
I960_dcctl,
I960_halt,
I960_send,
I960_sendserv,
I960_resumprcs,
I960_schedprcs,
I960_saveprcs,
I960_condwait,
I960_wait,
I960_signal,
I960_ldtime,
I960_addono,
I960_addino,
I960_subono,
I960_subino,
I960_selno,
I960_addog,
I960_addig,
I960_subog,
I960_subig,
I960_selg,
I960_addoe,
I960_addie,
I960_suboe,
I960_subie,
I960_sele,
I960_addoge,
I960_addige,
I960_suboge,
I960_subige,
I960_selge,
I960_addol,
I960_addil,
I960_subol,
I960_subil,
I960_sell,
I960_addone,
I960_addine,
I960_subone,
I960_subine,
I960_selne,
I960_addole,
I960_addile,
I960_subole,
I960_subile,
I960_selle,
I960_addoo,
I960_addio,
I960_suboo,
I960_subio,
I960_selo,

// Floating point instructions

I960_faddr, I960_fp_first = I960_faddr,
I960_faddrl,
I960_fatanr,
I960_fatanrl,
I960_fclassr,
I960_fclassrl,
I960_fcmpor,
I960_fcmporl,
I960_fcmpr,
I960_fcmprl,
I960_fcosr,
I960_fcosrl,
I960_fcpyrsre,
I960_fcpysre,
I960_fcvtilr,
I960_fcvtir,
I960_fcvtri,
I960_fcvtril,
I960_fcvtzri,
I960_fcvtzril,
I960_fdivr,
I960_fdivrl,
I960_fexpr,
I960_fexprl,
I960_flogbnr,
I960_flogbnrl,
I960_flogepr,
I960_flogeprl,
I960_flogr,
I960_flogrl,
I960_fmovr,
I960_fmovre,
I960_fmovrl,
I960_fmulr,
I960_fmulrl,
I960_fremr,
I960_fremrl,
I960_froundr,
I960_froundrl,
I960_fscaler,
I960_fscalerl,
I960_fsinr,
I960_fsinrl,
I960_fsqrtr,
I960_fsqrtrl,
I960_fsubr,
I960_fsubrl,
I960_ftanr,
I960_ftanrl, I960_fp_last = I960_ftanrl,

I960_last,

    };

#endif
