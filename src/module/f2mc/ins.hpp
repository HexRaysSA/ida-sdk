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

F2MC_null = 0,     // Unknown Operation

// TRANSFER INSTRUCTIONS

F2MC_mov,          // Move  byte data from source to destination
F2MC_movn,         // Move immediate nibble data to A
F2MC_movx,         // Move byte data with sign extension from source to A
F2MC_xch,          // Exchange byte data of source to destination
F2MC_movw,         // Move word data from source to destination
F2MC_xchw,         // Exchange word data of source to destination
F2MC_movl,         // Move long word data from source to destination

// NUMERIC DATA OPERATIONS INSTRUCTIONS

F2MC_add,          // Add byte data of destination and source to destination
F2MC_addc1,        // Add byte data of AL and AH with Carry to AL
F2MC_addc2,        // Add byte data of A and effective address with Carry to A
F2MC_adddc,        // Add decimal data of AL and AH with Carry to AL
F2MC_sub,          // Subtract byte data of source from festination to destination
F2MC_subc1,        // Subtract byte data of AL from AH with Carry to AL
F2MC_subc2,        // Subtract byte data of effective address from A with Carry to A
F2MC_subdc,        // Subtract decimal data of AL from AH with Carry to AL
F2MC_addw1,        // Add word data of AH and AL to AL
F2MC_addw2,        // Add word data of destination and source to destination
F2MC_addcw,        // Add word data of A and effective address from A with Carry to A
F2MC_subw1,        // Subtract word data of AL from AH to AL
F2MC_subw2,        // Subtract word data of source from festination to destination
F2MC_subcw,        // Subtract word data of A and effective address from A with carry to A
F2MC_addl,         // Add long word data of destination and source to destination
F2MC_subl,         // Subtract long word data of source from festination to destination
F2MC_inc,          // Increment byte data
F2MC_dec,          // Decrement byte data
F2MC_incw,         // Increment word data
F2MC_decw,         // Decrement word data
F2MC_incl,         // Increment long word data
F2MC_decl,         // Decrement long word data
F2MC_cmp1,         // Compare byte data of AH and AL
F2MC_cmp2,         // Compare byte data of destination and source
F2MC_cmpw1,        // Compare word data of AH and AL
F2MC_cmpw2,        // Compare word data of destination and source
F2MC_cmpl,         // Compare long word data of destination and source
F2MC_divu1,        // Divide unsigned AH by AL
F2MC_divu2,        // Divide unsigned word data by unsigned byte data
F2MC_divuw,        // Divide unsigned long word data by unsigned word data
F2MC_mulu1,        // Multiply unsigned byte AH by AL
F2MC_mulu2,        // Multiply unsigned byte data
F2MC_muluw1,       // Multiply unsigned word AH by AL
F2MC_muluw2,       // Multiply unsigned word data
F2MC_div1,         // Divide AH by AL
F2MC_div2,         // Divide word data by byte data
F2MC_divw,         // Divide long word data by word data
F2MC_mul1,         // Multiply byte AH by AL
F2MC_mul2,         // Multiply byte data
F2MC_mulw1,        // Multiply word AH by AL
F2MC_mulw2,        // Multiply word data

// LOGICAL DATA OPERATION INSTRUCTIONS

F2MC_and,          // And byte data of destination and source to destination
F2MC_or,           // Or byte data of destination and source to destination
F2MC_xor,          // Exclusive or byte data of destination and source to destination
F2MC_not,          // Not byte data of destination
F2MC_andw1,        // And word data of AH and AL to AL
F2MC_andw2,        // And word data of destination and source to destination
F2MC_orw1,         // Or word data of AH and AL to AL
F2MC_orw2,         // Or word data of destination and source to destination
F2MC_xorw1,        // Exclusive or word data of AH and AL to AL
F2MC_xorw2,        // Exclusive or word data of destination and source to destination
F2MC_notw,         // Not word data of destination
F2MC_andl,         // And long word data of destination and source to destination
F2MC_orl,          // Or long word data of destination and source to destination
F2MC_xorl,         // Exclusive or long word data of destination and source to destination
F2MC_neg,          // Negate byte data of destination
F2MC_negw,         // Negate word data of destination
F2MC_nrml,         // Normalize long word

// SHIFT INSTRUCTIONS

F2MC_rorc,         // Rotate byte data of A with Carry to right
F2MC_rolc,         // Rotate byte data of A with Carry to left
F2MC_asr,          // Arithmetic shift byte data of A to right
F2MC_lsr,          // Logical shift byte data of A to right
F2MC_lsl,          // Logical shift byte data of A to left
F2MC_asrw1,        // Arithmetic shift word data of A to right
F2MC_asrw2,        // Arithmetic shift word data of A to right
F2MC_lsrw1,        // Logical shift word data of A to right
F2MC_lsrw2,        // Logical shift word data of A to right
F2MC_lslw1,        // Logical shift word data of A to left
F2MC_lslw2,        // Logical shift word data of A to left
F2MC_asrl,         // Arithmetic shift long word data of A to right
F2MC_lsrl,         // Logical shift long word data of A to right
F2MC_lsll,         // Logical shift long word data of A to left

// BRANCH INSTRUCTIONS

F2MC_bz,           // Branch if Zero
F2MC_bnz,          // Branch if Not Zero
F2MC_bc,           // Branch if Carry
F2MC_bnc,          // Branch if Not Carry
F2MC_bn,           // Branch if Negative
F2MC_bp,           // Branch if Not Negative
F2MC_bv,           // Branch if Overflow
F2MC_bnv,          // Branch if Not Overflow
F2MC_bt,           // Branch if Sticky
F2MC_bnt,          // Branch if Not Sticky
F2MC_blt,          // Branch if Overflow or Negative
F2MC_bge,          // Branch if Not (Overflow or Negative)
F2MC_ble,          // Branch if (Overflow xor Negative) or Zero
F2MC_bgt,          // Branch if Not ((Overflow xor Negative) or Zero)
F2MC_bls,          // Branch if Carry or Zero
F2MC_bhi,          // Branch if Not (Carry or Zero)
F2MC_bra,          // Branch unconditionally
F2MC_jmp,          // Jump destination address
F2MC_jmpp,         // Jump destination physical address
F2MC_call,         // Call subroutine
F2MC_callv,        // Call vectored subroutine
F2MC_callp,        // Call physical address
F2MC_cbne,         // Compare byte data and branch if not Equal
F2MC_cwbne,        // Compare word data and branch if not Equal
F2MC_dbnz,         // Decrement byte data and branch if not Zero
F2MC_dwbnz,        // Decrement word data and branch if not Zero
F2MC_int,          // Software interrupt
F2MC_intp,         // Software interrupt
F2MC_int9,         // Software interrupt
F2MC_reti,         // Return from interrupt
F2MC_link,         // Link and create new stack frame
F2MC_unlink,       // Unlink and create new stack frame
F2MC_ret,          // Return from subroutine
F2MC_retp,         // Return from physical address

// OTHER INSTRUCTIONS

F2MC_pushw,        // Push to stack memory
F2MC_popw,         // Pop from stack memory
F2MC_jctx,         // Jump context
// F2MC_and,
// F2MC_or,
// F2MC_mov,
F2MC_movea,        // Move effective address to destination
F2MC_addsp,        // Add word data of SP and immediate data to SP
// F2MC_mov,
F2MC_nop,          // No operation
F2MC_adb,          // ADB register
F2MC_dtb,          // DTB register
F2MC_pcb,          // PCB register
F2MC_spb,          // SPB register
F2MC_ncc,          // Flag change inhibit
F2MC_cmr,          // Common register bank
F2MC_movb,         // Move bit data
F2MC_setb,         // Set bit
F2MC_clrb,         // Clear bit
F2MC_bbc,          // Branch if bit condition satisfied
F2MC_bbs,          // Branch if bit condition satisfied
F2MC_sbbs,         // Set bit and branch if bit set
F2MC_wbts,         // Wait until bit condition satisfied
F2MC_wbtc,         // Wait until bit condition satisfied
F2MC_swap,         // Swap byte data of A
F2MC_swapw,        // Swap word data of A
F2MC_ext,          // Sign extend from byte data to word data
F2MC_extw,         // Sign extend from word data to long word data
F2MC_zext,         // Zero extendfrom byte data to word data
F2MC_zextw,        // Zero extendfrom word data to long word data
F2MC_movsi,        // Move string byte with addresses incremented
F2MC_movsd,        // Move string byte with addresses decremented
F2MC_sceqi,        // Scan string byte until Equal with address incremented
F2MC_sceqd,        // Scan string byte until Equal with address decremented
F2MC_filsi,        // Fill string byte
F2MC_movswi,       // Move string word with address incremented
F2MC_movswd,       // Move string word with address decremented
F2MC_scweqi,       // Scan string word until Equal with address incremented
F2MC_scweqd,       // Scan string word until Equal with address decremented
F2MC_filswi,       // Fill string word

// MACROS

F2MC_bz16,         // Branch if Zero
F2MC_bnz16,        // Branch if Not Zero
F2MC_bc16,         // Branch if Carry
F2MC_bnc16,        // Branch if Not Carry
F2MC_bn16,         // Branch if Negative
F2MC_bp16,         // Branch if Not Negative
F2MC_bv16,         // Branch if Overflow
F2MC_bnv16,        // Branch if Not Overflow
F2MC_bt16,         // Branch if Sticky
F2MC_bnt16,        // Branch if Not Sticky
F2MC_blt16,        // Branch if Overflow or Negative
F2MC_bge16,        // Branch if Not (Overflow or Negative)
F2MC_ble16,        // Branch if (Overflow xor Negative) or Zero
F2MC_bgt16,        // Branch if Not ((Overflow xor Negative) or Zero)
F2MC_bls16,        // Branch if Carry or Zero
F2MC_bhi16,        // Branch if Not (Carry or Zero)

F2MC_cbne16,       // Compare byte data and branch if not Equal
F2MC_cwbne16,      // Compare word data and branch if not Equal

F2MC_dbnz16,       // Decrement byte data and branch if not Zero
F2MC_dwbnz16,      // Decrement word data and branch if not Zero

F2MC_bbc16,        // Branch if bit condition satisfied
F2MC_bbs16,        // Branch if bit condition satisfied
F2MC_sbbs16,       // Set bit and branch if bit set

F2MC_last,

};

#endif
