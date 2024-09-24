/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "f2mc.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  // TRANSFER INSTRUCTIONS

  { "mov",        CF_CHG1|CF_USE2                 },      // Move  byte data from source to destination
  { "movn",       CF_CHG1|CF_USE2                 },      // Move immediate nibble data to A
  { "movx",       CF_CHG1|CF_USE2                 },      // Move byte data with sign extension from source to A
  { "xch",        CF_CHG1|CF_CHG2                 },      // Exchange byte data of source to destination
  { "movw",       CF_CHG1|CF_USE2                 },      // Move word data from source to destination
  { "xchw",       CF_CHG1|CF_CHG2                 },      // Exchange word data of source to destination
  { "movl",       CF_CHG1|CF_USE2                 },      // Move long word data from source to destination

  // NUMERIC DATA OPERATIONS INSTRUCTIONS

  { "add",        CF_CHG1|CF_USE2                 },      // Add byte data of destination and source to destination
  { "addc",       CF_CHG1                         },      // Add byte data of AL and AH with Carry to AL
  { "addc",       CF_CHG1|CF_USE2                 },      // Add byte data of A and effective address with Carry to A
  { "adddc",      CF_CHG1                         },      // Add decimal data of AL and AH with Carry to AL
  { "sub",        CF_CHG1|CF_USE2                 },      // Subtract byte data of source from festination to destination
  { "subc",       CF_CHG1                         },      // Subtract byte data of AL from AH with Carry to AL
  { "subc",       CF_CHG1|CF_USE2                 },      // Subtract byte data of effective address from A with Carry to A
  { "subdc",      CF_CHG1                         },      // Subtract decimal data of AL from AH with Carry to AL
  { "addw",       CF_CHG1                         },      // Add word data of AH and AL to AL
  { "addw",       CF_CHG1|CF_USE2                 },      // Add word data of destination and source to destination
  { "addcw",      CF_CHG1                         },      // Add word data of A and effective address from A with Carry to A
  { "subw",       CF_CHG1                         },      // Subtract word data of AL from AH to AL
  { "subw",       CF_CHG1|CF_USE2                 },      // Subtract word data of source from festination to destination
  { "subcw",      CF_CHG1                         },      // Subtract word data of A and effective address from A with carry to A
  { "addl",       CF_CHG1|CF_USE2                 },      // Add long word data of destination and source to destination
  { "subl",       CF_CHG1|CF_USE2                 },      // Subtract long word data of source from festination to destination
  { "inc",        CF_CHG1                         },      // Increment byte data
  { "dec",        CF_CHG1                         },      // Decrement byte data
  { "incw",       CF_CHG1                         },      // Increment word data
  { "decw",       CF_CHG1                         },      // Decrement word data
  { "incl",       CF_CHG1                         },      // Increment long word data
  { "decl",       CF_CHG1                         },      // Decrement long word data
  { "cmp",        CF_USE1                         },      // Compare byte data of AH and AL
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare byte data of destination and source
  { "cmpw",       CF_USE1                         },      // Compare word data of AH and AL
  { "cmpw",       CF_USE1|CF_USE2                 },      // Compare word data of destination and source
  { "cmpl",       CF_USE1|CF_USE2                 },      // Compare long word data of destination and source
  { "divu",       CF_CHG1                         },      // Divide AH by AL
  { "divu",       CF_CHG1|CF_CHG2                 },      // Divide unsigned word data by unsigned byte data
  { "divuw",      CF_CHG1|CF_CHG2                 },      // Divide unsigned long word data by unsigned word data
  { "mulu",       CF_CHG1                         },      // Multiply unsigned byte AH by AL
  { "mulu",       CF_CHG1|CF_USE2                 },      // Multiply unsigned byte data
  { "muluw",      CF_CHG1                         },      // Multiply unsigned word AH by AL
  { "muluw",      CF_CHG1|CF_USE2                 },      // Multiply unsigned word data
  { "div",        CF_CHG1                         },      // Divide word data by byte data
  { "div",        CF_CHG1|CF_CHG2                 },      // Divide word data by byte data
  { "divw",       CF_CHG1|CF_CHG2                 },      // Divide long word data by word data
  { "mul",        CF_CHG1                         },      // Multiply byte AH by AL
  { "mul",        CF_CHG1|CF_USE2                 },      // Multiply byte data
  { "mulw",       CF_CHG1                         },      // Multiply word AH by AL
  { "mulw",       CF_CHG1|CF_USE2                 },      // Multiply word data

  // LOGICAL DATA OPERATION INSTRUCTIONS

  { "and",        CF_CHG1|CF_USE2                 },      // And byte data of destination and source to destination
  { "or",         CF_CHG1|CF_USE2                 },      // Or byte data of destination and source to destination
  { "xor",        CF_CHG1|CF_USE2                 },      // Exclusive or byte data of destination and source to destination
  { "not",        CF_CHG1                         },      // Not byte data of destination
  { "andw",       CF_CHG1                         },      // And word data of AH and AL to AL
  { "andw",       CF_CHG1|CF_USE2                 },      // And word data of destination and source to destination
  { "orw",        CF_CHG1                         },      // Or word data of AH and AL to AL
  { "orw",        CF_CHG1|CF_USE2                 },      // Or word data of destination and source to destination
  { "xorw",       CF_CHG1                         },      // Exclusive or word data of AH and AL to AL
  { "xorw",       CF_CHG1|CF_USE2                 },      // Exclusive or word data of destination and source to destination
  { "notw",       CF_CHG1                         },      // Not word data of destination
  { "andl",       CF_CHG1|CF_USE2                 },      // And long word data of destination and source to destination
  { "orl",        CF_CHG1|CF_USE2                 },      // Or long word data of destination and source to destination
  { "xorl",       CF_CHG1|CF_USE2                 },      // Exclusive or long word data of destination and source to destination
  { "neg",        CF_CHG1                         },      // Negate byte data of destination
  { "negw",       CF_CHG1                         },      // Negate word data of destination
  { "nrml",       CF_CHG1|CF_CHG2                 },      // Normalize long word

  // SHIFT INSTRUCTIONS

  { "rorc",       CF_CHG1                         },      // Rotate byte data of A with Carry to right
  { "rolc",       CF_CHG1                         },      // Rotate byte data of A with Carry to left
  { "asr",        CF_CHG1|CF_USE2                 },      // Arithmetic shift byte data of A to right
  { "lsr",        CF_CHG1|CF_USE2                 },      // Logical shift byte data of A to right
  { "lsl",        CF_CHG1|CF_USE2                 },      // Logical shift byte data of A to left
  { "asrw",       CF_CHG1                         },      // Arithmetic shift word data of A to right
  { "asrw",       CF_CHG1|CF_USE2                 },      // Arithmetic shift word data of A to right
  { "lsrw",       CF_CHG1                         },      // Logical shift word data of A to right
  { "lsrw",       CF_CHG1|CF_USE2                 },      // Logical shift word data of A to right
  { "lslw",       CF_CHG1                         },      // Logical shift word data of A to left
  { "lslw",       CF_CHG1|CF_USE2                 },      // Logical shift word data of A to left
  { "asrl",       CF_CHG1|CF_USE2                 },      // Arithmetic shift long word data of A to right
  { "lsrl",       CF_CHG1|CF_USE2                 },      // Logical shift long word data of A to right
  { "lsll",       CF_CHG1|CF_USE2                 },      // Logical shift long word data of A to left

  // BRANCH INSTRUCTIONS

  { "bz",         CF_USE1                         },      // Branch if Zero
  { "bnz",        CF_USE1                         },      // Branch if Not Zero
  { "bc",         CF_USE1                         },      // Branch if Carry
  { "bnc",        CF_USE1                         },      // Branch if Not Carry
  { "bn",         CF_USE1                         },      // Branch if Negative
  { "bp",         CF_USE1                         },      // Branch if Not Negative
  { "bv",         CF_USE1                         },      // Branch if Overflow
  { "bnv",        CF_USE1                         },      // Branch if Not Overflow
  { "bt",         CF_USE1                         },      // Branch if Sticky
  { "bnt",        CF_USE1                         },      // Branch if Not Sticky
  { "blt",        CF_USE1                         },      // Branch if Overflow or Negative
  { "bge",        CF_USE1                         },      // Branch if Not (Overflow or Negative)
  { "ble",        CF_USE1                         },      // Branch if ( Overflow xor Negative ) or Zero
  { "bgt",        CF_USE1                         },      // Branch if Not ((Overflow xor Negative) or Zero)
  { "bls",        CF_USE1                         },      // Branch if Carry or Zero
  { "bhi",        CF_USE1                         },      // Branch if Not (Carry or Zero)
  { "bra",        CF_USE1|CF_STOP                 },      // Branch unconditionally
  { "jmp",        CF_USE1|CF_STOP                 },      // Jump destination address
  { "jmpp",       CF_USE1|CF_STOP                 },      // Jump destination physical address
  { "call",       CF_USE1|CF_CALL                 },      // Call subroutine
  { "callv",      CF_USE1|CF_CALL                 },      // Call vectored subroutine
  { "callp",      CF_USE1|CF_CALL                 },      // Call physical address
  { "cbne",       CF_USE1|CF_USE2|CF_USE3         },      // Compare byte data and branch if not Equal
  { "cwbne",      CF_USE1|CF_USE2|CF_USE3         },      // Compare word data and branch if not Equal
  { "dbnz",       CF_CHG1|CF_USE2                 },      // Decrement byte data and branch if not Zero
  { "dwbnz",      CF_CHG1|CF_USE2                 },      // Decrement word data and branch if not Zero
  { "int",        CF_USE1|CF_CALL                 },      // Software interrupt
  { "intp",       CF_USE1|CF_CALL                 },      // Software interrupt
  { "int9",       CF_CALL                         },      // Software interrupt
  { "reti",       CF_STOP                         },      // Return from interrupt
  { "link",       CF_USE1                         },      // Link and create new stack frame
  { "unlink",     0                               },      // Unlink and create new stack frame
  { "ret",        CF_STOP                         },      // Return from subroutine
  { "retp",       CF_STOP                         },      // Return from physical address

  // OTHER INSTRUCTIONS

  { "pushw",      CF_USE1                         },      // Push to stack memory
  { "popw",       CF_CHG1                         },      // Pop from stack memory
  { "jctx",       CF_USE1|CF_STOP                 },      // Jump context
  // F2MC_and,
  // F2MC_or,
  // F2MC_mov,
  { "movea",      CF_CHG1|CF_USE2                 },      // Move effective address to destination
  { "addsp",      CF_USE1                         },      // Add word data of SP and immediate data to SP
  // F2MC_mov,
  { "nop",        0                               },      // No operation
  { "adb",        0                               },      // ADB register
  { "dtb",        0                               },      // DTB register
  { "pcb",        0                               },      // PCB register
  { "spb",        0                               },      // SPB register
  { "ncc",        0                               },      // Flag change inhibit
  { "cmr",        0                               },      // Common register bank
  { "movb",       CF_CHG1|CF_USE2                 },      // Move bit data
  { "setb",       CF_CHG1                         },      // Set bit
  { "clrb",       CF_CHG1                         },      // Clear bit
  { "bbc",        CF_USE1|CF_USE2                 },      // Branch if bit condition satisfied
  { "bbs",        CF_USE1|CF_USE2                 },      // Branch if bit condition satisfied
  { "sbbs",       CF_USE1|CF_USE2                 },      // Set bit and branch if bit set
  { "wbts",       CF_USE1                         },      // Wait until bit condition satisfied
  { "wbtc",       CF_USE1                         },      // Wait until bit condition satisfied
  { "swap",       0                               },      // Swap byte data of A
  { "swapw",      0                               },      // Swap word data of A
  { "ext",        0                               },      // Sign extend from byte data to word data
  { "extw",       0                               },      // Sign extend from word data to long word data
  { "zext",       0                               },      // Zero extendfrom byte data to word data
  { "zextw",      0                               },      // Zero extendfrom word data to long word data
  { "movsi",      CF_USE1|CF_USE2                 },      // Move string byte with addresses incremented
  { "movsd",      CF_USE1|CF_USE2                 },      // Move string byte with addresses decremented
  { "sceqi",      0                               },      // Scan string byte until Equal with address incremented
  { "sceqd",      0                               },      // Scan string byte until Equal with address decremented
  { "filsi",      0                               },      // Fill string byte
  { "movswi",     CF_USE1|CF_USE2                 },      // Move string word with address incremented
  { "movswd",     CF_USE1|CF_USE2                 },      // Move string word with address decremented
  { "scweqi",     0                               },      // Scan string word until Equal with address incremented
  { "scweqd",     0                               },      // Scan string word until Equal with address decremented
  { "filswi",     0                               },      // Fill string word

  // MACROS

  { "bz16",       CF_USE1                         },      // Branch if Zero
  { "bnz16",      CF_USE1                         },      // Branch if Not Zero
  { "bc16",       CF_USE1                         },      // Branch if Carry
  { "bnc16",      CF_USE1                         },      // Branch if Not Carry
  { "bn16",       CF_USE1                         },      // Branch if Negative
  { "bp16",       CF_USE1                         },      // Branch if Not Negative
  { "bv16",       CF_USE1                         },      // Branch if Overflow
  { "bnv16",      CF_USE1                         },      // Branch if Not Overflow
  { "bt16",       CF_USE1                         },      // Branch if Sticky
  { "bnt16",      CF_USE1                         },      // Branch if Not Sticky
  { "blt16",      CF_USE1                         },      // Branch if Overflow or Negative
  { "bge16",      CF_USE1                         },      // Branch if Not (Overflow or Negative)
  { "ble16",      CF_USE1                         },      // Branch if ( Overflow xor Negative ) or Zero
  { "bgt16",      CF_USE1                         },      // Branch if Not ((Overflow xor Negative) or Zero)
  { "bls16",      CF_USE1                         },      // Branch if Carry or Zero
  { "bhi16",      CF_USE1                         },      // Branch if Not (Carry or Zero)

  { "cbne16",     CF_USE1|CF_USE2|CF_USE3         },      // Compare byte data and branch if not Equal
  { "cwbne16",    CF_USE1|CF_USE2|CF_USE3         },      // Compare word data and branch if not Equal

  { "dbnz16",     CF_CHG1|CF_USE2                 },      // Decrement byte data and branch if not Zero
  { "dwbnz16",    CF_CHG1|CF_USE2                 },      // Decrement word data and branch if not Zero

  { "bbc16",      CF_USE1|CF_USE2                 },      // Branch if bit condition satisfied
  { "bbs16",      CF_USE1|CF_USE2                 },      // Branch if bit condition satisfied
  { "sbbs16",     CF_USE1|CF_USE2                 },      // Set bit and branch if bit set

};

CASSERT(qnumber(Instructions) == F2MC_last);
