/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "pic.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  // BYTE-ORIENTED FILE REGISTER OPERATIONS

  { "addwf",      CF_USE1|CF_USE2                 },      // Add W and f
  { "andwf",      CF_USE1|CF_USE2                 },      // AND W with f
  { "clrf",       CF_CHG1                         },      // Clear f
  { "clrw",       0                               },      // Clear W
  { "comf",       CF_USE1|CF_USE2                 },      // Complement f
  { "decf",       CF_USE1|CF_USE2                 },      // Decrement f
  { "decfsz",     CF_USE1|CF_USE2                 },      // Decrement f, Skip if 0
  { "incf",       CF_USE1|CF_USE2                 },      // Increment f
  { "incfsz",     CF_USE1|CF_USE2                 },      // Increment f, Skip if 0
  { "iorwf",      CF_USE1|CF_USE2                 },      // Inclusive OR W with f
  { "movf",       CF_USE1|CF_USE2                 },      // Move f
  { "movwf",      CF_CHG1                         },      // Move W to f
  { "nop",        0                               },      // No Operation
  { "rlf",        CF_USE1|CF_USE2                 },      // Rotate Left f through Carry
  { "rrf",        CF_USE1|CF_USE2                 },      // Rotate Right f through Carry
  { "subwf",      CF_USE1|CF_USE2                 },      // Subtract W from f
  { "swapf",      CF_USE1|CF_USE2                 },      // Swap nibbles in f
  { "xorwf",      CF_USE1|CF_USE2                 },      // Exclusive OR W with f

  // BIT-ORIENTED FILE REGISTER OPERATIONS

  { "bcf",        CF_CHG1|CF_USE2                 },      // Bit Clear f
  { "bsf",        CF_CHG1|CF_USE2                 },      // Bit Set f
  { "btfsc",      CF_USE1|CF_USE2                 },      // Bit Test f, Skip if Clear
  { "btfss",      CF_USE1|CF_USE2                 },      // Bit Test f, Skip if Set

  // LITERAL AND CONTROL OPERATIONS

  { "addlw",      CF_USE1                         },      // Add literal and W
  { "andlw",      CF_USE1                         },      // AND literal with W
  { "call",       CF_USE1|CF_CALL                 },      // Call subroutine
  { "clrwdt",     0                               },      // Clear Watchdog Timer
  { "goto",       CF_USE1|CF_STOP                 },      // Go to address
  { "iorlw",      CF_USE1                         },      // Inclusive OR literal with W
  { "movlw",      CF_USE1                         },      // Move literal to W
  { "retfie",             CF_STOP                 },      // Return from interrupt
  { "retlw",      CF_USE1|CF_STOP                 },      // Return with literal in W
  { "return",             CF_STOP                 },      // Return from Subroutine
  { "sleep",      0                               },      // Go into standby mode
  { "sublw",      CF_USE1                         },      // Subtract W from literal
  { "xorlw",      CF_USE1                         },      // Exclusive OR literal with W

  // ADDITIONAL INSTRUCTIONS TO MAINTAIN COMPITIBILITY WITH 12C5xx,16C5x

  { "option",     0                               },      // Load OPTION register
  { "tris",       CF_USE1                         },      // Load TRIS Register

  // MACROS

  { "movfw",      CF_USE1                         },      // Move Contents of File Reg to W
  { "tstf",       CF_USE1                         },      // Test Contents of File Register
  { "negf",       CF_USE1|CF_USE2                 },      // Negate File Register Contents
  { "b",          CF_USE1|CF_STOP                 },      // Branch to Address
  { "clrc",       0                               },      // Clear Carry
  { "clrdc",      0                               },      // Clear Digit Carry
  { "clrz",       0                               },      // Clear Zero
  { "setc",       0                               },      // Set Carry
  { "setdc",      0                               },      // Set Digit Carry
  { "setz",       0                               },      // Set Zero
  { "skpc",       0                               },      // Skip on Carry
  { "skpdc",      0                               },      // Skip on Digit Carry
  { "skpnc",      0                               },      // Skip on No Carry
  { "skpndc",     0                               },      // Skip on No Digit Carry
  { "skpnz",      0                               },      // Skip on No Zero
  { "skpz",       0                               },      // Skip on Zero
  { "bc",         CF_USE1                         },      // Branch on Carry to Address k
  { "bdc",        CF_USE1                         },      // Branch on Digit Carry to k
  { "bnc",        CF_USE1                         },      // Branch on No Carry to k
  { "bndc",       CF_USE1                         },      // Branch on No Digit Carry to k
  { "bnz",        CF_USE1                         },      // Branch on No Zero to Address
  { "bz",         CF_USE1                         },      // Branch on Zero to Address k
  { "addcf",      CF_USE1|CF_USE2                 },      // Add Carry to File Register
  { "adddcf",     CF_USE1|CF_USE2                 },      // Add Digit to File Register
  { "subcf",      CF_USE1|CF_USE2                 },      // Subtract Carry from File Reg

  // ADDITIONAL INSTRUCTIONS FOR 18Cxx

  // BYTE-ORIENTED FILE REGISTER OPERATIONS

  { "addwf",      CF_USE1|CF_USE2|CF_USE3         },      // Add W and f
  { "addwfc",     CF_USE1|CF_USE2|CF_USE3         },      // Add W and Carry to f
  { "andwf",      CF_USE1|CF_USE2|CF_USE3         },      // AND W with f
  { "clrf",       CF_CHG1|CF_USE2                 },      // Clear f
  { "comf",       CF_CHG1|CF_USE2|CF_USE3         },      // Complement f
  { "cpfseq",     CF_USE1|CF_USE2                 },      // Compare f with W, Skip if ==
  { "cpfsgt",     CF_USE1|CF_USE2                 },      // Compare f with W, Skip if >
  { "cpfslt",     CF_USE1|CF_USE2                 },      // Compare f with W, Skip if <
  { "decf",       CF_CHG1|CF_USE2|CF_USE3         },      // Decrement f
  { "decfsz",     CF_CHG1|CF_USE2|CF_USE3         },      // Decrement f, Skip if 0
  { "dcfsnz",     CF_CHG1|CF_USE2|CF_USE3         },      // Decrement f, Skip if not 0
  { "incf",       CF_CHG1|CF_USE2|CF_USE3         },      // Increment f
  { "incfsz",     CF_CHG1|CF_USE2|CF_USE3         },      // Increment f, Skip if 0
  { "infsnz",     CF_CHG1|CF_USE2|CF_USE3         },      // Increment f, Skip if not 0
  { "iorwf",      CF_USE1|CF_USE2|CF_USE3         },      // Inclusive OR W with f
  { "movf",       CF_USE1|CF_USE2|CF_USE3         },      // Move f
  { "movff",      CF_USE1|CF_CHG2                 },      // Move fs to fd
  { "movwf",      CF_CHG1|CF_USE2                 },      // Move W to f
  { "mulwf",      CF_USE1|CF_USE2                 },      // Multiply W with f
  { "negf",       CF_CHG1|CF_USE2                 },      // Negate f
  { "rlcf",       CF_CHG1|CF_USE2|CF_USE3         },      // Rotate Left f through Carry
  { "rlncf",      CF_CHG1|CF_USE2|CF_USE3         },      // Rotate Left f
  { "rrcf",       CF_CHG1|CF_USE2|CF_USE3         },      // Rotate Right f through Carry
  { "rrncf",      CF_CHG1|CF_USE2|CF_USE3         },      // Rotate Right f
  { "setf",       CF_CHG1|CF_USE2                 },      // Set f
  { "subfwb",     CF_USE1|CF_USE2|CF_USE3         },      // Substract f from W with borrow
  { "subwf",      CF_USE1|CF_USE2|CF_USE3         },      // Substract W from f
  { "subwfb",     CF_USE1|CF_USE2|CF_USE3         },      // Substract W from f with borrow
  { "swapf",      CF_CHG1|CF_USE2|CF_USE3         },      // Swap nibbles in f
  { "tstfsz",     CF_USE1|CF_USE2                 },      // Test f, Skip if 0
  { "xorwf",      CF_USE1|CF_USE2|CF_USE3         },      // Exclusive OR W with f

  // BIT-ORIENTED FILE REGISTER OPERATIONS

  { "bcf",        CF_CHG1|CF_USE2|CF_USE3         },      // Bit Clear f
  { "bsf",        CF_CHG1|CF_USE2|CF_USE3         },      // Bit Set f
  { "btfsc",      CF_USE1|CF_USE2|CF_USE3         },      // Bit Test f, Skip if Clear
  { "btfss",      CF_USE1|CF_USE2|CF_USE3         },      // Bit Test f, Skip if Set
  { "btg",        CF_CHG1|CF_USE2|CF_USE3         },      // Bit Toggle f

  // CONTROL OPERATIONS

  { "bc",         CF_USE1                         },      // Branch if Carry
  { "bn",         CF_USE1                         },      // Branch if Negative
  { "bnc",        CF_USE1                         },      // Branch if not Carry
  { "bnn",        CF_USE1                         },      // Branch if not Negative
  { "bnov",       CF_USE1                         },      // Branch if not Overflow
  { "bnz",        CF_USE1                         },      // Branch if not Zero
  { "bov",        CF_USE1                         },      // Branch if Overflow
  { "bra",        CF_USE1|CF_STOP                 },      // Branch unconditionally
  { "bz",         CF_USE1                         },      // Branch if Zero
  { "call",       CF_USE1|CF_USE2|CF_CALL         },      // Call subroutine
  // clrwdt
  { "daw",        0                               },      // Decimal Adjust W
  // goto
  // nop
  // nop
  { "pop",        0                               },      // Pop top of return stack
  { "push",       0                               },      // Push top of return stack
  { "rcall",      CF_USE1|CF_CALL                 },      // Relative Call subroutine
  { "reset",      0                               },      // Software device Reset
  { "retfie",     CF_USE1|CF_STOP                 },      // Return from interrupt enable
  // retlw
  { "return",     CF_USE1|CF_STOP                 },      // Return from Subroutine
  // sleep

  // LITERAL OPERATIONS

  // addlw
  // andlw
  // iorlw
  { "lfsr",       CF_CHG1|CF_USE2                 },      // Move literal to FSR
  { "movlb",      CF_USE1                         },      // Move literal to BSR
  // movlw
  { "mullw",      CF_USE1                         },      // Multiply literal with W
  // retlw
  // sublw
  // xorlw

  // DATA MEMORY <-> PROGRAM MEMORY OPERATIONS

  { "tblrd*",     0                               },      // Table Read
  { "tblrd*+",    0                               },      // Table Read with post-increment
  { "tblrd*-",    0                               },      // Table Read with post-decrement
  { "tblrd+*",    0                               },      // Table Read with pre-increment
  { "tblwt*",     0                               },      // Table Write
  { "tblwt*+",    0                               },      // Table Write with post-increment
  { "tblwt*-",    0                               },      // Table Write with post-decrement
  { "tblwt+*",    0                               },      // Table Write with pre-increment

  // ADDITIONAL INSTRUCTIONS FOR 16F1x AND 12F1x

  { "addwfc",     CF_USE1|CF_USE2                 },      // Add W and Carry to f
  { "movlp",      CF_USE1                         },      // Move literal to PCLATH
  { "movlb",      CF_USE1                         },      // Move literal to BSR
  { "addfsr",     CF_CHG1|CF_USE2                 },      // Add Literal to FSRn
  { "asrf",       CF_USE1|CF_USE2                 },      // Arithmetic Right Shift
  { "lslf",       CF_USE1|CF_USE2                 },      // Logical Left Shift
  { "lsrf",       CF_USE1|CF_USE2                 },      // Logical Right Shift
  { "subwfb",     CF_USE1|CF_USE2                 },      // Subtract W from f with Borrow
  { "bra",        CF_USE1|CF_STOP                 },      // Relative Branch
  { "brw",        CF_STOP                         },      // Relative Branch with W
  { "callw",      CF_CALL                         },      // Call Subroutine with W
  { "reset",      0                               },      // Software device Reset
  { "moviw",      CF_USE1                         },      // Move INDFn to W
  { "movwi",      CF_USE1                         },      // Move W to INDFn

};

CASSERT(qnumber(Instructions) == PIC_last);
