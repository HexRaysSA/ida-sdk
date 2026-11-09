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

PIC_null = 0,      // Unknown Operation

// BYTE-ORIENTED FILE REGISTER OPERATIONS

PIC_addwf,         // Add W and f
PIC_andwf,         // AND W with f
PIC_clrf,          // Clear f
PIC_clrw,          // Clear W
PIC_comf,          // Complement f
PIC_decf,          // Decrement f
PIC_decfsz,        // Decrement f, Skip if 0
PIC_incf,          // Increment f
PIC_incfsz,        // Increment f, Skip if 0
PIC_iorwf,         // Inclusive OR W with f
PIC_movf,          // Move f
PIC_movwf,         // Move W to f
PIC_nop,           // No Operation
PIC_rlf,           // Rotate Left f through Carry
PIC_rrf,           // Rotate Right f through Carry
PIC_subwf,         // Subtract W from f
PIC_swapf,         // Swap nibbles in f
PIC_xorwf,         // Exclusive OR W with f

// BIT-ORIENTED FILE REGISTER OPERATIONS

PIC_bcf,           // Bit Clear f
PIC_bsf,           // Bit Set f
PIC_btfsc,         // Bit Test f, Skip if Clear
PIC_btfss,         // Bit Test f, Skip if Set


// LITERAL AND CONTROL OPERATIONS

PIC_addlw,         // Add literal and W
PIC_andlw,         // AND literal with W
PIC_call,          // Call subroutine
PIC_clrwdt,        // Clear Watchdog Timer
PIC_goto,          // Go to address
PIC_iorlw,         // Inclusive OR literal with W
PIC_movlw,         // Move literal to W
PIC_retfie,        // Return from interrupt
PIC_retlw,         // Return with literal in W
PIC_return,        // Return from Subroutine
PIC_sleep,         // Go into standby mode
PIC_sublw,         // Subtract W from literal
PIC_xorlw,         // Exclusive OR literal with W

// ADDITIONAL INSTRUCTIONS TO MAINTAIN COMPITIBILITY WITH 12C5xx,16C5x

PIC_option,        // Load OPTION register
PIC_tris,          // Load TRIS Register

// MACROS

PIC_movfw,         // Move Contents of File Reg to W
PIC_tstf,          // Test Contents of File Register
PIC_negf,          // Negate File Register Contents
PIC_b,             // Branch to Address
PIC_clrc,          // Clear Carry
PIC_clrdc,         // Clear Digit Carry
PIC_clrz,          // Clear Zero
PIC_setc,          // Set Carry
PIC_setdc,         // Set Digit Carry
PIC_setz,          // Set Zero
PIC_skpc,          // Skip on Carry
PIC_skpdc,         // Skip on Digit Carry
PIC_skpnc,         // Skip on No Carry
PIC_skpndc,        // Skip on No Digit Carry
PIC_skpnz,         // Skip on No Zero
PIC_skpz,          // Skip on Zero
PIC_bc,            // Branch on Carry to Address k
PIC_bdc,           // Branch on Digit Carry to k
PIC_bnc,           // Branch on No Carry to k
PIC_bndc,          // Branch on No Digit Carry to k
PIC_bnz,           // Branch on No Zero to Address
PIC_bz,            // Branch on Zero to Address k
PIC_addcf,         // Add Carry to File Register
PIC_adddcf,        // Add Digit to File Register
PIC_subcf,         // Subtract Carry from File Reg

// ADDITIONAL INSTRUCTIONS FOR 18Cxx

// BYTE-ORIENTED FILE REGISTER OPERATIONS

PIC_addwf3,        // Add W and f
PIC_addwfc3,       // Add W and Carry to f
PIC_andwf3,        // AND W with f
PIC_clrf2,         // Clear f
PIC_comf3,         // Complement f
PIC_cpfseq2,       // Compare f with W, Skip if ==
PIC_cpfsgt2,       // Compare f with W, Skip if >
PIC_cpfslt2,       // Compare f with W, Skip if <
PIC_decf3,         // Decrement f
PIC_decfsz3,       // Decrement f, Skip if 0
PIC_dcfsnz3,       // Decrement f, Skip if not 0
PIC_incf3,         // Increment f
PIC_incfsz3,       // Increment f, Skip if 0
PIC_infsnz3,       // Increment f, Skip if not 0
PIC_iorwf3,        // Inclusive OR W with f
PIC_movf3,         // Move f
PIC_movff2,        // Move fs to fd
PIC_movwf2,        // Move W to f
PIC_mulwf2,        // Multiply W with f
PIC_negf2,         // Negate f
PIC_rlcf3,         // Rotate Left f through Carry
PIC_rlncf3,        // Rotate Left f
PIC_rrcf3,         // Rotate Right f through Carry
PIC_rrncf3,        // Rotate Right f
PIC_setf2,         // Set f
PIC_subfwb3,       // Substract f from W with borrow
PIC_subwf3,        // Substract W from f
PIC_subwfb3,       // Substract W from f with borrow
PIC_swapf3,        // Swap nibbles in f
PIC_tstfsz2,       // Test f, Skip if 0
PIC_xorwf3,        // Exclusive OR W with f

// BIT-ORIENTED FILE REGISTER OPERATIONS

PIC_bcf3,          // Bit Clear f
PIC_bsf3,          // Bit Set f
PIC_btfsc3,        // Bit Test f, Skip if Clear
PIC_btfss3,        // Bit Test f, Skip if Set
PIC_btg3,          // Bit Toggle f

// CONTROL OPERATIONS

PIC_bc1,           // Branch if Carry
PIC_bn1,           // Branch if Negative
PIC_bnc1,          // Branch if not Carry
PIC_bnn1,          // Branch if not Negative
PIC_bnov1,         // Branch if not Overflow
PIC_bnz1,          // Branch if not Zero
PIC_bov1,          // Branch if Overflow
PIC_bra1,          // Branch unconditionally
PIC_bz1,           // Branch if Zero
PIC_call2,         // Call subroutine
// PIC_clrwdt
PIC_daw0,          // Decimal Adjust W
// PIC_goto
// PIC_nop
// PIC_nop
PIC_pop0,          // Pop top of return stack
PIC_push0,         // Push top of return stack
PIC_rcall1,        // Relative Call subroutine
PIC_reset0,        // Software device Reset
PIC_retfie1,       // Return from interrupt enable
// PIC_retlw
PIC_return1,       // Return from Subroutine
// PIC_sleep

// LITERAL OPERATIONS

// PIC_addlw
// PIC_andlw
// PIC_iorlw
PIC_lfsr2,         // Move literal to FSR
PIC_movlb1,        // Move literal to BSR
// PIC_movlw
PIC_mullw1,        // Multiply literal with W
// PIC_retlw
// PIC_sublw
// PIC_xorlw

// DATA MEMORY <-> PROGRAM MEMORY OPERATIONS

PIC_tblrd0,        // Table Read
PIC_tblrd0p,       // Table Read with post-increment
PIC_tblrd0m,       // Table Read with post-decrement
PIC_tblrdp0,       // Table Read with pre-increment
PIC_tblwt0,        // Table Write
PIC_tblwt0p,       // Table Write with post-increment
PIC_tblwt0m,       // Table Write with post-decrement
PIC_tblwtp0,       // Table Write with pre-increment

// ADDITIONAL INSTRUCTIONS FOR 16F1x and 12F1x

PIC_addwfc,       // Add W and Carry to f
PIC_movlp,        // Move literal to PCLATH
PIC_movlb,        // Move literal to BSR
PIC_addfsr,       // Add Literal to FSRn
PIC_asrf,         // Arithmetic Right Shift
PIC_lslf,         // Logical Left Shift
PIC_lsrf,         // Logical Right Shift
PIC_subwfb,       // Subtract with Borrow W from f
PIC_bra,          // Relative Branch
PIC_brw,          // Relative Branch with W
PIC_callw,        // Call Subroutine with W
PIC_reset,        // Software device Reset
PIC_moviw,        // Move INDFn to W
PIC_movwi,        // Move W to INDFn

PIC_last,

    };

#endif
