/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
NEC_78K_0_null = 0,       // Unknown Operation

NEC_78K_0_mov,            // Move Byte Data Transfer
NEC_78K_0_xch,            // Exchange Byte Data
NEC_78K_0_movw,           // Move Word Data Transfer / Word Data Transfer with Stack Pointer
NEC_78K_0_xchw,           // Exchange Word Data

NEC_78K_0_add,            // Add Byte Data Addition
NEC_78K_0_addc,           // Add with Carry Addition of Byte Data with Carry
NEC_78K_0_sub,            // Subtract Byte Data Subtraction
NEC_78K_0_subc,           // Subtract with Carry Subtraction of Byte Data with Carry
NEC_78K_0_and,            // And Logical Product of Byte Data
NEC_78K_0_or,             // Or Logical Sum of Byte Data
NEC_78K_0_xor,            // Exclusive Or Exclusive Logical Sum of Byte Data
NEC_78K_0_cmp,            // Compare Byte Data Comparison

NEC_78K_0_addw,           // Add Word Data Addition
NEC_78K_0_subw,           // Subtract Word Data Subtraction
NEC_78K_0_cmpw,           // Compare Word Data Comparison

NEC_78K_0_mulu,           // Multiply Unsigned Multiplication of Data
NEC_78K_0_divuw,          // Divide Unsigned Word Unsigned Division of Word Data

NEC_78K_0_inc,            // Increment Byte Data Increment
NEC_78K_0_dec,            // Decrement Byte Data Decrement
NEC_78K_0_incw,           // Increment Word Data Increment
NEC_78K_0_decw,           // Decrement Word Data Decrement

NEC_78K_0_ror,            // Rotate Right Byte Data Rotation to the Right
NEC_78K_0_rol,            // Rotate Left Byte Data Rotation to the Left
NEC_78K_0_rorc,           // Rotate Right with Carry Byte Data Rotation to the Right with Carry
NEC_78K_0_rolc,           // Rotate Left with Carry Byte Data Rotation to the Left with Carry
NEC_78K_0_ror4,           // Rotate Right Digit Digit Rotation to the Right
NEC_78K_0_rol4,           // Rotate Left Digit Digit Rotation to the Left

NEC_78K_0_adjba,          // Decimal Adjust Register for Addition Decimal Adjustment of Addition Result
NEC_78K_0_adjbs,          // Decimal Adjust Register for Subtraction Decimal Adjustment of Subtraction Result

NEC_78K_0_mov1,           // Move Single Bit 1 Bit Data Transfer
NEC_78K_0_and1,           // And Single Bit 1 Bit Data Logical Product
NEC_78K_0_or1,            // Or Single Bit 1 Bit Data Logical Sum
NEC_78K_0_xor1,           // Exclusive Or Single Bit 1 Bit Data Exclusive Logical Sum
NEC_78K_0_set1,           // Set Single Bit (Carry Flag) 1 Bit Data Set
NEC_78K_0_clr1,           // Clear Single Bit (Carry Flag) 1 Bit Data Clear
NEC_78K_0_not1,           // Not Single Bit (Carry Flag) 1 Bit Data Logical Negation

NEC_78K_0_call,           // Call Subroutine Call (16 Bit Direct)
NEC_78K_0_callf,          // Call Flag Subroutine Call (11 Bit Direct Specification)
NEC_78K_0_callt,          // Call Table Subroutine Call (Refer to the Call Table)
NEC_78K_0_brk,            // Break Software Vectored Interrupt
NEC_78K_0_ret,            // Return Return from Subroutine
NEC_78K_0_retb,           // Return from Interrupt Return from Hardware Vectored Interrupt
NEC_78K_0_reti,           // Return from Break Return from Software Vectored Interrupt

NEC_78K_0_push,           // Push
NEC_78K_0_pop,            // Pop

NEC_78K_0_br,             // Branch Unconditional Branch
NEC_78K_0_bc,             // Branch if Carry Conditional Branch with Carry Flag (CY = 1)
NEC_78K_0_bnc,            // Branch if Not Carry Conditional Branch with Carry Flag (CY = 0)
NEC_78K_0_bz,             // Branch if Zero Conditional Branch with Zero Flag (Z = 1)
NEC_78K_0_bnz,            // Branch if Not Zero Conditional Branch with Zero Flag (Z = 0)
NEC_78K_0_bt,             // Branch if True Conditional Branch by Bit Test (Byte Data Bit = 1)
NEC_78K_0_bf,             // Branch if False Conditional Branch by Bit Test (Byte Data Bit = 0)
NEC_78K_0_btclr,          // Branch if True and Clear Conditional Branch and Clear by Bit Test (Byte Data Bit = 1)
NEC_78K_0_dbnz,           // Decrement and Branch if Not Zero Conditional Loop (R1!= 0)

NEC_78K_0_sel,            // Select Register Bank Register Bank Selection


NEC_78K_0_nop,            // No Operation
NEC_78K_0_EI,             // Enable Interrupt
NEC_78K_0_DI,             // Disable Interrupt
NEC_78K_0_HALT,           // HALT Mode Set
NEC_78K_0_STOP,           // Stop Mode Set


NEC_78K_0_last

    };

#endif
