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
  NEC_78K_0S_null = 0,           // Unknown Operation
  NEC_78K_0S_cmp,                // Compare Byte Data Comparison
  NEC_78K_0S_xor,                // Exclusive Or Exclusive Logical Sum of Byte Data
  NEC_78K_0S_and,                // AND Logical Product of Byte Data
  NEC_78K_0S_or,                 // OR Logical Sum of Byte Data
  NEC_78K_0S_add,                // ADD Byte Data Addition
  NEC_78K_0S_sub,                // Subtract Byte Data Subtraction
  NEC_78K_0S_addc,               // Add with Carry Addition of Byte Data with Carry
  NEC_78K_0S_subc,               // Subtract with Carry Subtraction of Byte Data with Carry
  NEC_78K_0S_subw,               // Subtract Word Data Subtraction
  NEC_78K_0S_addw,               // Add Word Data Addition
  NEC_78K_0S_cmpw,               // Compare Word Data Comparison
  NEC_78K_0S_inc,                // Increment Byte Data Increment
  NEC_78K_0S_dec,                // Decrement Byte Data Decrement
  NEC_78K_0S_incw,               // Increment Word Data Increment
  NEC_78K_0S_decw,               // Decrement Word Data Decrement
  NEC_78K_0S_ror,                // Rotate Right Byte Data Rotation to the Right
  NEC_78K_0S_rol,                // Rotate Left Byte Data Rotation to the Left
  NEC_78K_0S_rorc,               // Rotate Right with Carry Byte Data Rotation to the Right with Carry
  NEC_78K_0S_rolc,               // Rotate Left with Carry Byte Data Rotation to the Left with Carry
  NEC_78K_0S_call,               // CALL Subroutine Call (16 Bit Direct)
  NEC_78K_0S_callt,              // Call Table Subroutine Call (Call Table Reference)
  NEC_78K_0S_ret,                // Return from Subroutine
  NEC_78K_0S_reti,               // Return from Interrupt / Return from Hardware Vectored Interrupt
  NEC_78K_0S_mov,                // Move Byte Data Transfer
  NEC_78K_0S_xch,                // Exchange Byte Data Exchange
  NEC_78K_0S_xchw,               // Exchange Word Data Exchange
  NEC_78K_0S_set1,               // Set Single Bit (Carry Flag) 1 Bit Data Set
  NEC_78K_0S_clr1,               // Clear Single Bit (Carry Flag) 1 Bit Data Clear
  NEC_78K_0S_not1,               // Not Single Bit (Carry Flag) 1 Bit Data Logical Negation
  NEC_78K_0S_push,               // Push
  NEC_78K_0S_pop,                // Pop
  NEC_78K_0S_movw,               // Move Word Data Transfer / Word Data Transfer with Stack Pointer
  NEC_78K_0S_br,                 // Unconditional Branch
  NEC_78K_0S_bc,                 // Branch if Carry Conditional Branch with Carry Flag (CY = 1)
  NEC_78K_0S_bnc,                // Branch if Not Carry Conditional Branch with Carry Flag (CY = 0)
  NEC_78K_0S_bz,                 // Branch if Zero Conditional Branch with Zero Flag (Z = 1)
  NEC_78K_0S_bnz,                // Branch if Not Zero Conditional Branch with Zero Flag (Z = 0)
  NEC_78K_0S_bt,                 // Branch if True Conditional Branch by Bit Test (Byte Data Bit = 1)
  NEC_78K_0S_bf,                 // Branch if False Conditional Branch by Bit Test (Byte Data Bit = 0)
  NEC_78K_0S_dbnz,               // Decrement and Branch if Not Zero Conditional Loop (R1 != 0)
  NEC_78K_0S_nop,                // No Operation
  NEC_78K_0S_EI,                 // Enable Interrupt
  NEC_78K_0S_DI,                 // Disable Interrupt
  NEC_78K_0S_HALT,               // HALT Mode Set
  NEC_78K_0S_STOP,               // Stop Mode Set
  NEC_78K_0S_last
};

#endif
