/*
 *      NEC 78K0 processor module for IDA.
 *      Copyright (c) 2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "78k0.hpp"

const instruc_t Instructions[] =
{

  { "",  0                        },           // Unknown Operation

  { "mov",    CF_USE2 | CF_CHG1   },           // Move Byte Data Transfer
  { "xch",    CF_CHG1 | CF_CHG2   },           // Exchange Byte Data
  { "movw",   CF_USE2 | CF_CHG1   },           // Move Word Data Transfer / Word Data Transfer with Stack Pointer
  { "xchw",   CF_CHG1 | CF_CHG2   },           // Exchange Word Data

  { "add",    CF_USE2 | CF_CHG1   },           // Add Byte Data Addition
  { "addc",   CF_USE2 | CF_CHG1   },           // Add with Carry Addition of Byte Data with Carry
  { "sub",    CF_USE2 | CF_CHG1   },           // Subtract Byte Data Subtraction
  { "subc",   CF_USE2 | CF_CHG1   },           // Subtract with Carry Subtraction of Byte Data with Carry
  { "and",    CF_USE2 | CF_CHG1   },           // And Logical Product of Byte Data
  { "or",     CF_USE2 | CF_CHG1   },           // Or Logical Sum of Byte Data
  { "xor",    CF_USE2 | CF_CHG1   },           // Exclusive Or Exclusive Logical Sum of Byte Data
  { "cmp",    CF_USE1 | CF_USE2   },           // Compare Byte Data Comparison

  { "addw",   CF_USE2 | CF_CHG1   },           // Add Word Data Addition
  { "subw",   CF_USE2 | CF_CHG1   },           // Subtract Word Data Subtraction
  { "cmpw",   CF_USE1 | CF_USE2   },           // Compare Word Data Comparison

  { "mulu",   0                   },           // Multiply Unsigned Multiplication of Data
  { "divuw",  0                   },           // Divide Unsigned Word Unsigned Division of Word Data

  { "inc",    CF_CHG1             },           // Increment Byte Data Increment
  { "dec",    CF_CHG1             },           // Decrement Byte Data Decrement
  { "incw",   CF_CHG1             },           // Increment Word Data Increment
  { "decw",   CF_CHG1             },           // Decrement Word Data Decrement

  { "ror",    CF_CHG1             },           // Rotate Right Byte Data Rotation to the Right
  { "rol",    CF_CHG1             },           // Rotate Left Byte Data Rotation to the Left
  { "rorc",   CF_CHG1             },           // Rotate Right with Carry Byte Data Rotation to the Right with Carry
  { "rolc",   CF_CHG1             },           // Rotate Left with Carry Byte Data Rotation to the Left with Carry
  { "ror4",   CF_CHG1             },           // Rotate Right Digit Digit Rotation to the Right
  { "rol4",   CF_CHG1             },           // Rotate Left Digit Digit Rotation to the Left

  { "adjba",  0                   },           // Decimal Adjust Register for Addition Decimal Adjustment of Addition Result
  { "adjbs",  0                   },           // Decimal Adjust Register for Subtraction Decimal Adjustment of Subtraction Result

  { "mov1",   CF_USE2 | CF_CHG1   },           // Move Single Bit 1 Bit Data Transfer
  { "and1",   CF_USE2 | CF_CHG1   },           // And Single Bit 1 Bit Data Logical Product
  { "or1",    CF_USE2 | CF_CHG1   },           // Or Single Bit 1 Bit Data Logical Sum
  { "xor1",   CF_USE2 | CF_CHG1   },           // Exclusive Or Single Bit 1 Bit Data Exclusive Logical Sum
  { "set1",   CF_CHG1             },           // Set Single Bit (Carry Flag) 1 Bit Data Set
  { "clr1",   CF_CHG1             },           // Clear Single Bit (Carry Flag) 1 Bit Data Clear
  { "not1",   CF_USE1             },           // Not Single Bit (Carry Flag) 1 Bit Data Logical Negation

  { "call",   CF_USE1 | CF_CALL   },           // Call Subroutine Call (16 Bit Direct)
  { "callf",  CF_USE1 | CF_CALL   },           // Call Flag Subroutine Call (11 Bit Direct Specification)
  { "callt",  CF_USE1 | CF_CALL   },           // Call Table Subroutine Call (Refer to the Call Table)
  { "brk",    0                   },           // Break Software Vectored Interrupt
  { "ret",    CF_STOP             },           // Return Return from Subroutine
  { "retb",   CF_STOP             },           // Return from Interrupt Return from Hardware Vectored Interrupt
  { "reti",   CF_STOP             },           // Return from Break Return from Software Vectored Interrupt

  { "push",   CF_USE1             },           // Push
  { "pop",    CF_USE1             },           // Pop


  { "br",     CF_USE1     | CF_STOP       },           // Branch Unconditional Branch
  { "bc",     CF_USE1             },           // Branch if Carry Conditional Branch with Carry Flag (CY = 1)
  { "bnc",    CF_USE1             },           // Branch if Not Carry Conditional Branch with Carry Flag (CY = 0)
  { "bz",     CF_USE1             },           // Branch if Zero Conditional Branch with Zero Flag (Z = 1)
  { "bnz",    CF_USE1             },           // Branch if Not Zero Conditional Branch with Zero Flag (Z = 0)
  { "bt",     CF_USE1 | CF_USE2   },           // Branch if True Conditional Branch by Bit Test (Byte Data Bit = 1)
  { "bf",     CF_USE1 | CF_USE2   },           // Branch if False Conditional Branch by Bit Test (Byte Data Bit = 0)
  { "btclr",  CF_USE1 | CF_USE2   },           // Branch if True and Clear Conditional Branch and Clear by Bit Test (Byte Data Bit = 1)
  { "dbnz",   CF_CHG1     | CF_USE2       },           // Decrement and Branch if Not Zero Conditional Loop (R1!= 0)

  { "sel",    CF_USE1             },           // Select Register Bank Register Bank Selection


  { "nop",    0                   },           // No Operation
  { "EI",     0                   },           // Enable Interrupt
  { "DI",     0                   },           // Disable Interrupt
  { "HALT",   0                   },           // HALT Mode Set
  { "STOP",   CF_STOP             }            // Stop Mode Set

};

CASSERT(qnumber(Instructions) == NEC_78K_0_last);
