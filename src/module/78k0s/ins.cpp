/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

//-----------------------------------------------------------------------
const instruc_t Instructions[] =
{
{ "",  0      },           // Unknown Operation
{ "cmp",   CF_USE1 | CF_USE2  },           // Compare Byte Data Comparison
{ "xor",   CF_CHG1 | CF_USE2  },           // Exclusive Or Exclusive Logical Sum of Byte Data
{ "and",   CF_CHG1 | CF_USE2  },           // AND Logical Product of Byte Data
{ "or",    CF_CHG1 | CF_USE2  },           // OR Logical Sum of Byte Data
{ "add",   CF_CHG1 | CF_USE2  },           // ADD Byte Data Addition
{ "sub",   CF_CHG1 | CF_USE2  },           // Subtract Byte Data Subtraction
{ "addc",  CF_CHG1 | CF_USE2  },           // Add with Carry Addition of Byte Data with Carry
{ "subc",  CF_CHG1 | CF_USE2  },           // Subtract with Carry Subtraction of Byte Data with Carry
{ "subw",  CF_CHG1 | CF_USE2  },           // Subtract Word Data Subtraction
{ "addw",  CF_CHG1 | CF_USE2  },           // Add Word Data Addition
{ "cmpw",  CF_USE1 | CF_USE2  },           // Compare Word Data Comparison
{ "inc",   CF_CHG1            },           // Increment Byte Data Increment
{ "dec",   CF_CHG1            },           // Decrement Byte Data Decrement
{ "incw",  CF_CHG1            },           // Increment Word Data Increment
{ "decw",  CF_CHG1            },           // Decrement Word Data Decrement
{ "ror",   CF_CHG1            },           // Rotate Right Byte Data Rotation to the Right
{ "rol",   CF_CHG1            },           // Rotate Left Byte Data Rotation to the Left
{ "rorc",  CF_CHG1            },           // Rotate Right with Carry Byte Data Rotation to the Right with Carry
{ "rolc",  CF_CHG1            },           // Rotate Left with Carry Byte Data Rotation to the Left with Carry
{ "call",  CF_USE1 | CF_CALL  },           // CALL Subroutine Call (16 Bit Direct)
{ "callt", CF_USE1 | CF_CALL  },           // Call Table Subroutine Call (Call Table Reference)
{ "ret",   CF_STOP            },           // Return from Subroutine
{ "reti",  CF_STOP            },           // Return from Interrupt / Return from Hardware Vectored Interrupt
{ "mov",   CF_CHG1 | CF_USE2  },           // Move Byte Data Transfer
{ "xch",   CF_CHG1 | CF_CHG2  },           // Exchange Byte Data Exchange
{ "xchw",  CF_CHG1 | CF_CHG2  },           // Exchange Word Data Exchange
{ "set1",  CF_CHG1            },           // Set Single Bit (Carry Flag) 1 Bit Data Set
{ "clr1",  CF_CHG1            },           // Clear Single Bit (Carry Flag) 1 Bit Data Clear
{ "not1",  CF_CHG1            },           // Not Single Bit (Carry Flag) 1 Bit Data Logical Negation
{ "push",  CF_USE1            },           // Push
{ "pop",   CF_CHG1            },           // Pop
{ "movw",  CF_CHG1 | CF_USE2  },           // Move Word Data Transfer / Word Data Transfer with Stack Pointer
{ "br",    CF_USE1 | CF_STOP  },           // Unconditional Branch
{ "bc",    CF_USE1            },           // Branch if Carry Conditional Branch with Carry Flag (CY = 1)
{ "bnc",   CF_USE1            },           // Branch if Not Carry Conditional Branch with Carry Flag (CY = 0)
{ "bz",    CF_USE1            },           // Branch if Zero Conditional Branch with Zero Flag (Z = 1)
{ "bnz",   CF_USE1            },           // Branch if Not Zero Conditional Branch with Zero Flag (Z = 0)
{ "bt",    CF_USE1 | CF_USE2  },           // Branch if True Conditional Branch by Bit Test (Byte Data Bit = 1)
{ "bf",    CF_USE1 | CF_USE2  },           // Branch if False Conditional Branch by Bit Test (Byte Data Bit = 0)
{ "dbnz",  CF_CHG1 | CF_USE2  },           // Decrement and Branch if Not Zero Conditional Loop (R1 != 0)
{ "nop",   0                  },               // No Operation
{ "EI",    0                  },           // Enable Interrupt
{ "DI",    0                  },           // Disable Interrupt
{ "HALT",  0                  },               // HALT Mode Set
{ "STOP",  CF_STOP            }            // Stop Mode Set
};
//-----------------------------------------------------------------------

CASSERT(qnumber(Instructions) == NEC_78K_0S_last);
