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
TMS320C3X_null = 0,     // Unknown Operation

TMS320C3X_ABSF,                 // Absolute value of a floating-point number
TMS320C3X_ABSI,                 // Absolute value of an integer
TMS320C3X_ADDC,                 // Add integers with carry
TMS320C3X_ADDF,                 // Add Floating-Point Values
TMS320C3X_ADDI,                 // Add Integer
TMS320C3X_AND,                  // Bitwise-Logical AND
TMS320C3X_ANDN,                 // Bitwise-Logical AND With Complement
TMS320C3X_ASH,                  // Arithmetic Shift
TMS320C3X_CMPF,                 // Compare Floating-Point Value
TMS320C3X_CMPI,                 // Compare Integer
TMS320C3X_FIX,                  // Floating-Point-to-Integer Conversion
TMS320C3X_FLOAT,                // Integer-to-Floating-Point Conversion
TMS320C3X_IDLE,                 // Idle Until Interrupt
TMS320C3X_IDLE2,                // Low-Power Idle
TMS320C3X_LDE,                  // Load Floating-Point Exponent
TMS320C3X_LDF,                  // Load Floating-Point Value
TMS320C3X_LDFI,                 // Load Floating-Point Value, Interlocked
TMS320C3X_LDI,                  // Load Integer
TMS320C3X_LDII,                 // Load Integer, Interlocked
TMS320C3X_LDM,                  // Load Floating-Point Mantissa
TMS320C3X_LSH,                  // Logical Shift
TMS320C3X_MPYF,                 // Multiply Floating-Point Value
TMS320C3X_MPYI,                 // Multiply Integer
TMS320C3X_NEGB,                 // Negative Integer With Borrow
TMS320C3X_NEGF,                 // Negate Floating-Point Value
TMS320C3X_NEGI,                 // Negate Integer
TMS320C3X_NOP,                  // No Operation
TMS320C3X_NORM,                 // Normalize
TMS320C3X_NOT,                  // Bitwise-Logical Complement
TMS320C3X_POP,                  // Pop Integer
TMS320C3X_POPF,                 // Pop Floating-Point Value
TMS320C3X_PUSH,                 // PUSH Integer
TMS320C3X_PUSHF,                // PUSH Floating-Point Value
TMS320C3X_OR,                   // Bitwise-Logical OR
TMS320C3X_LOPOWER,              // Divide Clock by 16
TMS320C3X_MAXSPEED,             // Restore Clock to Regular Speed
TMS320C3X_RND,                  // Round Floating-Point Value
TMS320C3X_ROL,                  // Rotate Left
TMS320C3X_ROLC,                 // Rotate Left Through Carry
TMS320C3X_ROR,                  // Rotate Right
TMS320C3X_RORC,                 // Rotate Right Through Carry
TMS320C3X_RPTS,                 // Repeat Single Instruction
TMS320C3X_STF,                  // Store Floating-Point Value
TMS320C3X_STFI,                 // Store Floating-Point Value, Interlocked
TMS320C3X_STI,                  // Store Integer
TMS320C3X_STII,                 // Store Integer, Interlocked
TMS320C3X_SIGI,                 // Signal, Interlocked
TMS320C3X_SUBB,                 // Subtract Integer With Borrow
TMS320C3X_SUBC,                 // Subtract Integer Conditionally
TMS320C3X_SUBF,                 // Subtract Floating-Point Value
TMS320C3X_SUBI,                 // Subtract Integer
TMS320C3X_SUBRB,                // Subtract Reverse Integer With Borrow
TMS320C3X_SUBRF,                // Subtract Reverse Floating-Point Value
TMS320C3X_SUBRI,                // Subtract Reverse Integer
TMS320C3X_TSTB,                 // Test Bit Fields
TMS320C3X_XOR,                  // Bitwise-Exclusive OR
TMS320C3X_IACK,                 // Interrupt acknowledge

TMS320C3X_ADDC3,                // Add integers with carry (3-operand)
TMS320C3X_ADDF3,                // Add floating-point values (3-operand)
TMS320C3X_ADDI3,                // Add integers (3 operand)
TMS320C3X_AND3,                 // Bitwise-logical AND (3-operand)
TMS320C3X_ANDN3,                // Bitwise-logical ANDN (3-operand)
TMS320C3X_ASH3,                 // Arithmetic shift (3-operand)
TMS320C3X_CMPF3,                // Compare floating-point values (3-operand)
TMS320C3X_CMPI3,                // Compare integers (3-operand)
TMS320C3X_LSH3,                 // Logical shift (3-operand)
TMS320C3X_MPYF3,                // Multiply floating-point value (3-operand)
TMS320C3X_MPYI3,                // Multiply integers (3-operand)
TMS320C3X_OR3,                  // Bitwise-logical OR (3-operand)
TMS320C3X_SUBB3,                // Subtract integers with borrow (3-operand)
TMS320C3X_SUBF3,                // Subtract floating-point values (3-operand)
TMS320C3X_SUBI3,                // Subtract integers (3-operand)
TMS320C3X_TSTB3,                // Test Bit Fields, 3-Operand
TMS320C3X_XOR3,                 // Bitwise-Exclusive OR, 3-Operand

TMS320C3X_LDFcond,              // Load floating-point value conditionally
TMS320C3X_LDIcond,              // Load integer conditionally
TMS320C3X_BR,                   // Branch unconditionally (standard)
TMS320C3X_BRD,                  // Branch unconditionally (delayed)
TMS320C3X_CALL,                 // Call subroutine
TMS320C3X_RPTB,                 // Repeat block of instructions
TMS320C3X_SWI,                  // Software Interrupt
TMS320C3X_Bcond,                // Branch conditionally
TMS320C3X_DBcond,               // Decrement and branch conditionally
TMS320C3X_CALLcond,             // Call subroutine conditionally
TMS320C3X_TRAPcond,             // Trap Conditionally
TMS320C3X_RETIcond,             // Return from interrupt conditionally
TMS320C3X_RETScond,             // Return from subroutine conditionally
TMS320C3X_RETIU,                // Return from interrupt unconditionally
TMS320C3X_RETSU,                // Return from subroutine unconditionally

TMS320C3X_NONE,                 // Pseudo insn (more accurate definition need)
TMS320C3X_MV_IDX,               // Pseudo insn (move to next index need)
TMS320C3X_last,                 // last ID

};


#endif
