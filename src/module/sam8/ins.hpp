/************************************************************************/
/* Disassembler for Samsung SAM8 processors                             */
/************************************************************************/
#ifndef __INSTRS_HPP
#define __INSTRS_HPP


/************************************************************************/
/* Instructions enumeration                                             */
/************************************************************************/
extern const instruc_t Instructions[];
enum nameNum
{
  SAM8_null = 0,   // Unknown Operation

  SAM8_ADC,        // Add with carry
  SAM8_ADD,        // Add
  SAM8_AND,        // Logical and
  SAM8_BAND,       // Bit and
  SAM8_BCP,        // Bit compare
  SAM8_BITC,       // Bit complement
  SAM8_BITR,       // Bit reset
  SAM8_BITS,       // Bit set
  SAM8_BOR,        // Bit or
  SAM8_BTJRF,      // Bit test, jump relative on false
  SAM8_BTJRT,      // Bit test, jump relative on true
  SAM8_BXOR,       // Bit xor
  SAM8_CALL,       // Call procedure
  SAM8_CCF,        // Complement carry flag
  SAM8_CLR,        // Clear
  SAM8_COM,        // Complement
  SAM8_CP,         // Compare
  SAM8_CPIJE,      // Compare, increment, and jump on equal
  SAM8_CPIJNE,     // Compare, increment, and jump on non-equal
  SAM8_DA,         // Decimal adjust
  SAM8_DEC,        // Decrement
  SAM8_DECW,       // Decrement word
  SAM8_DI,         // Disable interrupts
  SAM8_DIV,        // Divide (unsigned)
  SAM8_DJNZ,       // Decrement and jump if non-zero
  SAM8_EI,         // Enable interrupts
  SAM8_ENTER,      // Enter
  SAM8_EXIT,       // Exit
  SAM8_IDLE,       // Idle operation
  SAM8_INC,        // Increment
  SAM8_INCW,       // Increment word
  SAM8_IRET,       // Interrupt return
  SAM8_JP,         // Jump
  SAM8_JR,         // Jump relative
  SAM8_LD,         // Load
  SAM8_LDB,        // Load bit
  SAM8_LDC,        // Load program memory
  SAM8_LDE,        // Load external data memory
  SAM8_LDCD,       // Load program memory and decrement
  SAM8_LDED,       // Load external data memory and decrement
  SAM8_LDCI,       // Load program memory and increment
  SAM8_LDEI,       // Load external data memory and increment
  SAM8_LDCPD,      // Load program memory with pre-decrement
  SAM8_LDEPD,      // Load external data memory with pre-decrement
  SAM8_LDCPI,      // Load program memory with pre-increment
  SAM8_LDEPI,      // Load external data memory with pre-increment
  SAM8_LDW,        // Load word
  SAM8_MULT,       // Multiply (unsigned)
  SAM8_NEXT,       // Next
  SAM8_NOP,        // No operation
  SAM8_OR,         // Logical or
  SAM8_POP,        // Pop from stack
  SAM8_POPUD,      // Pop user stack (decrementing)
  SAM8_POPUI,      // Pop user stack (incrementing)
  SAM8_PUSH,       // Push to stack
  SAM8_PUSHUD,     // Push user stack (decrementing)
  SAM8_PUSHUI,     // Push user stack (incrementing)
  SAM8_RCF,        // Reset carry flag
  SAM8_RET,        // Return
  SAM8_RL,         // Rotate left
  SAM8_RLC,        // Rotate left through carry
  SAM8_RR,         // Rotate right
  SAM8_RRC,        // Rotate right through carry
  SAM8_SB0,        // Select bank 0
  SAM8_SB1,        // Select bank 1
  SAM8_SBC,        // Subtract with carry
  SAM8_SCF,        // Set carry flag
  SAM8_SRA,        // Shift right arithmetic
  SAM8_SRP,        // Set register pointer
  SAM8_SRP0,       // Set register pointer 0
  SAM8_SRP1,       // Set register pointer 1
  SAM8_STOP,       // Stop operation
  SAM8_SUB,        // Subtract
  SAM8_SWAP,       // Swap nibbles
  SAM8_TCM,        // Test complement under mask
  SAM8_TM,         // Test under mask
  SAM8_WFI,        // Wait for interrupt
  SAM8_XOR,        // Logical exclusive or

  SAM8_last
};

#endif
