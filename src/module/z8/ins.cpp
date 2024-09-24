/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

const instruc_t Instructions[] =
{
  { "",       0                       },  // Unknown Operation

  { "adc",    CF_USE2|CF_USE1|CF_CHG1 },  // Add with carry
  { "add",    CF_USE2|CF_USE1|CF_CHG1 },  // Add
  { "and",    CF_USE2|CF_USE1|CF_CHG1 },  // Logical AND
  { "call",   CF_USE1|CF_CALL         },  // Call procedure
  { "ccf",    0                       },  // Complement carry flag
  { "clr",    CF_CHG1                 },  // Clear
  { "com",    CF_USE1|CF_CHG1         },  // Complement
  { "cp",     CF_USE2|CF_USE1         },  // Compare
  { "da",     CF_USE1|CF_CHG1         },  // Decimal adjust
  { "dec",    CF_USE1|CF_CHG1         },  // Decrement
  { "decw",   CF_USE1|CF_CHG1         },  // Decrement word
  { "di",     0                       },  // Disable interrupts
  { "djnz",   CF_USE2|CF_USE1|CF_CHG1 },  // Decrement and jump if non-zero
  { "ei",     0                       },  // Enable interrupts
  { "halt",   0                       },  // Enter HALT mode
  { "inc",    CF_USE1|CF_CHG1         },  // Increment
  { "incw",   CF_USE1|CF_CHG1         },  // Increment word
  { "iret",   CF_STOP                 },  // Return from interrupt
//  { "jp",     CF_JUMP|CF_USE1|CF_STOP },  // Indirect jump
  { "jp",     CF_USE1|CF_STOP         },  // Unconditional jump
  { "jp",     CF_USE2                 },  // Conditional jump
  { "jr",     CF_USE1|CF_STOP         },  // Relative jump
  { "jr",     CF_USE2                 },  // Conditional relative jump
  { "ld",     CF_USE2|CF_USE1|CF_CHG1 },  // Load data
  { "ldc",    CF_USE2|CF_USE1|CF_CHG1 },  // Load constant
  { "ldci",   CF_USE2|CF_USE1|CF_CHG1 },  // Load constant with auto-increment
  { "lde",    CF_USE2|CF_USE1|CF_CHG1 },  // Load external data
  { "ldei",   CF_USE2|CF_USE1|CF_CHG1 },  // Load external data with auto-increment
  { "nop",    0                       },  // NOP
  { "or",     CF_USE2|CF_USE1|CF_CHG1 },  // Logical OR
  { "pop",    CF_CHG1                 },  // Pop
  { "push",   CF_USE1                 },  // Push
  { "rcf",    0                       },  // Reset carry flag
  { "ret",    CF_STOP                 },  // Return
  { "rl",     CF_SHFT|CF_USE1|CF_CHG1 },  // Rotate left
  { "rlc",    CF_SHFT|CF_USE1|CF_CHG1 },  // Rotate left through carry
  { "rr",     CF_SHFT|CF_USE1|CF_CHG1 },  // Rotate right
  { "rrc",    CF_SHFT|CF_USE1|CF_CHG1 },  // Rotate right through carry
  { "sbc",    CF_USE2|CF_USE1|CF_CHG1 },  // Subtract with carry
  { "scf",    0                       },  // Set carry flag
  { "sra",    CF_SHFT|CF_USE1|CF_CHG1 },  // Shift right arithmetic
  { "srp",    CF_USE1                 },  // Set register pointer
  { "stop",   CF_STOP                 },  // Enter STOP mode
  { "sub",    CF_USE2|CF_USE1|CF_CHG1 },  // Subtract
  { "swap",   CF_USE1|CF_CHG1         },  // Swap nibbles
  { "tm",     CF_USE2|CF_USE1         },  // Test under mask
  { "tcm",    CF_USE2|CF_USE1         },  // Test complement under mask
  { "xor",    CF_USE2|CF_USE1|CF_CHG1 },  // Logical EXCLUSIVE OR
  { "wdh",    0                       },  // Enable WATCH-DOG in HALT mode
  { "wdt",    0                       }   // Clear WATCH-DOG timer
};

CASSERT(sizeof(Instructions)/sizeof(Instructions[0]) == Z8_last);
