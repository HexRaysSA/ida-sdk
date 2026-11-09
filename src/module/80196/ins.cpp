/*
 *  Interactive disassembler (IDA).
 *  Intel 80196 module
 *
 */

#include "i196.hpp"

const instruc_t Instructions[] =
{
  { "",       0                       },  // Unknown Operation

  { "add",    CF_USE2|CF_USE1|CF_CHG1 },  // Add words (2 operands)
  { "add",    CF_USE3|CF_USE2|CF_CHG1 },  // Add words (3 operands)
  { "addb",   CF_USE2|CF_USE1|CF_CHG1 },  // Add bytes (2 operands)
  { "addb",   CF_USE3|CF_USE2|CF_CHG1 },  // Add bytes (3 operands)

  { "addc",   CF_USE2|CF_USE1|CF_CHG1 },  // Add words with carry
  { "addcb",  CF_USE2|CF_USE1|CF_CHG1 },  // Add bytes with carry

  { "and",    CF_USE2|CF_USE1|CF_CHG1 },  // Logical AND words (2 operands)
  { "and",    CF_USE3|CF_USE2|CF_CHG1 },  // Logical AND words (3 operands)
  { "andb",   CF_USE2|CF_USE1|CF_CHG1 },  // Logical AND bytes (2 operands)
  { "andb",   CF_USE3|CF_USE2|CF_CHG1 },  // Logical AND bytes (3 operands)

  { "bmov",   CF_USE2|CF_USE1         },  // Block move
  { "bmovi",  CF_USE2|CF_USE1         },  // Interruptable block move

  { "br",     CF_JUMP|CF_USE1|CF_STOP },  // Branch indirect

  { "clr",    CF_CHG1                 },  // Clear word
  { "clrb",   CF_CHG1                 },  // Clear byte
  { "clrc",   0                       },  // Clear carry flag
  { "clrvt",  0                       },  // Clear overflow-trap flag

  { "cmp",    CF_USE2|CF_USE1         },  // Compare words
  { "cmpb",   CF_USE2|CF_USE1         },  // Compare bytes
  { "cmpl",   CF_USE2|CF_USE1         },  // Compare long

  { "dec",    CF_USE1|CF_CHG1         },  // Decrement word
  { "decb",   CF_USE1|CF_CHG1         },  // Decrement byte

  { "di",     0                       },  // Disable interrupts

  { "div",    CF_USE2|CF_USE1|CF_CHG1 },  // Divide integers
  { "divb",   CF_USE2|CF_USE1|CF_CHG1 },  // Divide short-integers
  { "divu",   CF_USE2|CF_USE1|CF_CHG1 },  // Divide words, unsigned
  { "divub",  CF_USE2|CF_USE1|CF_CHG1 },  // Divide bytes, unsigned

  { "djnz",   CF_USE2|CF_USE1|CF_CHG1 },  // Decrement and jump if not zero
  { "djnzw",  CF_USE2|CF_USE1|CF_CHG1 },  // Decrement and jump if not zero word

  { "dpts",   0                       },  // Disable peripheral transaction server

  { "ei",     0                       },  // Enable interrupts

  { "epts",   0                       },  // Enable peripheral transaction server

  { "ext",    CF_USE1|CF_CHG1         },  // Sign-extend integer into long-integer
  { "extb",   CF_USE1|CF_CHG1         },  // Sign-extend short-integer into integer

  { "idlpd",  CF_USE1                 },  // Idle/powerdown

  { "inc",    CF_USE1|CF_CHG1         },  // Increment word
  { "incb",   CF_USE1|CF_CHG1         },  // Increment byte

  { "jbc",    CF_USE3|CF_USE2|CF_USE1 },  // Jump if bit is clear
  { "jbs",    CF_USE3|CF_USE2|CF_USE1 },  // Jump if bit is set
  { "jc",     CF_USE1                 },  // Jump if carry flag is set
  { "je",     CF_USE1                 },  // Jump if equal
  { "jge",    CF_USE1                 },  // Jump if signed greater than or equal
  { "jgt",    CF_USE1                 },  // Jump if signed greater than
  { "jh",     CF_USE1                 },  // Jump if higher (unsigned)
  { "jle",    CF_USE1                 },  // Jump if signed less than or equal
  { "jlt",    CF_USE1                 },  // Jump if signed less than
  { "jnc",    CF_USE1                 },  // Jump if carry flag is clear
  { "jne",    CF_USE1                 },  // Jump if not equal
  { "jnh",    CF_USE1                 },  // Jump if not higher (unsigned)
  { "jnst",   CF_USE1                 },  // Jump if sticky bit flag is clear
  { "jnv",    CF_USE1                 },  // Jump if overflow flag is clear
  { "jnvt",   CF_USE1                 },  // Jump if overflow-trap flag is clear
  { "jst",    CF_USE1                 },  // Jump if sticky bit flag is set
  { "jv",     CF_USE1                 },  // Jump if overflow flag is set
  { "jvt",    CF_USE1                 },  // Jump if overflow-trap flag is set

  { "lcall",  CF_USE1|CF_CALL         },  // Long call

  { "ld",     CF_USE2|CF_CHG1         },  // Load word
  { "ldb",    CF_USE2|CF_CHG1         },  // Load byte
  { "ldbse",  CF_USE2|CF_CHG1         },  // Load byte sign-extended
  { "ldbze",  CF_USE2|CF_CHG1         },  // Load byte zero-extended

  { "ljmp",   CF_USE1|CF_STOP         },  // Long jump

  { "mul",    CF_USE2|CF_USE1|CF_CHG1 },  // Multiply integers (2 operands)
  { "mul",    CF_USE3|CF_USE2|CF_CHG1 },  // Multiply integers (3 operands)
  { "mulb",   CF_USE2|CF_USE1|CF_CHG1 },  // Multiply short-integers (2 operands)
  { "mulb",   CF_USE3|CF_USE2|CF_CHG1 },  // Multiply short-integers (3 operands)
  { "mulu",   CF_USE2|CF_USE1|CF_CHG1 },  // Multiply words, unsigned (2 operands)
  { "mulu",   CF_USE3|CF_USE2|CF_CHG1 },  // Multiply words, unsigned (3 operands)
  { "mulub",  CF_USE2|CF_USE1|CF_CHG1 },  // Multiply bytes, unsigned (2 operands)
  { "mulub",  CF_USE3|CF_USE2|CF_CHG1 },  // Multiply bytes, unsigned (3 operands)

  { "neg",    CF_USE1|CF_CHG1         },  // Negate integer
  { "negb",   CF_USE1|CF_CHG1         },  // Negate short-integer

  { "nop",    0                       },  // No operation

  { "norml",  CF_USE1|CF_CHG2|CF_CHG1 },  // Normalize long-integer

  { "not",    CF_USE1|CF_CHG1         },  // Complement word
  { "notb",   CF_USE1|CF_CHG1         },  // Complement byte

  { "or",     CF_USE2|CF_USE1|CF_CHG1 },  // Logical OR words
  { "orb",    CF_USE2|CF_USE1|CF_CHG1 },  // Logical OR bytes

  { "pop",    CF_CHG1                 },  // Pop word
  { "popa",   0                       },  // Pop all
  { "popf",   0                       },  // Pop flags
  { "push",   CF_USE1                 },  // Push word
  { "pusha",  0                       },  // Push all
  { "pushf",  0                       },  // Push flags

  { "ret",    CF_STOP                 },  // Return from subroutine

  { "rst",    CF_STOP                 },  // Reset system

  { "scall",  CF_USE1|CF_CALL         },  // Short call

  { "setc",   0                       },  // Set carry flag

  { "shl",    CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Shift word left
  { "shlb",   CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Shift byte left
  { "shll",   CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Shift double-word left
  { "shr",    CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Logical right shift word
  { "shra",   CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Arithmetic right shift word
  { "shrab",  CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Arithmetic right shift byte
  { "shral",  CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Arithmetic right shift double-word
  { "shrb",   CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Logical right shift byte
  { "shrl",   CF_SHFT|CF_USE2|CF_USE1|CF_CHG1 },  // Logical right shift double-word

  { "sjmp",   CF_USE1|CF_STOP         },  // Short jump

  { "skip",   CF_USE1                 },  // Two byte no-operation

  { "st",     CF_USE1|CF_CHG2         },  // Store word
  { "stb",    CF_USE1|CF_CHG2         },  // Store byte

  { "sub",    CF_USE2|CF_USE1|CF_CHG1 },  // Subtract words (2 operands)
  { "sub",    CF_USE3|CF_USE2|CF_CHG1 },  // Subtract words (3 operands)
  { "subb",   CF_USE2|CF_USE1|CF_CHG1 },  // Subtract bytes (2 operands)
  { "subb",   CF_USE3|CF_USE2|CF_CHG1 },  // subtract bytes (3 operands)

  { "subc",   CF_USE2|CF_USE1|CF_CHG1 },  // Subtract words with borrow
  { "subcb",  CF_USE2|CF_USE1|CF_CHG1 },  // Subtract bytes with borrow

  { "tijmp",  CF_JUMP|CF_USE3|CF_USE2|CF_USE1|CF_STOP }, // Table indirect jump

  { "trap",   0                       },  // Software trap

  { "xch",    CF_USE2|CF_USE1|CF_CHG2|CF_CHG1 },  // Exchange word
  { "xchb",   CF_USE2|CF_USE1|CF_CHG2|CF_CHG1 },  // Exchange byte

  { "xor",    CF_USE2|CF_USE1|CF_CHG1 },  // Logical exclusive-or words
  { "xorb",   CF_USE2|CF_USE1|CF_CHG1 },  // Logical exclusive-or bytes

// 8x196NU, NP instructions

  { "ebmovi", CF_USE1|CF_USE2         },  // Extended interruptable block move
  { "ebr",    CF_USE1|CF_STOP         },  // Extended branch indirect
  { "ecall",  CF_USE1|CF_CALL         },  // Extended call
  { "ejmp",   CF_USE1|CF_STOP         },  // Extended jump
  { "eld",    CF_CHG1|CF_USE2         },  // Extended load word
  { "eldb",   CF_CHG1|CF_USE2         },  // Extended load byte
  { "est",    CF_USE1|CF_CHG2         },  // Extended store word
  { "estb",   CF_USE1|CF_CHG2         },  // Extended store byte

};

CASSERT(qnumber(Instructions) == I196_last);
