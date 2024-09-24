
#include "m32r.hpp"

// m32r instructions definition
const instruc_t Instructions[] =
{
  { "",           0                              },    // Null instruction
  { "add",        CF_USE1|CF_USE2|CF_CHG1        },    // Add
  { "add3",       CF_USE2|CF_USE3|CF_CHG1        },    // Add 3-operand
  { "addi",       CF_USE1|CF_USE2|CF_CHG1        },    // Add immediate
  { "addv",       CF_USE1|CF_USE2|CF_CHG1        },    // Add with overflow checking
  { "addv3",      CF_USE2|CF_USE3|CF_CHG1        },    // Add 3-operand with overflow checking
  { "addx",       CF_USE1|CF_USE2|CF_CHG1        },    // Add with carry
  { "and",        CF_USE1|CF_USE2|CF_CHG1        },    // AND
  { "and3",       CF_USE2|CF_USE3|CF_CHG1        },    // AND 3-operand
  { "bc",         CF_USE1                        },    // Branch on C-bit
  { "beq",        CF_USE1|CF_USE2|CF_USE3        },    // Branch on equal
  { "beqz",       CF_USE1|CF_USE2                },    // Branch on equal zero
  { "bgez",       CF_USE1|CF_USE2                },    // Branch on greater than or equal zero
  { "bgtz",       CF_USE1|CF_USE2                },    // Branch on greater than zero
  { "bl",         CF_USE1|CF_CALL                },    // Branch and link
  { "blez",       CF_USE1|CF_USE2                },    // Branch on less than or equal zero
  { "bltz",       CF_USE1|CF_USE2                },    // Branch on less than zero
  { "bnc",        CF_USE1                        },    // Branch on not C-bit
  { "bne",        CF_USE1|CF_USE2|CF_USE3        },    // Branch on not equal
  { "bnez",       CF_USE1|CF_USE2                },    // Branch on not equal zero
  { "bra",        CF_USE1|CF_STOP                },    // Branch
  { "cmp",        CF_USE1|CF_USE2                },    // Compare
  { "cmpi",       CF_USE1|CF_USE2                },    // Compare immediate
  { "cmpu",       CF_USE1|CF_USE2                },    // Compare unsigned
  { "cmpui",      CF_USE1|CF_USE2                },    // Compare unsigned immediate
  { "div",        CF_USE1|CF_USE2|CF_CHG1        },    // Divide
  { "divu",       CF_USE1|CF_USE2|CF_CHG1        },    // Divide unsigned
  { "jl",         CF_USE1|CF_CALL|CF_JUMP        },    // Jump and link
  { "jmp",        CF_USE1|CF_JUMP|CF_STOP        },    // Jump
  { "ld",         CF_USE2|CF_CHG1                },    // Load
  { "ld24",       CF_USE2|CF_CHG1                },    // Load 24-bit immediate
  { "ldb",        CF_USE2|CF_CHG1                },    // Load byte
  { "ldh",        CF_USE2|CF_CHG1                },    // Load halfword
  { "ldi",        CF_USE2|CF_CHG1                },    // Load immediate
  { "ldub",       CF_USE2|CF_CHG1                },    // Load unsigned byte
  { "lduh",       CF_USE2|CF_CHG1                },    // Load unsigned halfword
  { "lock",       CF_USE2|CF_CHG1                },    // Load locked
  { "machi",      CF_USE1|CF_USE2                },    // Multiply-accumulate high-order halfwords
  { "maclo",      CF_USE1|CF_USE2                },    // Multiply-accumulate low-order halfwords
  { "macwhi",     CF_USE1|CF_USE2                },    // Multiply-accumulate word and high-order halfword
  { "macwlo",     CF_USE1|CF_USE2                },    // Multiply-accumulate word and low-order halfword
  { "mul",        CF_USE1|CF_USE2|CF_CHG1        },    // Multiply
  { "mulhi",      CF_USE1|CF_USE2                },    // Multiply high-order halfwords
  { "mullo",      CF_USE1|CF_USE2                },    // Multiply low-order halfwords
  { "mulwhi",     CF_USE1|CF_USE2                },    // Multiply word high-order halfwords
  { "mulwlo",     CF_USE1|CF_USE2                },    // Multiply word low-order halfwords
  { "mv",         CF_USE2|CF_CHG1                },    // Move register
  { "mvfachi",    CF_CHG1                        },    // Move from accumulator high-order word
  { "mvfaclo",    CF_CHG1                        },    // Move from accumulator low-order word
  { "mvfacmi",    CF_CHG1                        },    // Move from accumulator middle-order word
  { "mvfc",       CF_USE2|CF_CHG1                },    // Move from control register
  { "mvtachi",    CF_USE1                        },    // Move to accumulator high-order word
  { "mvtaclo",    CF_USE1                        },    // Move to accumulator low-order word
  { "mvtc",       CF_USE2|CF_CHG1                },    // Move to control register
  { "neg",        CF_USE2|CF_CHG1                },    // Negate
  { "nop",        0                              },    // No operation
  { "not",        CF_USE2|CF_CHG1                },    // Logical NOT
  { "or",         CF_USE1|CF_USE2|CF_CHG1        },    // OR
  { "or3",        CF_USE2|CF_USE3|CF_CHG1        },    // OR 3-operand
  { "push",       CF_USE1                        },    // Push, mnem for st reg, @-sp
  { "pop",        CF_CHG1                        },    // Pop, mnem for ld reg, @sp+
  { "rac",        0                              },    // Round accumulator
  { "rach",       0                              },    // Round accumulator halfword
  { "rem",        CF_USE1|CF_USE2|CF_CHG1        },    // Remainder
  { "remu",       CF_USE1|CF_USE2|CF_CHG1        },    // Remainder unsigned
  { "rte",        CF_STOP                        },    // Return from EIT
  { "seth",       CF_USE2|CF_CHG1                },    // Set high-order 16-bit
  { "sll",        CF_USE1|CF_USE2|CF_CHG1        },    // Shift left logical
  { "sll3",       CF_USE2|CF_USE3|CF_CHG1        },    // Shift left logical 3-operand
  { "slli",       CF_USE1|CF_USE2|CF_CHG1        },    // Shift left logical immediate
  { "sra",        CF_USE1|CF_USE2|CF_CHG1        },    // Shirt right arithmetic
  { "sra3",       CF_USE2|CF_USE3|CF_CHG1        },    // Shirt right arithmetic 3-operand
  { "srai",       CF_USE1|CF_USE2|CF_CHG1        },    // Shirt right arithmetic immediate
  { "srl",        CF_USE1|CF_USE2|CF_CHG1        },    // Shift right logical
  { "srl3",       CF_USE2|CF_USE3|CF_CHG1        },    // Shift right logical 3-operand
  { "srli",       CF_USE1|CF_USE2|CF_CHG1        },    // Shift right logical immediate
  { "st",         CF_USE1|CF_USE2|CF_CHG1        },    // Store
  { "stb",        CF_USE1|CF_CHG2                },    // Store byte
  { "sth",        CF_USE1|CF_CHG2                },    // Store halfword
  { "sub",        CF_USE1|CF_USE2|CF_CHG1        },    // Substract
  { "subv",       CF_USE1|CF_USE2|CF_CHG1        },    // Substract with overflow checking
  { "subx",       CF_USE1|CF_USE2|CF_CHG1        },    // Substract with borrow
  { "trap",       CF_USE1                        },    // Trap
  { "unlock",     CF_USE1|CF_CHG2                },    // Store unlocked
  { "xor",        CF_USE1|CF_USE2|CF_CHG1        },    // Exclusive OR
  { "xor3",       CF_USE2|CF_USE3|CF_CHG1        },    // Exclusive OR 3-operand

  // M32RX :

  { "bcl",        CF_USE1                                },
  { "bncl",       CF_USE1                                },
  { "cmpeq",      CF_USE1|CF_USE2                        },
  { "cmpz",       CF_USE1                                },
  { "divh",       CF_USE1|CF_USE2|CF_CHG1                },
  { "jc",         CF_USE1                                },
  { "jnc",        CF_USE1                                },
  { "machi",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'machi' 3-operand
  { "maclo",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'maclo' 3-operand
  { "macwhi",     CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'macwhi' 3-operand
  { "macwlo",     CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'macwlo' 3-operand
  { "mulhi",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'mulhi' 3-operand
  { "mullo",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'mullo' 3-operand
  { "mulwhi",     CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'mulwhi' 3-operand
  { "mulwlo",     CF_USE1|CF_USE2|CF_USE3|CF_CHG3        },    // 'mulwlo' 3-operand
  { "mvfachi",    CF_USE2|CF_CHG1                        },    // 'mvfachi' 3-operand
  { "mvfaclo",    CF_USE2|CF_CHG1                        },    // 'mvfaclo' 3-operand
  { "mvfacmi",    CF_USE2|CF_CHG1                        },    // 'mvfacmi' 3-operand
  { "mvtachi",    CF_USE1|CF_CHG2                        },    // 'mvtachi' 3-operand
  { "mvtaclo",    CF_USE1|CF_CHG2                        },    // 'mvtaclo' 3-operand
  { "rac",        CF_USE2|CF_CHG1                        },    // 'rac' 3 operand
  { "rach",       CF_USE2|CF_CHG1                        },    // 'rach' 3 operand
  { "satb",       CF_USE2|CF_CHG1                        },
  { "sath",       CF_USE2|CF_CHG1                        },
  { "sat",        CF_USE2|CF_CHG1                        },
  { "pcmpbz",     CF_USE1                                },
  { "sadd",       0                                      },
  { "macwu1",     CF_USE1|CF_USE2                        },
  { "msblo",      CF_USE1|CF_USE2                        },
  { "mulwu1",     CF_USE1|CF_USE2                        },
  { "maclh1",     CF_USE1|CF_USE2                        },
  { "sc",         0                                      },
  { "snc",        0                                      },

// Floating point
  { "fadd",       CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point add
  { "fsub",       CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point subtract
  { "fmul",       CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point multiply
  { "fdiv",       CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point divede
  { "fmadd",      CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point multiply and add
  { "fmsub",      CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point multiply and subtract
  { "itof",       CF_CHG1|CF_USE2                        },    // Integer to float
  { "utof",       CF_CHG1|CF_USE2                        },    // Unsigned integer to float
  { "ftoi",       CF_CHG1|CF_USE2                        },    // Float to integer
  { "ftos",       CF_CHG1|CF_USE2                        },    // Float to short
  { "fcmp",       CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point compare
  { "fcmpe",      CF_CHG1|CF_USE2|CF_USE3                },    // Floating-point compare with exeption if unordered
// Bit Operation Instructions
  { "bset",       CF_USE1|CF_CHG2                        },    // Bit set
  { "bclr",       CF_USE1|CF_CHG2                        },    // Bit clear
  { "btst",       CF_USE1|CF_USE2                        },    // Bit test
  { "setpsw",     CF_USE1                                },    // Set PSW
  { "clrpsw",     CF_USE1                                },    // Clear PSW
};

CASSERT(qnumber(Instructions) == m32r_last);
