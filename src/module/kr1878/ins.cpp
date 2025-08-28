
#include "kr1878.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  { "mov",        CF_USE2|CF_CHG1                 },
  { "cmp",        CF_USE1|CF_USE2                 },      // Compare
  { "add",        CF_USE1|CF_USE2|CF_CHG1         },      // Addition
  { "sub",        CF_USE1|CF_USE2|CF_CHG1         },      // Subtract
  { "and",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical AND
  { "or",         CF_USE1|CF_USE2|CF_CHG1         },      // Logical Inclusive OR
  { "xor",        CF_USE1|CF_USE2|CF_CHG1         },      // Logical Exclusive OR

  { "movl",       CF_USE2|CF_CHG1                 },
  { "cmpl",       CF_USE1|CF_USE2                 },      // Compare
  { "addl",       CF_USE1|CF_USE2|CF_CHG1         },      // Addition
  { "subl",       CF_USE1|CF_USE2|CF_CHG1         },      // Subtract
  { "bic",        CF_USE1|CF_USE2|CF_CHG1         },
  { "bis",        CF_USE1|CF_USE2|CF_CHG1         },
  { "btg",        CF_USE1|CF_USE2|CF_CHG1         },
  { "btt",        CF_USE1|CF_USE2|CF_CHG1         },

  { "swap",       CF_USE1|CF_CHG1                 },
  { "neg",        CF_USE1|CF_CHG1                 },
  { "not",        CF_USE1|CF_CHG1                 },
  { "shl",        CF_USE1|CF_CHG1                 },      // Shift Left
  { "shr",        CF_USE1|CF_CHG1                 },      // Shift Right
  { "shra",       CF_USE1|CF_CHG1                 },      // Arithmetic Shift Right
  { "rlc",        CF_USE1|CF_CHG1                 },      // Rotate Left
  { "rrc",        CF_USE1|CF_CHG1                 },      // Rotate Right
  { "adc",        CF_USE1|CF_CHG1                 },      // Add with Carry
  { "sbc",        CF_USE1|CF_CHG1                 },      // Subtract with Carry

  { "ldr",        CF_USE2|CF_CHG1                 },
  { "mtpr",       CF_USE2|CF_CHG1                 },
  { "mfpr",       CF_USE2|CF_CHG1                 },
  { "push",       CF_USE1                         },
  { "pop",        CF_CHG1                         },
  { "sst",        CF_USE1                         },
  { "cst",        CF_USE1                         },
  { "tof",        0                               },
  { "tdc",        0                               },

  { "jmp",        CF_USE1|CF_STOP|CF_JUMP         },      // Jump
  { "jsr",        CF_USE1|CF_CALL                 },      // Jump to Subroutine
  { "jnz",        CF_USE1|CF_JUMP                 },      // Jump
  { "jz",         CF_USE1|CF_JUMP                 },      // Jump
  { "jns",        CF_USE1|CF_JUMP                 },      // Jump
  { "js",         CF_USE1|CF_JUMP                 },      // Jump
  { "jnc",        CF_USE1|CF_JUMP                 },      // Jump
  { "jc",         CF_USE1|CF_JUMP                 },      // Jump
  { "ijmp",       CF_STOP                         },      // Jump
  { "ijsr",       CF_STOP                         },      // Jump to Subroutine
  { "rts",        CF_STOP                         },      // Return from Subroutine
  { "rtsc",       CF_USE1|CF_STOP                 },      // Return from Subroutine
  { "rti",        CF_STOP                         },      // Return from Interrupt

  { "nop",        0                               },      // No Operation
  { "wait",       0                               },
  { "stop",       0                               },
  { "reset",      0                               },
  { "sksp",       0                               },

};

CASSERT(qnumber(Instructions) == KR1878_last);
