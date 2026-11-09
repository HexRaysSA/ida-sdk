
#include "m7700.hpp"

const instruc_t Instructions[] =
{
  // 7700 :

  { "",            0                          },     // null instruction
  { "adc",         CF_USE1                    },     // addition with carry
  { "and",         CF_USE1                    },     // logical AND
  { "asl",         CF_USE1|CF_CHG1            },     // arithmetic shift left
  { "bbc",         CF_USE1|CF_USE2|CF_USE3    },     // branch on bit clear
  { "bbs",         CF_USE1|CF_USE2|CF_USE3    },     // branch on bit set
  { "bcc",         CF_USE1                    },     // branch on carry clear
  { "bcs",         CF_USE1                    },     // branch on carry set
  { "beq",         CF_USE1                    },     // branch on equal
  { "bmi",         CF_USE1                    },     // branch on result minus
  { "bne",         CF_USE1                    },     // branch on not equal
  { "bpl",         CF_USE1                    },     // branch on result plus
  { "bra",         CF_USE1                    },     // branch always
  { "brk",         0                          },     // force break
  { "bvc",         CF_USE1                    },     // branch on overflow clear
  { "bvs",         CF_USE1                    },     // branch on overflow set
  { "clb",         CF_USE1|CF_USE2|CF_CHG2    },     // clear bit
  { "clc",         0                          },     // clear carry flag
  { "cli",         0                          },     // clear interrupt disable status
  { "clm",         0                          },     // clear m flag
  { "clp",         CF_USE1                    },     // clear processor status
  { "clv",         0                          },     // clear overflow flag
  { "cmp",         CF_USE1|CF_USE2            },     // compare
  { "cpx",         CF_USE1                    },     // compare memory and index register X
  { "cpy",         CF_USE1                    },     // compare memory and index register Y
  { "dec",         CF_USE1|CF_CHG1            },     // decrement by one
  { "dex",         0                          },     // decrement index register X by one
  { "dey",         0                          },     // decrement index register Y by one
  { "div",         CF_USE1                    },     // divide
  { "eor",         CF_USE1|CF_CHG1|CF_USE2    },     // exclusive OR memory with accumulator
  { "inc",         CF_USE1|CF_CHG1            },     // increment by one
  { "inx",         0                          },     // increment index register X by one
  { "iny",         0                          },     // increment index register Y by one
  { "jmp",         CF_USE1                    },     // jump
  { "jsr",         CF_USE1|CF_CALL            },     // jump to subroutine
  { "lda",         CF_USE1|CF_CHG1|CF_USE2    },     // load accumulator from memory
  { "ldm",         CF_USE1|CF_CHG2            },     // load immediate to memory
  { "ldt",         CF_USE1                    },     // load immediate to data bank register
  { "ldx",         CF_USE1                    },     // load index register X from memory
  { "ldy",         CF_USE1                    },     // load index register Y from memory
  { "lsr",         CF_USE1|CF_CHG1            },     // logical shift right
  { "mpy",         CF_USE1                    },     // multiply
  { "mvn",         CF_USE2|CF_CHG1            },     // move negative
  { "mvp",         CF_USE2|CF_CHG1            },     // move positive
  { "nop",         0                          },     // no operation
  { "ora",         CF_USE1|CF_CHG1|CF_USE2    },     // OR memory with accumulator
  { "pea",         CF_USE1                    },     // push effective address
  { "pei",         CF_USE1                    },     // push effective indirect address
  { "per",         CF_USE1                    },     // push effective program counter relative address
  { "pha",         0                          },     // push accumulator A on stack
  { "phb",         0                          },     // push accumulator B on stack
  { "phd",         0                          },     // push direct page register on stack
  { "phg",         0                          },     // push program bank register on stack
  { "php",         0                          },     // push processor status on stack
  { "pht",         0                          },     // push data bank register on stack
  { "phx",         0                          },     // push index register X on stack
  { "phy",         0                          },     // push index register Y on stack
  { "pla",         0                          },     // pull accumulator A from stack
  { "plb",         0                          },     // pull accumulator B from stack
  { "pld",         0                          },     // pull direct page register from stack
  { "plp",         0                          },     // pull processor status from stack
  { "plt",         0                          },     // pull data bank register from stack
  { "plx",         0                          },     // pull index register X from stack
  { "ply",         0                          },     // pull index register Y from stack
  { "psh",         CF_USE1                    },     // push
  { "pul",         CF_USE1                    },     // pull
  { "rla",         CF_USE1                    },     // rotate left accumulator A
  { "rol",         CF_USE2|CF_CHG1            },     // rotate one bit left
  { "ror",         CF_USE2|CF_CHG1            },     // rotate one bit right
  { "rti",         CF_STOP                    },     // return from interrupt
  { "rtl",         CF_STOP                    },     // return from subroutine long
  { "rts",         CF_STOP                    },     // return from subroutine
  { "sbc",         CF_USE1|CF_CHG1|CF_USE2    },     // subtract with carry
  { "seb",         CF_USE1|CF_USE2|CF_CHG2    },     // set bit
  { "sec",         0                          },     // set carry flag
  { "sei",         0                          },     // set interrupt disable status
  { "sem",         0                          },     // set m flag
  { "sep",         CF_USE1                    },     // set processor status
  { "sta",         CF_USE1|CF_CHG2            },     // store accumulator in memory
  { "stp",         0                          },     // stop
  { "stx",         CF_CHG1                    },     // store index register X in memory
  { "sty",         CF_CHG1                    },     // store index register Y in memory
  { "tad",         0                          },     // transfer accumulator A to direct page register
  { "tas",         0                          },     // transfer accumulator A to stack pointer
  { "tax",         0                          },     // transfer accumulator A to index register X
  { "tay",         0                          },     // transfer accumulator A to index register Y
  { "tbd",         0                          },     // transfer accumulator B to direct page register
  { "tbs",         0                          },     // transfer accumulator B to stack pointer
  { "tbx",         0                          },     // transfer accumulator B to index register X
  { "tby",         0                          },     // transfer accumulator B to index register Y
  { "tda",         0                          },     // transfer direct page register to accumulator A
  { "tdb",         0                          },     // transfer direct page register to accumulator B
  { "tsa",         0                          },     // transfer stack pointer to accumulator A
  { "tsb",         0                          },     // transfer stack pointer to accumulator B
  { "tsx",         0                          },     // transfer stack pointer to index register X
  { "txa",         0                          },     // transfer index register X to accumulator A
  { "txb",         0                          },     // transfer index register X to accumulator B
  { "txs",         0                          },     // transfer index register X to stack pointer
  { "txy",         0                          },     // transfer index register X to Y
  { "tya",         0                          },     // transfer index register Y to accumulator A
  { "tyb",         0                          },     // transfer index register Y to accumulator B
  { "tyx",         0                          },     // transfer index register Y to X
  { "wit",         0                          },     // wait
  { "xab",         0                          },     // exchange accumulator A and B

  // 7750 :

  { "asr",         CF_USE1|CF_CHG1            },     // arithmetic shift right
  { "divs",        CF_USE1                    },     // divide with sign
  { "exts",        CF_USE1|CF_CHG1            },     // extention with sign
  { "extz",        CF_USE1|CF_CHG1            },     // extention zero
  { "mpys",        CF_USE1                    }      // multiply with sign
};

CASSERT(qnumber(Instructions) == m7700_last);
