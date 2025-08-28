
#include "m740.hpp"

const instruc_t Instructions[] =
{
  { "",            0                           },    // null instruction
  { "adc",        CF_USE1                      },    // add with carry
  { "and",        CF_USE1                      },    // logical and
  { "asl",        CF_USE1                      },    // arithmetic shift left
  { "bbc",        CF_USE1|CF_USE2|CF_USE3      },    // branch on bit clear
  { "bbs",        CF_USE1|CF_USE2|CF_USE3      },    // branch on bit set
  { "bcc",        CF_USE1                      },    // branch on carry clear
  { "bcs",        CF_USE1                      },    // branch on carry set
  { "beq",        CF_USE1                      },    // branch on equal
  { "bit",        CF_USE1                      },    // test bit in memory with accumulator
  { "bmi",        CF_USE1                      },    // branch on result minus
  { "bne",        CF_USE1                      },    // branch on not equal
  { "bpl",        CF_USE1                      },    // branch on result plus
  { "bra",        CF_USE1|CF_STOP              },    // branch always
  { "brk",        0                            },    // force break
  { "bvc",        CF_USE1                      },    // branch on overflow clear
  { "bvs",        CF_USE1                      },    // branch on overflow set
  { "clb",        CF_USE1|CF_USE2|CF_CHG2      },    // clear bit
  { "clc",        0                            },    // clear carry flag
  { "cld",        0                            },    // clear decimal mode
  { "cli",        0                            },    // clear interrupt disable status
  { "clt",        0                            },    // clear transfer flag
  { "clv",        0                            },    // clear overflow flag
  { "cmp",        CF_USE1                      },    // compare
  { "com",        CF_USE1|CF_CHG1              },    // complement
  { "cpx",        CF_USE1                      },    // compare memory and index register X
  { "cpy",        CF_USE1                      },    // compare memory and index register Y
  { "dec",        CF_USE1|CF_CHG1              },    // decrement by one
  { "dex",        0                            },    // decrement index register X by one
  { "dey",        0                            },    // decrement index register Y by one
  { "div",        CF_USE1                      },    // divide memory by accumulator
  { "eor",        CF_USE1                      },    // exclusive or memory with accumulator
  { "inc",        CF_USE1|CF_CHG1              },    // increment by one
  { "inx",        0                            },    // increment index register X by one
  { "iny",        0                            },    // increment index register Y by one
  { "jmp",        CF_USE1|CF_STOP              },    // jump
  { "jsr",        CF_USE1|CF_CALL              },    // jump to subroutine
  { "lda",        CF_USE1                      },    // load accumulator with memory
  { "ldm",        CF_USE1|CF_USE2|CF_CHG2      },    // load immediate data to memory
  { "ldx",        CF_USE1                      },    // load index register X from memory
  { "ldy",        CF_USE1                      },    // load index register Y from memory
  { "lsr",        CF_USE1|CF_CHG1              },    // logical shift right
  { "mul",        CF_USE1                      },    // multiply accumulator and memory
  { "nop",        0                            },    // no operation
  { "ora",        CF_USE1                      },    // or memory with accumulator
  { "pha",        0                            },    // push accumulator on stack
  { "php",        0                            },    // push processor status on stack
  { "pla",        0                            },    // pull accumulator from stack
  { "plp",        0                            },    // pull processor status from stack
  { "rol",        CF_USE1|CF_CHG1              },    // rotate one bit left
  { "ror",        CF_USE1|CF_CHG1              },    // rotate one bit right
  { "rrf",        CF_USE1|CF_CHG1              },    // rotate right of four bits
  { "rti",        CF_STOP                      },    // return from interrupt
  { "rts",        CF_STOP                      },    // return from subroutine
  { "sbc",        CF_USE1                      },    // subtract with carry
  { "seb",        CF_USE1|CF_USE2|CF_CHG2      },    // set bit
  { "sec",        0                            },    // set carry flag
  { "sed",        0                            },    // set decimal mode
  { "sei",        0                            },    // set interrupt disable flag
  { "set",        0                            },    // set transfert flag
  { "sta",        CF_CHG1                      },    // store accumulator in memory
  { "stp",        0                            },    // stop
  { "stx",        CF_CHG1                      },    // store index register X in memory
  { "sty",        CF_CHG1                      },    // store index register Y in memory
  { "tax",        0                            },    // transfert accumulator to index register X
  { "tay",        0                            },    // transfert accumulator to index register Y
  { "tst",        CF_USE1                      },    // test for negative or zero
  { "tsx",        0                            },    // transfert stack pointer to index register X
  { "txa",        0                            },    // transfert index register X to accumulator
  { "txs",        0                            },    // transfert index register X to stack pointer
  { "tya",        0                            },    // transfert index register Y to accumulator
  { "wit",        0                            }    // wait
};

CASSERT(qnumber(Instructions) == m740_last);
