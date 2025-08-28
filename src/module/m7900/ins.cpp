/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"



const instruc_t Instructions[] =
{

  { "",  0                               },   // Unknown Operation

  { "abs",    CF_CHG1                    },   // ABSolute
  { "absd",   CF_CHG1                    },   // ABSolute at Double-word

  { "adc",    CF_CHG1 | CF_USE2          },   // ADd with Carry
  { "adcb",   CF_CHG1 | CF_USE2          },   // ADd with Carry at Byte
  { "adcd",   CF_CHG1 | CF_USE2          },   // ADd with Carry at Double-word

  { "add",    CF_CHG1 | CF_USE2          },   // Addition

  { "addb",   CF_CHG1 | CF_USE2          },   // ADD at Byte

  { "addd",   CF_CHG1 | CF_USE2          },   // ADD at Double-word
  { "addm",   CF_CHG1 | CF_USE2          },   // ADD immediate and Memory
  { "addmb",  CF_CHG1 | CF_USE2          },   // ADD immediate and Memory at Byte
  { "addmd",  CF_CHG1 | CF_USE2          },   // ADD immediate and Memory at Double-word
  { "adds",   CF_USE1                    },   // ADD Stack pointer and immediate
  { "addx",   CF_USE1                    },   // ADD index register X and immediate
  { "addy",   CF_USE1                    },   // ADD index register Y and immediate

  { "and",    CF_CHG1 | CF_USE2          },   // Logical AND
  { "andb",   CF_CHG1 | CF_USE2          },   // logical AND between immediate (Byte)
  { "andm",   CF_CHG1 | CF_USE2          },   // logical AND between immediate value and Memory
  { "andmb",  CF_CHG1 | CF_USE2          },   // logical AND between immediate value and Memory (Byte)
  { "andmd",  CF_CHG1 | CF_USE2          },   // logical AND between immediate value and Memory (Double word)


  { "asl",    CF_CHG1                    },   // Arithmetic Shift to Left
  { "asl",    CF_CHG1 | CF_USE2          },   // Arithmetic Shift to Left by n bits
  { "asld",   CF_CHG1 | CF_USE2          },   // Arithmetic Shift to Left by n bits (Double word)

  { "asr",    CF_CHG1                    },   // Arithmetic Shift to Right
  { "asr",    CF_CHG1 | CF_USE2          },   // Arithmetic Shift to Right by n bits
  { "asrd",   CF_CHG1 | CF_USE2          },   // Arithmetic Shift to Right by n bits (Double word)

  { "bbc",    CF_USE1 | CF_USE2 | CF_USE3 },   // Branch on Bit Clear
  { "bbcb",   CF_USE1 | CF_USE2 | CF_USE3 },   // Branch on Bit Clear (Byte)
  { "bbs",    CF_USE1 | CF_USE2 | CF_USE3 },   // Branch on Bit Set
  { "bbsb",   CF_USE1 | CF_USE2 | CF_USE3 },   // Branch on Bit Set (Byte)

  { "bcc",    CF_USE1                     },   // Branch on Carry Clear
  { "bcs",    CF_USE1                     },   // Branch on Carry Set
  { "beq",    CF_USE1                     },   // Branch on EQual
  { "bge",    CF_USE1                     },   // Branch on Greater or Equal
  { "bgt",    CF_USE1                     },   // Branch on Greater Than
  { "bgtu",   CF_USE1                     },   // Branch on Greater Than with Unsign
  { "ble",    CF_USE1                     },   // Branch on Less or Equal
  { "bleu",   CF_USE1                     },   // Branch on Less Equal with Unsign
  { "blt",    CF_USE1                     },   // Branch on Less Than
  { "bmi",    CF_USE1                     },   // Branch on result MInus
  { "bne",    CF_USE1                     },   // Branch on Not Equal
  { "bpl",    CF_USE1                     },   // Branch on result PLus
  { "bra",    CF_USE1 | CF_JUMP | CF_STOP },   // BRanch Always
  { "bral",   CF_USE1 | CF_JUMP | CF_STOP },   // BRanch Always

  { "brk",    0                           },   // run int 0xFFFA

  { "bsc",    CF_USE1 | CF_USE2 | CF_USE3 },   // Branch on Single bit Clear
  { "bsr",    CF_USE1 | CF_CALL           },   // Branch to SubRoutine
  { "bss",    CF_USE1 | CF_USE2 | CF_USE3 },   // Branch on Single bit Set

  { "bvc",    CF_USE1                     },   // Branch on oVerflow Clear
  { "bvs",    CF_USE1                     },   // Branch on oVerflow Set

  { "cbeq",   CF_USE1 | CF_USE2 | CF_USE3 },   // Compare immediate and Branch on EQual
  { "cbeqb",  CF_USE1 | CF_USE2 | CF_USE3 },   // Compare immediate and Branch on EQual at Byte
  { "cbne",   CF_USE1 | CF_USE2 | CF_USE3 },   // Compare immediate and Branch on Not Equal
  { "cbneb",  CF_USE1 | CF_USE2 | CF_USE3 },   // Compare immediate and Branch on Not Equal at Byte

  { "clc", 0                              },   // CLear Carry flag
  { "cli", 0                              },   // CLear Interrupt disable status
  { "clm", 0                              },   // CLear M flag
  { "clp",    CF_USE1                     },   // CLear Processor status

  { "clr",    CF_CHG1                     },   // CLeaR accumulator
  { "clrb",   CF_CHG1                     },   // CLeaR accumulator at Byte
  { "clrm",   CF_CHG1                     },   // CLeaR Memory
  { "clrmb",  CF_CHG1                     },   // CLeaR Memory at Byte
  { "clrx",   0                           },   // CLeaR index register X
  { "clry",   0                           },   // CLeaR index register Y

  { "clv",    0                           },   // CLear oVerflow flag

  { "cmp",   CF_USE1 | CF_USE2            },   // CoMPare
  { "cmpb",  CF_USE1 | CF_USE2            },   // CoMPare at Byte
  { "cmpd",  CF_USE1 | CF_USE2            },   // CoMPare at Double-word
  { "cmpm",  CF_USE1 | CF_USE2            },   // CoMPare immediate with Memory
  { "cmpmb", CF_USE1 | CF_USE2            },   // CoMPare immediate with Memory at Byte
  { "cmpmd", CF_USE1 | CF_USE2            },   // CoMPare immediate with Memory at Double-word

  { "cpx",   CF_USE1                      },   // ComPare memory and index register X
  { "cpy",   CF_USE1                      },   // ComPare memory and index register Y

  { "debne", CF_USE1 | CF_USE2  | CF_USE3 },   // DEcrement memory and Branch on Not Equal

  { "dec",   CF_CHG1                      },   // DECrement by one
  { "dex", 0                              },   // DEcrement index register X by one
  { "dey", 0                              },   // DEcrement index register Y by one

  { "div",   CF_USE1                      },   // DIVide unsigned
  { "divs",  CF_USE1                      },   // DIVide with Sign
  { "dxbne", CF_USE1  | CF_USE2           },   // Decrement index register X and Branch on Not Equal
  { "dybne", CF_USE1  | CF_USE2           },   // Decrement index register Y and Branch on Not Equal

  { "eor",   CF_CHG1 | CF_USE2            },   // Exclusive OR memory with accumulator
  { "eorb",  CF_CHG1 | CF_USE2            },   // Exclusive OR immediate with accumulator at Byte
  { "eorm",  CF_CHG1 | CF_USE2            },   // Exclusive OR immediate with Memory
  { "eormb", CF_CHG1 | CF_USE2            },   // Exclusive OR immediate with Memory at Byte
  { "eormd", CF_CHG1 | CF_USE2            },   // Exclusive OR immediate with Memory at Double-word

  { "exts",  CF_CHG1                      },   // EXTension Sign
  { "extsd", CF_CHG1                      },   // EXTension Sign at Double-word
  { "extz",  CF_CHG1                      },   // EXTension Zero
  { "extzd", CF_CHG1                      },   // EXTension Zero at Double-word

  { "inc", CF_CHG1                        },   // INCrement by one
  { "inx", 0                              },   // INcrement index register X by one
  { "iny", 0                              },   // INcrement index register y by one

  { "jmp",   CF_USE1 | CF_JUMP | CF_STOP  },   // JuMP16
  { "jmpl",  CF_USE1 | CF_JUMP | CF_STOP  },   // Jump24

  { "jsr",   CF_USE1 | CF_CALL            },   // Jump to SubRoutine16
  { "jsrl",  CF_USE1 | CF_CALL            },   // Jump to SubRoutine24


  { "lda",  CF_CHG1 | CF_USE2             },   // LoaD Accumulator from memory
  { "ldab", CF_CHG1 | CF_USE2             },   // LoaD Accumulator from memory at Byte
  { "ldad", CF_CHG1 | CF_USE2             },   // LoaD Accumulator from memory at Double-word
  { "ldd",  CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 |  CF_USE5              },   // LoaD immediate to Direct page register n

  { "ldt",  CF_USE1                       },   // LoaD immediate to DaTa bank register
  { "ldx",  CF_USE1                       },   // LoaD index register X from memory
  { "ldxb", CF_USE1                       },   // LoaD index register X from memory at Byte
  { "ldy",  CF_USE1                       },   // LoaD index register Y from memory
  { "ldyb", CF_USE1                       },   // LoaD index register Y from memory at Byte

  { "lsr",   CF_CHG1                      },   // Logical Shift Right
  { "lsr",   CF_USE2 | CF_CHG1            },   // Logical n bits Shift Right
  { "lsrd",  CF_USE2 | CF_CHG1            },   // Logical n bits Shift Right at Double-word

  { "movm",  CF_USE2 | CF_CHG1            },   // MOVe Memory to memory
  { "movmb", CF_USE2 | CF_CHG1            },   // MOVe Memory to memory at Byte
  { "movr",  CF_USE1 | CF_HLL             },   // MOVe Repeat memory to memory
  { "movrb", CF_USE1 | CF_HLL             },   // MOVe Repeat memory to memory at Byte

  { "mpy",   CF_USE1                      },  // MultiPlY
  { "mpys",  CF_USE1                      },  // MultiPlY with Sign

  { "mvn",   CF_USE1 | CF_USE2            },  // MoVe Negative
  { "mvp",   CF_USE1 | CF_USE2            },  // MoVe Positive

  { "neg",   CF_CHG1                      },  // NEGative
  { "negd",  CF_CHG1                      },  // NEGative at Double-word
  { "nop",   0                            },  // No OPeration


  { "ora",   CF_CHG1 | CF_USE2            }, // OR memory with Accumulator
  { "orab",  CF_CHG1 | CF_USE2            },  // OR immediate with Accumulator at Byte
  { "oram",  CF_CHG1 | CF_USE2            },  // OR immediAte with Memory
  { "oramb", CF_CHG1 | CF_USE2            },  // OR immediAte with Memory at Byte
  { "oramd", CF_CHG1 | CF_USE2            },  // OR immediAte with Memory at Double-word


  { "pea",   CF_USE1                      },  // Push Effective Address
  { "pei",   CF_USE1                      },  // Push Effective Indirect address
  { "per",   CF_USE1                      },  // Push Effective program counter Relative address
  { "pha",   0                            },  // PusH accumulator A on stack
  { "phb",   0                            },  // PusH accumulator B on stack
  { "phd",   0                            },  // PusH Direct page register on stack
  { "phd",   CF_USE1                      },  // PusH Direct page register n on stack
  { "phg",   0                            },  // PusH proGram bank register on stack

  { "phld",  CF_USE1 | CF_HLL             },  // PusH dpr n to stack and Load immediate to Dpr n

  { "php",   0                            },  // PusH Processor status on stack
  { "pht",   0                            },  // PusH daTa bank register on stack
  { "phx",   0                            },  // PusH index register X on stack
  { "phy",   0                            },  // PusH index register Y on stack

  { "pla",   0                            },  // PuLl accumulator A from stack
  { "plb",   0                            },  // PuLl accumulator B from stack
  { "pld",   0                            },  // PuLl Direct page register from stack
  { "pld",   CF_USE1                      },  // PuLl Direct page register n from stack
  { "plp",   0                            },  // PuLl Processor status from stack
  { "plt",   0                            },  // PuLl daTa bank register from stack
  { "plx",   0                            },  // PuLl index register X from stack
  { "ply",   0                            },  // PuLl index register Y from stack

  { "psh",   CF_USE1                      },  // PuSH
  { "pul",   CF_USE1                      },  // PuLl

  { "rla",   CF_USE1                      },  // Rotate Left accumulator A
  { "rmpa",  CF_USE1                      },  // Repeat Multiply and Accumulate

  { "rol",   CF_CHG1                      },  // ROtate one bit Left
  { "rol",   CF_USE2 | CF_CHG1            },  // n bits ROtate Left
  { "rold",  CF_USE2 | CF_CHG1            },  // n bits ROtate Left at Double-word

  { "ror",   CF_CHG1                      },  // ROtate one bit Right
  { "ror",   CF_USE2 | CF_CHG1            },  // n bits ROtate Right
  { "rord",  CF_USE2 | CF_CHG1            },  // n bits ROtate Right at Double-word

  { "rti",   CF_STOP                      },  // Return from Interrupt
  { "rtl",   CF_STOP                      },  // ReTurn from subroutine Long
  { "rtld",  CF_USE1 | CF_STOP            },  // ReTurn from subroutine Long and pull Direct page register n
  { "rts",   CF_STOP                      },  // ReTurn from Subroutine
  { "rtsd",  CF_USE1 | CF_STOP            },  // ReTurn from Subroutine and pull Direct page register n


  { "sbc",   CF_USE1 | CF_USE2            },  // SuBtract with Carry
  { "sbcb",  CF_USE1 | CF_USE2            },  // SuBtract with Carry at Byte
  { "sbcd",  CF_USE1 | CF_USE2            },  // SuBtract with Carry at Double-word


  { "sec",   0                            },  // SEt Carry flag
  { "sei",   0                            },  // SEt Interrupt disable status
  { "sem",   0                            },  // SEt M flag
  { "sep",   CF_USE1                      },  // SEt Processor status


  { "sta",   CF_CHG2 | CF_USE1            },  // STore Accumulator in memory
  { "stab",  CF_CHG2 | CF_USE1            },  // STore Accumulator in memory at Byte
  { "stad",  CF_CHG2 | CF_USE1            },  // STore Accumulator in memory at Double-word

  { "stp",   0                            },  // SToP

  { "stx",   CF_CHG1                      },  // STore index register X in memory
  { "sty",   CF_CHG1                      },  // STore index register Y in memory

  { "sub",   CF_CHG1 | CF_USE2            },  // SUBtract
  { "subb",  CF_CHG1 | CF_USE2            },  // SUBtract at Byte
  { "subd",  CF_CHG1 | CF_USE2            },  // SUBtract at Double-word
  { "subm",  CF_CHG1 | CF_USE2            },  // SUBtract immediate from Memory
  { "submb", CF_CHG1 | CF_USE2            },  // SUBtract immediate from Memory at Byte
  { "submd", CF_CHG1 | CF_USE2            },  // SUBtract immediate from Memory at Double-word

  { "subs",  CF_USE1                      },  // SUBtract Stack pointer
  { "subx",  CF_USE1                      },  // SUBtract immediate from index register X
  { "suby",  CF_USE1                      },  // SUBtract immediate from index register Y

  { "tad",   CF_USE1                      },  // Transfer accumulator A to Direct page register n

  { "tas", 0                               },  // Transfer accumulator A to Stack pointer
  { "tax", 0                               },  // Transfer accumulator A to index register X
  { "tay", 0                               },  // Transfer accumulator A to index register Y

  { "tbd",  CF_USE1                        },  // Transfer accumulator B to Direct page register n

  { "tbs", 0                               },  // Transfer accumulator B to Stack pointer
  { "tbx", 0                               },  // Transfer accumulator B to index register X
  { "tby", 0                               },  // Transfer accumulator B to index register Y

  { "tda", CF_USE1                         },   // Transfer Direct page register n to accumulator A
  { "tdb", CF_USE1                         },   // Transfer Direct page register n to accumulator B

  { "tds", 0                               },   // Transfer Direct page register to Stack pointer
  { "tsa", 0                               },   // Transfer Stack pointer to accumulator A
  { "tsb", 0                               },   // Transfer Stack pointer to accumulator B

  { "tsd", 0                               },   // Transfer Stack pointer to Direct page register
  { "tsx", 0                               },   // Transfer Stack pointer to index register X
  { "txa", 0                               },   // Transfer index register X to accumulator A
  { "txb", 0                               },   // Transfer index register X to accumulator B
  { "txs", 0                               },   // Transfer index register X to Stack pointer
  { "txy", 0                               },   // Transfer index register X to Y
  { "tya", 0                               },   // Transfer index register Y to accumulator A
  { "tyb", 0                               },   // Transfer index register Y to accumulator B
  { "tyx", 0                               },   // Transfer index register Y to X

  { "wit", CF_STOP                         },   // WaIT

  { "xab", 0                               },   // eXchange accumulator A and B

};

CASSERT(qnumber(Instructions) == m7900_last);
