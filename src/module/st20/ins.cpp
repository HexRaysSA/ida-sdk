/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "st20.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },      // Unknown Operation

  { "adc",        CF_USE1                         },      // add constant
  { "add",        0                               },      // add
  { "addc",       0                               },      // add with carry
  { "ajw",        CF_USE1                         },      // adjust work space
  { "and",        0                               },      // and
  { "arot",       0                               },      // anti-rotate stack
  { "ashr",       0                               },      // arithmetic shift right
  { "biquad",     0                               },      // biquad IIR filter step
  { "bitld",      0                               },      // load bit
  { "bitmask",    0                               },      // create bit mask
  { "bitst",      0                               },      // store bit
  { "breakpoint", 0                               },      // breakpoint
  { "cj",         CF_USE1                         },      // conditional jump
  { "dequeue",    0                               },      // dequeue a process
  { "divstep",    0                               },      // divide step
  { "dup",        0                               },      // duplicate
  { "ecall",      0                               },      // exception call
  { "enqueue",    0                               },      // enqueue a process
  { "eqc",        CF_USE1                         },      // equals constant
  { "eret",               CF_STOP                 },      // exception return
  { "fcall",      CF_USE1|CF_CALL                 },      // function call
  { "gajw",       0                               },      // general adjust workspace
  { "gt",         0                               },      // greater than
  { "gtu",        0                               },      // greater than unsigned
  { "io",         0                               },      // input/output
  { "j",          CF_USE1|CF_STOP                 },      // jump
  { "jab",        0                               },      // jump absolute
  { "lbinc",      0                               },      // load byte and increment
  { "ldc",        CF_USE1                         },      // load constant
  { "ldl",        CF_USE1                         },      // load local
  { "ldlp",       CF_USE1                         },      // load local pointer
  { "ldnl",       CF_USE1                         },      // load non-local
  { "ldnlp",      CF_USE1                         },      // load non-local pointer
  { "ldpi",       0                               },      // load pointer to instruction
  { "ldprodid",   0                               },      // load product identity
  { "ldtdesc",    0                               },      // load task descriptor
  { "lsinc",      0                               },      // load sixteen and increment
  { "lsxinc",     0                               },      // load sixteen sign extended and increment
  { "lwinc",      0                               },      // load word and increment
  { "mac",        0                               },      // multiply accumulate
  { "mul",        0                               },      // multiply
  { "nfix",       CF_USE1                         },      // negative prefix
  { "nop",        0                               },      // no operation
  { "not",        0                               },      // bitwise not
  { "opr",        CF_USE1                         },      // operate
  { "or",         0                               },      // or
  { "order",      0                               },      // order
  { "orderu",     0                               },      // unsigned order
  { "pfix",       CF_USE1                         },      // prefix
  { "rev",        0                               },      // reverse
  { "rmw",        0                               },      // read modify write
  { "rot",        0                               },      // rotate stack
  { "run",        0                               },      // run process
  { "saturate",   0                               },      // saturate
  { "sbinc",      0                               },      // store byte and increment
  { "shl",        0                               },      // shift left
  { "shr",        0                               },      // shift right
  { "signal",     0                               },      // signal
  { "smacinit",   0                               },      // initialize short multiply accumulate loop
  { "smacloop",   0                               },      // short multiply accumulate loop
  { "smul",       0                               },      // short multiply
  { "ssinc",      0                               },      // store sixteen and increment
  { "statusclr",  0                               },      // clear bits in status register
  { "statusset",  0                               },      // set bits in status register
  { "statustst",  0                               },      // test status register
  { "stl",        CF_USE1                         },      // store local
  { "stnl",       CF_USE1                         },      // store non-local
  { "stop",       0                               },      // stop process
  { "sub",        0                               },      // subtract
  { "subc",       0                               },      // subtract with carry
  { "swap32",     0                               },      // byte swap 32
  { "swinc",      0                               },      // store word and increment
  { "timeslice",  0                               },      // timeslice
  { "umac",       0                               },      // unsigned multiply accumulate
  { "unsign",     0                               },      // unsign argument
  { "wait",       0                               },      // wait
  { "wsub",       0                               },      // word subscript
  { "xbword",     0                               },      // sign extend byte to word
  { "xor",        0                               },      // exclusive or
  { "xsword",     0                               },      // sign extend sixteen to word

  // C2-C4 instructions

  { "alt",           0                            },      // alt start
  { "altend",        CF_STOP                      },      // alt end
  { "altwt",         0                            },      // alt wait
  { "bcnt",          0                            },      // byte count
  { "bitcnt",        0                            },      // count bits set in word
  { "bitrevnbits",   0                            },      // reverse bottom n bits in word
  { "bitrevword",    0                            },      // reverse bits in word
  { "bsub",          0                            },      // byte subscript
  { "call",          CF_USE1|CF_CALL              },      // call
  { "causeerror",    0                            },      // cause error
  { "cb",            0                            },      // check byte
  { "cbu",           0                            },      // check byte unsigned
  { "ccnt1",         0                            },      // check count from 1
  { "cflerr",        0                            },      // check floating point error
  { "cir",           0                            },      // check in range
  { "ciru",          0                            },      // check in range unsigned
  { "clockdis",      0                            },      // clock disable
  { "clockenb",      0                            },      // clock enable
  { "clrhalterr",    0                            },      // clear halt-on error flag
  { "crcbyte",       0                            },      // calculate CRC on byte
  { "crcword",       0                            },      // calculate CRC on word
  { "cs",            0                            },      // check sixteen
  { "csngl",         0                            },      // check single
  { "csu",           0                            },      // check sixteen unsigned
  { "csub0",         0                            },      // check subscript from 0
  { "cword",         0                            },      // check word
  { "devlb",         0                            },      // device load byte
  { "devls",         0                            },      // device load sixteen
  { "devlw",         0                            },      // device load word
  { "devmove",       0                            },      // device move
  { "devsb",         0                            },      // device store byte
  { "devss",         0                            },      // device store sixteen
  { "devsw",         0                            },      // device store word
  { "diff",          0                            },      // difference
  { "disc",          0                            },      // disable channel
  { "diss",          0                            },      // disable skip
  { "dist",          0                            },      // disable timer
  { "div",           0                            },      // divide
  { "enbc",          0                            },      // enable channel
  { "enbs",          0                            },      // enable skip
  { "enbt",          0                            },      // enable timer
  { "endp",          CF_STOP                      },      // end process
  { "fmul",          0                            },      // fractional multiply
  { "fptesterr",     0                            },      // test for FPU error
  { "gcall",         CF_CALL|CF_JUMP              },      // general call
  { "gintdis",       0                            },      // general interrupt disable
  { "gintenb",       0                            },      // general interrupt enable
  { "in",            0                            },      // input message
  { "insertqueue",   0                            },      // insert at front of scheduler queue
  { "intdis",        0                            },      // (localised) interrupt disable
  { "intenb",        0                            },      // (localised) interrupt enable
  { "iret",          CF_STOP                      },      // interrupt return
  { "ladd",          0                            },      // long add
  { "lb",            0                            },      // load byte
  { "lbx",           0                            },      // load byte and sign extend
  { "ldclock",       0                            },      // load clock
  { "lddevid",       0                            },      // load device identity
  { "ldiff",         0                            },      // long diff
  { "ldinf",         0                            },      // load infinity
  { "ldiv",          0                            },      // long divide
  { "ldmemstartval", 0                            },      // load value of MemStart address
  { "ldpri",         0                            },      // load current priority
  { "ldshadow",      0                            },      // load shadow registers
  { "ldtimer",       0                            },      // load timer
  { "ldtraph",       0                            },      // load trap handler
  { "ldtrapped",     0                            },      // load trapped process status
  { "lend",          0                            },      // loop end
  { "lmul",          0                            },      // long multiply
  { "ls",            0                            },      // load sixteen
  { "lshl",          0                            },      // long shift left
  { "lshr",          0                            },      // long shift right
  { "lsub",          0                            },      // long subtract
  { "lsum",          0                            },      // long sum
  { "lsx",           0                            },      // load sixteen and sign extend
  { "mint",          0                            },      // minimum integer
  { "move",          0                            },      // move message
  { "move2dall",     0                            },      // 2D block copy
  { "move2dinit",    0                            },      // initialize data for 2D block move
  { "move2dnonzero", 0                            },      // 2D block copy non-zero bytes
  { "move2dzero",    0                            },      // 2D block copy zero bytes
  { "norm",          0                            },      // normalize
  { "out",           0                            },      // output message
  { "outbyte",       0                            },      // output byte
  { "outword",       0                            },      // output word
  { "pop",           0                            },      // pop processor stack
  { "postnormsn",    0                            },      // post-normalize correction of single length fp number
  { "prod",          0                            },      // product
  { "reboot",        CF_STOP                      },      // reboot
  { "rem",           0                            },      // remainder
  { "resetch",       0                            },      // reset channel
  { "restart",       CF_STOP                      },      // restart
  { "ret",           CF_STOP                      },      // return
  { "roundsn",       0                            },      // round single length floating point number
  { "runp",          0                            },      // run process
  { "satadd",        0                            },      // saturating add
  { "satmul",        0                            },      // saturating multiply
  { "satsub",        0                            },      // saturating subtract
  { "saveh",         0                            },      // save high priority queue registers
  { "savel",         0                            },      // save low priority queue registers
  { "sb",            0                            },      // store byte
  { "seterr",        0                            },      // set error flags
  { "sethalterr",    0                            },      // set halt-on error flag
  { "settimeslice",  0                            },      // set timeslicing status
  { "slmul",         0                            },      // signed long multiply
  { "ss",            0                            },      // store sixteen
  { "ssub",          0                            },      // sixteen subscript
  { "startp",        0                            },      // start process
  { "stclock",       0                            },      // store clock register
  { "sthb",          0                            },      // store high priority back pointer
  { "sthf",          0                            },      // store high priority front pointer
  { "stlb",          0                            },      // store low priority back pointer
  { "stlf",          0                            },      // store low priority front pointer
  { "stoperr",       0                            },      // stop on error
  { "stopp",         0                            },      // stop process
  { "stshadow",      0                            },      // store shadow registers
  { "sttimer",       0                            },      // store timer
  { "sttraph",       0                            },      // store trap handler
  { "sttrapped",     0                            },      // store trapped process
  { "sulmul",        0                            },      // signed timer unsigned long multiply
  { "sum",           0                            },      // sum
  { "swapqueue",     0                            },      // swap scheduler queue
  { "swaptimer",     0                            },      // swap timer queue
  { "talt",          0                            },      // timer alt start
  { "taltwt",        0                            },      // timer alt wait
  { "testerr",       0                            },      // test error flag
  { "testhalterr",   0                            },      // test halt-on error flag
  { "testpranal",    0                            },      // test processor analysing
  { "tin",           0                            },      // timer input
  { "trapdis",       0                            },      // trap disable
  { "trapenb",       0                            },      // trap enable
  { "tret",          CF_STOP                      },      // trap return
  { "unpacksn",      0                            },      // unpack single length fp number
  { "wcnt",          0                            },      // word count
  { "wsubdb",        0                            },      // form double word subscript
  { "xdble",         0                            },      // extend to double
  { "xword",         0                            },      // extend word
};

CASSERT(qnumber(Instructions) == ST20_last);
