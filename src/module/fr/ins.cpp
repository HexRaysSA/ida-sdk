
#include "fr.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               },  // null instruction
  { "add",        CF_USE1|CF_USE2|CF_CHG2         },  // add word data of source register / 4-bit immediate data to destination register
  { "add2",       CF_USE1|CF_USE2|CF_CHG2         },  // add 4-bit immediate data to destination register
  { "addc",       CF_USE1|CF_USE2|CF_CHG2         },  // add word data of source register and carry bit to destination register
  { "addn",       CF_USE1|CF_USE2|CF_CHG2         },  // add word data of source register / immediate data to destination register
  { "addn2",      CF_USE1|CF_USE2|CF_CHG2         },  // add immediate data to destination register
  { "sub",        CF_USE1|CF_USE2|CF_CHG2         },  // subtract word data in source register from destination register
  { "subc",       CF_USE1|CF_USE2|CF_CHG2         },  // subtract word data in source register and carry bit from destination register
  { "subn",       CF_USE1|CF_USE2|CF_CHG2         },  // subtract word data in source register from destination register
  { "cmp",        CF_USE1|CF_USE2                 },  // compare word / immediate data in source register and destination register
  { "cmp2",       CF_USE1|CF_USE2                 },  // compare immediate data and destination register
  { "and",        CF_USE1|CF_USE2|CF_CHG2         },  // and word data of source register to destination register / data in memory
  { "andh",       CF_USE1|CF_USE2|CF_CHG2         },  // and half-word data of source register to data in memory
  { "andb",       CF_USE1|CF_USE2|CF_CHG2         },  // and byte data of source register to data in memory
  { "or",         CF_USE1|CF_USE2|CF_CHG2         },  // or word data of source register to destination register / data in memory
  { "orh",        CF_USE1|CF_USE2|CF_CHG2         },  // or half-word data of source register to data in memory
  { "orb",        CF_USE1|CF_USE2|CF_CHG2         },  // or byte data of source register to data in memory
  { "eor",        CF_USE1|CF_USE2|CF_CHG2         },  // exclusive or word data of source register to destination register / data in memory
  { "eorh",       CF_USE1|CF_USE2|CF_CHG2         },  // exclusive or half-word data of source register to data in memory
  { "eorb",       CF_USE1|CF_USE2|CF_CHG2         },  // exclusive or byte data of source register to data in memory
  { "bandl",      CF_USE1|CF_USE2|CF_CHG2         },  // and 4-bit immediate data to lower 4 bits of byte data in memory
  { "bandh",      CF_USE1|CF_USE2|CF_CHG2         },  // and 4-bit immediate data to higher 4 bits of byte data in memory
  { "borl",       CF_USE1|CF_USE2|CF_CHG2         },  // or 4-bit immediate data to lower 4 bits of byte data in memory
  { "borh",       CF_USE1|CF_USE2|CF_CHG2         },  // or 4-bit immediate data to higher 4 bits of byte data in memory
  { "beorl",      CF_USE1|CF_USE2|CF_CHG2         },  // eor 4-bit immediate data to lower 4 bits of byte data in memory
  { "beorh",      CF_USE1|CF_USE2|CF_CHG2         },  // eor 4-bit immediate data to higher 4 bits of byte data in memory
  { "btstl",      CF_USE1|CF_USE2                 },  // test lower 4 bits of byte data in memory
  { "btsth",      CF_USE1|CF_USE2                 },  // test higher 4 bits of byte data in memory
  { "mul",        CF_USE1|CF_USE2                 },  // multiply word data
  { "mulu",       CF_USE1|CF_USE2                 },  // multiply unsigned word data
  { "mulh",       CF_USE1|CF_USE2                 },  // multiply half-word data
  { "muluh",      CF_USE1|CF_USE2                 },  // multiply unsigned half-word data
  { "div0s",      CF_USE1                         },  // initial setting up for signed division
  { "div0u",      CF_USE1                         },  // initial setting up for unsigned division
  { "div1",       CF_USE1                         },  // main process of division
  { "div2",       CF_USE1                         },  // correction when remainder is 0
  { "div3",       0                               },  // correction when remainder is 0
  { "div4s",      0                               },  // correction answer for signed division
  { "lsl",        CF_USE1|CF_USE2|CF_CHG2         },  // logical shift to the left direction
  { "lsl2",       CF_USE1|CF_USE2|CF_CHG2         },  // logical shift to the left direction
  { "lsr",        CF_USE1|CF_USE2|CF_CHG2         },  // logical shift to the right direction
  { "lsr2",       CF_USE1|CF_USE2|CF_CHG2         },  // logical shift to the right direction
  { "asr",        CF_USE1|CF_USE2|CF_CHG2         },  // arithmetic shift to the right direction
  { "asr2",       CF_USE1|CF_USE2|CF_CHG2         },  // arithmetic shift to the right direction
  { "ldi:32",     CF_USE1|CF_USE2|CF_CHG2         },  // load immediate 32-bit data to destination register
  { "ldi:20",     CF_USE1|CF_USE2|CF_CHG2         },  // load immediate 20-bit data to destination register
  { "ldi:8",      CF_USE1|CF_USE2|CF_CHG2         },  // load immediate 8-bit data to destination register
  { "ld",         CF_USE1|CF_USE2|CF_CHG2         },  // load word data in memory to register / program status register
  { "lduh",       CF_USE1|CF_USE2|CF_CHG2         },  // load half-word data in memory to register
  { "ldub",       CF_USE1|CF_USE2|CF_CHG2         },  // load byte data in memory to register
  { "st",         CF_USE1|CF_USE2|CF_CHG2         },  // store word data in register / program status register to memory
  { "sth",        CF_USE1|CF_USE2|CF_CHG2         },  // store half-word data in register to memory
  { "stb",        CF_USE1|CF_USE2|CF_CHG2         },  // store byte data in register to memory
  { "mov",        CF_USE1|CF_USE2|CF_CHG2         },  // move word data in source register / program status register to destination register / program status register
  { "jmp",        CF_USE1|CF_STOP                 },  // jump
  { "call",       CF_USE1|CF_CALL                 },  // call subroutine
  { "ret",        CF_STOP                         },  // return from subroutine
  { "int",        CF_USE1                         },  // software interrupt
  { "inte",       0                               },  // software interrupt for emulator
  { "reti",       CF_STOP                         },  // return from interrupt
  { "bra",        CF_USE1|CF_STOP                 },  // branch relative if condition satisfied
  { "bno",        CF_USE1                         },  // branch relative if condition satisfied
  { "beq",        CF_USE1                         },  // branch relative if condition satisfied
  { "bne",        CF_USE1                         },  // branch relative if condition satisfied
  { "bc",         CF_USE1                         },  // branch relative if condition satisfied
  { "bnc",        CF_USE1                         },  // branch relative if condition satisfied
  { "bn",         CF_USE1                         },  // branch relative if condition satisfied
  { "bp",         CF_USE1                         },  // branch relative if condition satisfied
  { "bv",         CF_USE1                         },  // branch relative if condition satisfied
  { "bnv",        CF_USE1                         },  // branch relative if condition satisfied
  { "blt",        CF_USE1                         },  // branch relative if condition satisfied
  { "bge",        CF_USE1                         },  // branch relative if condition satisfied
  { "ble",        CF_USE1                         },  // branch relative if condition satisfied
  { "bgt",        CF_USE1                         },  // branch relative if condition satisfied
  { "bls",        CF_USE1                         },  // branch relative if condition satisfied
  { "bhi",        CF_USE1                         },  // branch relative if condition satisfied
  { "dmov",       CF_USE1|CF_USE2|CF_CHG2         },  // move word data from register / address to register / address
  { "dmovh",      CF_USE1|CF_USE2|CF_CHG2         },  // move half-word data from register / address to register / address
  { "dmovb",      CF_USE1|CF_USE2|CF_CHG2         },  // move byte data from register / address to register / address
  { "ldres",      CF_USE1|CF_USE2|CF_CHG1         },  // load word data in memory to resource
  { "stres",      CF_USE1|CF_USE2|CF_CHG1         },  // store word data in resource to memory
  { "copop",      CF_USE1|CF_USE2|CF_USE3|CF_USE4 },  // coprocessor operation
  { "copld",      CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_CHG4 },  // load 32-bit data from register to coprocessor register
  { "copst",      CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_CHG4 },  // store 32-bit data from coprocessor register to register
  { "copsv",      CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_CHG4 },  // save 32-bit data from coprocessor register to register
  { "nop",        0                               },  // no operation
  { "andccr",     CF_USE1                         },  // and condition code register and immediate data
  { "orccr",      CF_USE1                         },  // or condition code register and immediate data
  { "stilm",      CF_USE1                         },  // set immediate data to interrupt level mask register
  { "addsp",      CF_USE1                         },  // add stack pointer and immediate data
  { "extsb",      CF_USE1|CF_CHG1                 },  // sign extend from byte data to word data
  { "extub",      CF_USE1|CF_CHG1                 },  // unsign extend from byte data to word data
  { "extsh",      CF_USE1|CF_CHG1                 },  // sign extend from byte data to word data
  { "extuh",      CF_USE1|CF_CHG1                 },  // unsigned extend from byte data to word data
  { "ldm0",       CF_USE1                         },  // load multiple registers
  { "ldm1",       CF_USE1                         },  // load multiple registers
  { "stm0",       CF_USE1                         },  // store multiple registers
  { "stm1",       CF_USE1                         },  // store multiple registers
  { "enter",      CF_USE1                         },  // enter function
  { "leave",      CF_USE1                         },  // leave function
  { "xchb",       CF_CHG1|CF_CHG2                 }   // exchange byte data
};

CASSERT(qnumber(Instructions) == fr_last);
