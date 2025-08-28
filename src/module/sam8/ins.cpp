/*
 * Disassembler for Samsung SAM8 processors
 */

#include "sam8.hpp"

const instruc_t Instructions[] =
{
  { "",           0                               },      // Unknown Operation
  { "adc",        CF_USE1|CF_USE2|CF_CHG1         },      // ADC dst, src
  { "add",        CF_USE1|CF_USE2|CF_CHG1         },      // ADD dst, src
  { "and",        CF_USE1|CF_USE2|CF_CHG1         },      // AND dst, src
  { "band",       CF_USE1|CF_USE2|CF_CHG1         },      // BAND dst, src.b     BAND dst.b, src
  { "bcp",        CF_USE1|CF_USE2                 },      // BCP dst, src.b
  { "bitc",       CF_USE1|CF_CHG1                 },      // BITC dst.b
  { "bitr",       CF_CHG1                         },      // BITR dst.b
  { "bits",       CF_CHG1                         },      // BITS dst.b
  { "bor",        CF_USE1|CF_USE2|CF_CHG1         },      // BOR dst, src.b      BOR dst.b, src
  { "btjrf",      CF_USE1|CF_USE2|CF_JUMP         },      // BTJRF dst, src.b
  { "btjrt",      CF_USE1|CF_USE2|CF_JUMP         },      // BTJRT dst, src.b
  { "bxor",       CF_USE1|CF_USE2|CF_CHG1         },      // BXOR dst, src.b     BXOR dst.b, src
  { "call",       CF_USE1|CF_CALL                 },      // CALL dst
  { "ccf",        0                               },      // CCF
  { "clr",        CF_CHG1                         },      // CLR dst
  { "com",        CF_USE1|CF_CHG1                 },      // COM dst
  { "cp",         CF_USE1|CF_USE2                 },      // CP dst, src
  { "cpije",      CF_USE1|CF_USE2|CF_USE3|CF_CHG2|CF_JUMP },      // CPIJE dst, src, RA
  { "cpijne",     CF_USE1|CF_USE2|CF_USE3|CF_CHG2|CF_JUMP },      // CPIJNE dst, src, RA
  { "da",         CF_USE1|CF_CHG1                 },      // DA dst
  { "dec",        CF_USE1|CF_CHG1                 },      // DEC dst
  { "decw",       CF_USE1|CF_CHG1                 },      // DECW dst
  { "di",         0                               },      // DI
  { "div",        CF_USE1|CF_USE2|CF_CHG1         },      // DIV dst, src.b
  { "djnz",       CF_USE1|CF_USE2|CF_CHG1|CF_JUMP },      // DJNZ r, dst
  { "ei",         0                               },      // EI
  { "enter",      0                               },      // ENTER
  { "exit",       CF_STOP                         },      // EXIT
  { "idle",       0                               },      // IDLE
  { "inc",        CF_USE1|CF_CHG1                 },      // INC dst
  { "incw",       CF_USE1|CF_CHG1                 },      // INCW dst
  { "iret",       0                               },      // IRET
  { "jp",         CF_USE1|CF_JUMP                 },      // JP cc, dst
  { "jr",         CF_USE1|CF_JUMP                 },      // JR cc, dst
  { "ld",         CF_USE1|CF_USE2|CF_CHG1         },      // LD dst, src
  { "ldb",        CF_USE1|CF_USE2|CF_CHG1         },      // LDB dst, src.b    LDB dst.b, src
  { "ldc",        CF_USE1|CF_USE2|CF_CHG1         },      // LDC dst, src
  { "lde",        CF_USE1|CF_USE2|CF_CHG1         },      // LDE dst, src
  { "ldcd",       CF_USE1|CF_USE2|CF_CHG1         },      // LDCD dst, src
  { "lded",       CF_USE1|CF_USE2|CF_CHG1         },      // LDED dst, src
  { "ldci",       CF_USE1|CF_USE2|CF_CHG1         },      // LDCI dst, src
  { "ldei",       CF_USE1|CF_USE2|CF_CHG1         },      // LDEI dst, src
  { "ldcpd",      CF_USE1|CF_USE2|CF_CHG1         },      // LDCPD dst, src
  { "ldepd",      CF_USE1|CF_USE2|CF_CHG1         },      // LDEPD dst, src
  { "ldcpi",      CF_USE1|CF_USE2|CF_CHG1         },      // LDCPI dst, src
  { "ldepi",      CF_USE1|CF_USE2|CF_CHG1         },      // LDEPI dst, src
  { "ldw",        CF_USE1|CF_USE2|CF_CHG1         },      // LDW dst, src
  { "mult",       CF_USE1|CF_USE2|CF_CHG1         },      // MULT dst, src
  { "next",       CF_STOP                         },      // NEXT
  { "nop",        0                               },      // NOP
  { "or",         CF_USE1|CF_USE2|CF_CHG1         },      // OR dst, src
  { "pop",        CF_CHG1                         },      // POP dst
  { "popud",      CF_USE2|CF_CHG1|CF_CHG2         },      // POPUD dst, src
  { "popui",      CF_USE2|CF_CHG1|CF_CHG2         },      // POPUI dst, src
  { "push",       CF_USE1                         },      // PUSH dst
  { "pushud",     CF_USE1|CF_USE2|CF_CHG1         },      // PUSHUD dst, src
  { "pushui",     CF_USE1|CF_USE2|CF_CHG1         },      // PUSHUI dst, src
  { "rcf",        0                               },      // RCF
  { "ret",        CF_STOP                         },      // RET
  { "rl",         CF_USE1|CF_CHG1|CF_SHFT         },      // RL dst
  { "rlc",        CF_USE1|CF_CHG1|CF_SHFT         },      // RLC dst
  { "rr",         CF_USE1|CF_CHG1|CF_SHFT         },      // RR dst
  { "rrc",        CF_USE1|CF_CHG1|CF_SHFT         },      // RRC dst
  { "sb0",        0                               },      // SB0
  { "sb1",        0                               },      // SB1
  { "sbc",        CF_USE1|CF_USE2|CF_CHG1         },      // SBC dst, src
  { "scf",        0                               },      // SCF
  { "sra",        CF_USE1|CF_CHG1|CF_SHFT         },      // SRA dst
  { "srp",        CF_USE1                         },      // SRP src
  { "srp0",       CF_USE1                         },      // SRP0 src
  { "srp1",       CF_USE1                         },      // SRP1 src
  { "stop",       0                               },      // STOP
  { "sub",        CF_USE1|CF_USE2|CF_CHG1         },      // SUB dst, src
  { "swap",       CF_USE1|CF_CHG1                 },      // SWAP dst
  { "tcm",        CF_USE1|CF_USE2                 },      // TCM dst, src
  { "tm",         CF_USE1|CF_USE2                 },      // TM dst, src
  { "wfi",        0                               },      // WFI
  { "xor",        CF_USE1|CF_USE2|CF_CHG1         }       // XOR dst, src
};

CASSERT(qnumber(Instructions) == SAM8_last);
