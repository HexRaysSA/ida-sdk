/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "i960.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },       // Unknown Operation

  { "addc",       CF_USE1|CF_USE2|CF_CHG3         },       // Add ordinal with carry
  { "addi",       CF_USE1|CF_USE2|CF_CHG3         },       // Add integer
  { "addo",       CF_USE1|CF_USE2|CF_CHG3         },       // Add ordinal
  { "alterbit",   CF_USE1|CF_USE2|CF_CHG3         },       // Alter bit
  { "and",        CF_USE1|CF_USE2|CF_CHG3         },       // Src2 AND src1
  { "andnot",     CF_USE1|CF_USE2|CF_CHG3         },       // Src2 AND (NOT src1)
  { "atadd",      CF_USE1|CF_USE2|CF_CHG3         },       // Atomic add
  { "atmod",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },       // Atomic modify
  { "b",          CF_USE1|CF_STOP                 },       // Branch
  { "bal",        CF_USE1|CF_CALL                 },       // Branch and Link
  { "balx",       CF_USE1|CF_CHG2|CF_CALL         },       // Branch and Link Extended
  { "bbc",        CF_USE1|CF_USE2|CF_USE3         },       // Check bit and branch if clear
  { "bbs",        CF_USE1|CF_USE2|CF_USE3         },       // Check bit and branch if set
  { "bno",        CF_USE1                         },       // Branch if unordered/false
  { "bg",         CF_USE1                         },       // Branch if greater
  { "be",         CF_USE1                         },       // Branch if equal/true
  { "bge",        CF_USE1                         },       // Branch if greater or equal
  { "bl",         CF_USE1                         },       // Branch if less
  { "bne",        CF_USE1                         },       // Branch if not equal
  { "ble",        CF_USE1                         },       // Branch if less or equal
  { "bo",         CF_USE1                         },       // Branch if ordered
  { "bx",         CF_USE1|CF_STOP                 },       // Branch Extended
  { "call",       CF_USE1|CF_CALL                 },       // Call
  { "calls",      CF_USE1|CF_CALL                 },       // Call system
  { "callx",      CF_USE1|CF_CALL                 },       // Call extended
  { "chkbit",     CF_USE1|CF_USE2                 },       // Check bit
  { "clrbit",     CF_USE1|CF_USE2|CF_CHG3         },       // Clear bit
  { "cmpdeci",    CF_USE1|CF_USE2|CF_CHG3         },       // Compare and decrement integer
  { "cmpdeco",    CF_USE1|CF_USE2|CF_CHG3         },       // Compare and decrement ordinal
  { "cmpi",       CF_USE1|CF_USE2                 },       // Compare integer
  { "cmpibno",    CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if unordered
  { "cmpibg",     CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if greater
  { "cmpibe",     CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if equal
  { "cmpibge",    CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if greater or equal
  { "cmpibl",     CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if less
  { "cmpibne",    CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if not equal
  { "cmpible",    CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if less or equal
  { "cmpibo",     CF_USE1|CF_USE2|CF_USE3         },       // Compare integer and branch if ordered
  { "cmpinci",    CF_USE1|CF_USE2|CF_CHG3         },       // Compare and increment integer
  { "cmpinco",    CF_USE1|CF_USE2|CF_CHG3         },       // Compare and increment ordinal
  { "cmpo",       CF_USE1|CF_USE2                 },       // Compare ordinal
  { "cmpobg",     CF_USE1|CF_USE2|CF_USE3         },       // Compare ordinal and branch if greater
  { "cmpobe",     CF_USE1|CF_USE2|CF_USE3         },       // Compare ordinal and branch if equal
  { "cmpobge",    CF_USE1|CF_USE2|CF_USE3         },       // Compare ordinal and branch if greater or equal
  { "cmpobl",     CF_USE1|CF_USE2|CF_USE3         },       // Compare ordinal and branch if less
  { "cmpobne",    CF_USE1|CF_USE2|CF_USE3         },       // Compare ordinal and branch if not equal
  { "cmpoble",    CF_USE1|CF_USE2|CF_USE3         },       // Compare ordinal and branch if less or equal
  { "concmpi",    CF_USE1|CF_USE2                 },       // Conditional compare integer
  { "concmpo",    CF_USE1|CF_USE2                 },       // Conditional compare ordinal
  { "divi",       CF_USE1|CF_USE2|CF_CHG3         },       // Divide integer
  { "divo",       CF_USE1|CF_USE2|CF_CHG3         },       // Divide ordinal
  { "ediv",       CF_USE1|CF_USE2|CF_CHG3         },       // Extended divide
  { "emul",       CF_USE1|CF_USE2|CF_CHG3         },       // Extended multiply
  { "eshro",      CF_USE1|CF_USE2|CF_CHG3         },       // Extended shift right ordinal
  { "extract",    CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },       // Extract
  { "faultno",    0                               },       // Fault if unordered
  { "faultg",     0                               },       // Fault if greater
  { "faulte",     0                               },       // Fault if equal
  { "faultge",    0                               },       // Fault if greater or equal
  { "faultl",     0                               },       // Fault if less
  { "faultne",    0                               },       // Fault if not equal
  { "faultle",    0                               },       // Fault if less or equal
  { "faulto",     0                               },       // Fault if ordered
  { "flushreg",   0                               },       // Flush cached local register sets to memory
  { "fmark",      0                               },       // Force mark
  { "ld",         CF_USE1|CF_CHG2                 },       // Load word
  { "lda",        CF_USE1|CF_CHG2                 },       // Load address
  { "ldib",       CF_USE1|CF_CHG2                 },       // Load integer byte
  { "ldis",       CF_USE1|CF_CHG2                 },       // Load integer short
  { "ldl",        CF_USE1|CF_CHG2                 },       // Load long
  { "ldob",       CF_USE1|CF_CHG2                 },       // Load ordinal byte
  { "ldos",       CF_USE1|CF_CHG2                 },       // Load ordinal short
  { "ldq",        CF_USE1|CF_CHG2                 },       // Load quad
  { "ldt",        CF_USE1|CF_CHG2                 },       // Load triple
  { "mark",       0                               },       // Mark
  { "modac",      CF_USE1|CF_USE2|CF_CHG3         },       // Modify the AC register
  { "modi",       CF_USE1|CF_USE2|CF_CHG3         },       // Modulo integer
  { "modify",     CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },       // Modify
  { "modpc",      CF_USE1|CF_USE2|CF_USE3|CF_CHG3 },       // Modify the process controls register
  { "modtc",      CF_USE1|CF_USE2|CF_CHG3         },       // Modify trace controls
  { "mov",        CF_USE1|CF_CHG2                 },       // Move word
  { "movl",       CF_USE1|CF_CHG2                 },       // Move long word
  { "movq",       CF_USE1|CF_CHG2                 },       // Move quad word
  { "movt",       CF_USE1|CF_CHG2                 },       // Move triple word
  { "muli",       CF_USE1|CF_USE2|CF_CHG3         },       // Multiply integer
  { "mulo",       CF_USE1|CF_USE2|CF_CHG3         },       // Multiply ordinal
  { "nand",       CF_USE1|CF_USE2|CF_CHG3         },       // NOT (src2 AND src1)
  { "nor",        CF_USE1|CF_USE2|CF_CHG3         },       // NOT (src2 OR src1)
  { "not",        CF_USE1|CF_CHG2                 },       // NOT src1
  { "notand",     CF_USE1|CF_USE2|CF_CHG3         },       // (NOT src2) AND src1
  { "notbit",     CF_USE1|CF_USE2|CF_CHG3         },       // Not bit
  { "notor",      CF_USE1|CF_USE2|CF_CHG3         },       // (NOT src2) or src1
  { "or",         CF_USE1|CF_USE2|CF_CHG3         },       // Src2 OR src1
  { "ornot",      CF_USE1|CF_USE2|CF_CHG3         },       // Src2 or (NOT src1)
  { "remi",       CF_USE1|CF_USE2|CF_CHG3         },       // Remainder integer
  { "remo",       CF_USE1|CF_USE2|CF_CHG3         },       // Remainder ordinal
  { "ret",        CF_STOP                         },       // Return
  { "rotate",     CF_USE1|CF_USE2|CF_CHG3         },       // Rotate left
  { "scanbit",    CF_USE1|CF_CHG2                 },       // Scan for bit
  { "scanbyte",   CF_USE1|CF_USE2                 },       // Scan byte equal
  { "setbit",     CF_USE1|CF_USE2|CF_CHG3         },       // Set bit
  { "shli",       CF_USE1|CF_USE2|CF_CHG3         },       // Shift left integer
  { "shlo",       CF_USE1|CF_USE2|CF_CHG3         },       // Shift left ordinal
  { "shrdi",      CF_USE1|CF_USE2|CF_CHG3         },       // Shift right dividing integer
  { "shri",       CF_USE1|CF_USE2|CF_CHG3         },       // Shift right integer
  { "shro",       CF_USE1|CF_USE2|CF_CHG3         },       // Shift right ordinal
  { "spanbit",    CF_USE1|CF_CHG2                 },       // Span over bit
  { "st",         CF_USE1|CF_CHG2                 },       // Store word
  { "stib",       CF_USE1|CF_CHG2                 },       // Store integer byte
  { "stis",       CF_USE1|CF_CHG2                 },       // Store integer short
  { "stl",        CF_USE1|CF_CHG2                 },       // Store long
  { "stob",       CF_USE1|CF_CHG2                 },       // Store ordinal byte
  { "stos",       CF_USE1|CF_CHG2                 },       // Store ordinal short
  { "stq",        CF_USE1|CF_CHG2                 },       // Store quad
  { "stt",        CF_USE1|CF_CHG2                 },       // Store triple
  { "subc",       CF_USE1|CF_USE2|CF_CHG3         },       // Subtract ordinal with carry
  { "subi",       CF_USE1|CF_USE2|CF_CHG3         },       // Subtract integer
  { "subo",       CF_USE1|CF_USE2|CF_CHG3         },       // Subtract ordinal
  { "syncf",      0                               },       // Synchronize faults
  { "testno",     CF_CHG1                         },       // Test for unordered
  { "testg",      CF_CHG1                         },       // Test for greater
  { "teste",      CF_CHG1                         },       // Test for equal
  { "testge",     CF_CHG1                         },       // Test for greater or equal
  { "testl",      CF_CHG1                         },       // Test for less
  { "testne",     CF_CHG1                         },       // Test for not equal
  { "testle",     CF_CHG1                         },       // Test for less or equal
  { "testo",      CF_CHG1                         },       // Test for ordered
  { "xnor",       CF_USE1|CF_USE2|CF_CHG3         },       // Src2 XNOR src1
  { "xor",        CF_USE1|CF_USE2|CF_CHG3         },       // Src2 XOR src1

  // Cx instructions

  { "sdma",       CF_USE1|CF_USE2|CF_USE3         },       // Set up a DMA controller channel
  { "sysctl",     CF_USE1|CF_USE2|CF_USE3         },       // Perform system control function
  { "udma",       0                               },       // Copy current DMA pointers to internal data RAM

  // Unknown instructions

  { "dcinva",     CF_USE1                         },
  { "cmpob",      CF_USE1|CF_USE2                 },
  { "cmpib",      CF_USE1|CF_USE2                 },
  { "cmpos",      CF_USE1|CF_USE2                 },
  { "cmpis",      CF_USE1|CF_USE2                 },
  { "bswap",      CF_USE1|CF_CHG2                 },
  { "intdis",     0                               },
  { "inten",      0                               },
  { "synmov",     CF_USE1|CF_USE2                 },
  { "synmovl",    CF_USE1|CF_USE2                 },
  { "synmovq",    CF_USE1|CF_USE2                 },
  { "cmpstr",     CF_USE1|CF_USE2|CF_CHG3         },
  { "movqstr",    CF_USE1|CF_USE2|CF_CHG3         },
  { "movstr",     CF_USE1|CF_USE2|CF_CHG3         },
  { "inspacc",    CF_USE1|CF_CHG2                 },
  { "ldphy",      CF_USE1|CF_CHG2                 },
  { "synld",      CF_USE1|CF_CHG2                 },
  { "fill",       CF_USE1|CF_USE2|CF_CHG3         },
  { "daddc",      CF_USE1|CF_USE2|CF_CHG3         },
  { "dsubc",      CF_USE1|CF_USE2|CF_CHG3         },
  { "dmovt",      CF_USE1|CF_CHG2                 },
  { "condrec",    CF_USE1|CF_CHG2                 },
  { "receive",    CF_USE1|CF_CHG2                 },
  { "intctl",     CF_USE1|CF_CHG2                 },
  { "icctl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "dcctl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "halt",       CF_USE1|CF_STOP                 },
  { "send",       CF_USE1|CF_USE2|CF_CHG3         },
  { "sendserv",   CF_USE1                         },
  { "resumprcs",  CF_USE1                         },
  { "schedprcs",  CF_USE1                         },
  { "saveprcs",   0                               },
  { "condwait",   CF_USE1                         },
  { "wait",       CF_USE1                         },
  { "signal",     CF_USE1                         },
  { "ldtime",     CF_CHG1                         },
  { "addono",     CF_USE1|CF_USE2|CF_CHG3         },
  { "addino",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subono",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subino",     CF_USE1|CF_USE2|CF_CHG3         },
  { "selno",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addog",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addig",      CF_USE1|CF_USE2|CF_CHG3         },
  { "subog",      CF_USE1|CF_USE2|CF_CHG3         },
  { "subig",      CF_USE1|CF_USE2|CF_CHG3         },
  { "selg",       CF_USE1|CF_USE2|CF_CHG3         },
  { "addoe",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addie",      CF_USE1|CF_USE2|CF_CHG3         },
  { "suboe",      CF_USE1|CF_USE2|CF_CHG3         },
  { "subie",      CF_USE1|CF_USE2|CF_CHG3         },
  { "sele",       CF_USE1|CF_USE2|CF_CHG3         },
  { "addoge",     CF_USE1|CF_USE2|CF_CHG3         },
  { "addige",     CF_USE1|CF_USE2|CF_CHG3         },
  { "suboge",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subige",     CF_USE1|CF_USE2|CF_CHG3         },
  { "selge",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addol",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addil",      CF_USE1|CF_USE2|CF_CHG3         },
  { "subol",      CF_USE1|CF_USE2|CF_CHG3         },
  { "subil",      CF_USE1|CF_USE2|CF_CHG3         },
  { "sell",       CF_USE1|CF_USE2|CF_CHG3         },
  { "addone",     CF_USE1|CF_USE2|CF_CHG3         },
  { "addine",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subone",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subine",     CF_USE1|CF_USE2|CF_CHG3         },
  { "selne",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addole",     CF_USE1|CF_USE2|CF_CHG3         },
  { "addile",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subole",     CF_USE1|CF_USE2|CF_CHG3         },
  { "subile",     CF_USE1|CF_USE2|CF_CHG3         },
  { "selle",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addoo",      CF_USE1|CF_USE2|CF_CHG3         },
  { "addio",      CF_USE1|CF_USE2|CF_CHG3         },
  { "suboo",      CF_USE1|CF_USE2|CF_CHG3         },
  { "subio",      CF_USE1|CF_USE2|CF_CHG3         },
  { "selo",       CF_USE1|CF_USE2|CF_CHG3         },

  // Floating point instructions

  { "addr",       CF_USE1|CF_USE2|CF_CHG3         },
  { "addrl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "atanr",      CF_USE1|CF_USE2|CF_CHG3         },
  { "atanrl",     CF_USE1|CF_USE2|CF_CHG3         },
  { "classr",     CF_USE1                         },
  { "classrl",    CF_USE1                         },
  { "cmpor",      CF_USE1|CF_USE2                 },
  { "cmporl",     CF_USE1|CF_USE2                 },
  { "cmpr",       CF_USE1|CF_USE2                 },
  { "cmprl",      CF_USE1|CF_USE2                 },
  { "cosr",       CF_USE1|CF_CHG2                 },
  { "cosrl",      CF_USE1|CF_CHG2                 },
  { "cpyrsre",    CF_USE1|CF_USE2|CF_CHG3         },
  { "cpysre",     CF_USE1|CF_USE2|CF_CHG3         },
  { "cvtilr",     CF_USE1|CF_CHG2                 },
  { "cvtir",      CF_USE1|CF_CHG2                 },
  { "cvtri",      CF_USE1|CF_CHG2                 },
  { "cvtril",     CF_USE1|CF_CHG2                 },
  { "cvtzri",     CF_USE1|CF_CHG2                 },
  { "cvtzril",    CF_USE1|CF_CHG2                 },
  { "divr",       CF_USE1|CF_USE2|CF_CHG3         },
  { "divrl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "expr",       CF_USE1|CF_CHG2                 },
  { "exprl",      CF_USE1|CF_CHG2                 },
  { "logbnr",     CF_USE1|CF_CHG2                 },
  { "logbnrl",    CF_USE1|CF_CHG2                 },
  { "logepr",     CF_USE1|CF_USE2|CF_CHG3         },
  { "logeprl",    CF_USE1|CF_USE2|CF_CHG3         },
  { "logr",       CF_USE1|CF_USE2|CF_CHG3         },
  { "logrl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "movr",       CF_USE1|CF_CHG2                 },
  { "movre",      CF_USE1|CF_CHG2                 },
  { "movrl",      CF_USE1|CF_CHG2                 },
  { "mulr",       CF_USE1|CF_USE2|CF_CHG3         },
  { "mulrl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "remr",       CF_USE1|CF_USE2|CF_CHG3         },
  { "remrl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "roundr",     CF_USE1|CF_CHG2                 },
  { "roundrl",    CF_USE1|CF_CHG2                 },
  { "scaler",     CF_USE1|CF_USE2|CF_CHG3         },
  { "scalerl",    CF_USE1|CF_USE2|CF_CHG3         },
  { "sinr",       CF_USE1|CF_CHG2                 },
  { "sinrl",      CF_USE1|CF_CHG2                 },
  { "sqrtr",      CF_USE1|CF_CHG2                 },
  { "sqrtrl",     CF_USE1|CF_CHG2                 },
  { "subr",       CF_USE1|CF_USE2|CF_CHG3         },
  { "subrl",      CF_USE1|CF_USE2|CF_CHG3         },
  { "tanr",       CF_USE1|CF_CHG2                 },
  { "tanrl",      CF_USE1|CF_CHG2                 },

};

CASSERT(qnumber(Instructions) == I960_last);
