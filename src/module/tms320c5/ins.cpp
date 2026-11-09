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
  { "",           0                               },      // Unknown Operation
  { "abs",        0                               },      // Absolute value of Acc
  { "adcb",       0                               },      // Add ACCB to Acc With Carry
  { "add",        CF_USE1                         },      // Add to Acc
  { "addb",       0                               },      // Add ACCB to Acc
  { "addc",       CF_USE1                         },      // Add to Acc With Carry
  { "adds",       CF_USE1                         },      // Add to Acc With Sign-Extension Suppressed
  { "addt",       CF_USE1                         },      // Add to Acc With Shift Specified by TREG1
  { "adrk",       CF_USE1                         },      // Add to Aux Register With Short Immediate
  { "and",        CF_USE1                         },      // AND With Acc
  { "andb",       0                               },      // AND ACCD With Acc
  { "apac",       0                               },      // Add P Register to Acc
  { "apl",        CF_USE1|CF_CHG1                 },      // AND Data Memory Value With DBMR or Long Constant
  { "apl",        CF_USE1|CF_USE2|CF_CHG2         },      // AND Data Memory Value With DBMR or Long Constant
  { "b",          CF_USE1|CF_STOP                 },      // Branch Unconditionally
  { "bacc",       CF_STOP|CF_JUMP                 },      // Branch to Location (Acc)
  { "baccd",      CF_JUMP                         },      // Branch to Location (Acc) Delayed
  { "banz",       CF_USE1                         },      // Branch on Aux Register Not Zero
  { "banzd",      CF_USE1                         },      // Branch on Aux Register Not Zero Delayed
  { "bcnd",       CF_USE1                         },      // Branch Conditionally
  { "bcndd",      CF_USE1                         },      // Branch Conditionally Delayed
  { "bd",         CF_USE1                         },      // Branch Unconditionally Delayed
  { "bit",        CF_USE1|CF_USE2                 },      // Test Bit
  { "bitt",       CF_USE1                         },      // Test Bit Specified by TREG2
  { "bldd",       CF_USE1|CF_CHG2                 },      // Block Move From Data Memory to Data Memory
  { "bldp",       CF_USE1                         },      // Block Move From Data Memory to Program Memory
  { "blpd",       CF_USE1|CF_CHG2                 },      // Block Move From Program Memory to Data Memory
  { "bsar",       CF_USE1                         },      // Barrel Shift
  { "cala",       CF_CALL|CF_JUMP                 },      // Call Subroutine at (Acc)
  { "calad",      CF_CALL|CF_JUMP                 },      // Call Subroutine at (Acc) Delayed
  { "call",       CF_USE1|CF_CALL                 },      // Call Unconditionally
  { "calld",      CF_USE1|CF_CALL                 },      // Call Unconditionally Delayed
  { "cc",         CF_USE1|CF_CALL                 },      // Call Conditionally
  { "ccd",        CF_USE1|CF_CALL                 },      // Call Conditionally Delayed
  { "clrc",       CF_CHG1                         },      // Clear Control Bit
  { "cmpl",       0                               },      // Complement Acc
  { "cmpr",       CF_USE1                         },      // Compare Aux Register With ARCR
  { "cpl",        CF_USE1                         },      // Compare DBMR or Long Immediate With Data Value
  { "cpl",        CF_USE1|CF_USE2                 },      // Compare DBMR or Long Immediate With Data Value
  { "crgt",       0                               },      // Test for Acc Greater Than ACCB
  { "crlt",       0                               },      // Test for Acc Smaller Than ACCB
  { "dmov",       CF_USE1                         },      // Data Move in Data Memory
  { "estop",      CF_STOP                         },      // Emulator Stop
  { "exar",       0                               },      // Exchange ACCB With Acc
  { "idle",       0                               },      // Idle Until Interrupt
  { "idle2",      0                               },      // Idle Until Interrupt - Low Power Mode
  { "in",         CF_CHG1|CF_USE2                 },      // Input Data From Port
  { "intr",       CF_USE1                         },      // Soft Interrupt
  { "lacb",       0                               },      // Load Acc With ACCB
  { "lacc",       CF_USE1                         },      // Load Acc With Shift
  { "lacl",       CF_USE1                         },      // Load Low Acc and Clear High Acc
  { "lact",       CF_USE1                         },      // Load Acc With Shift Specified by TREG1
  { "lamm",       CF_USE1                         },      // Load Acc With Memory-Mapped Register
  { "lar",        CF_CHG1|CF_USE2                 },      // Load Aux Register
  { "ldp",        CF_USE1                         },      // Load Data Memory Pointer
  { "lmmr",       CF_CHG1|CF_USE2                 },      // Load Memory-Mapped Register
  { "lph",        CF_USE1                         },      // Load Product High Register
  { "lst",        CF_USE1|CF_USE2                 },      // Load Status Register
  { "lt",         CF_USE1                         },      // Load TREG0
  { "lta",        CF_USE1                         },      // Load TREG0 and Accumulate Previous Product
  { "ltd",        CF_USE1                         },      // Load TREG0,Accumulate Previous Product and Move Data
  { "ltp",        CF_USE1                         },      // Load TREG0 and Store P -> Acc
  { "lts",        CF_USE1                         },      // Load TREG0 and Subtract Previous Product
  { "mac",        CF_USE1|CF_USE2                 },      // Multiply and Accumulate
  { "macd",       CF_USE1|CF_USE2                 },      // Multiply and Accumulate With Data Move
  { "madd",       CF_USE1                         },      // Multiply and Accumulate With Data Move and Dynamic Addressing
  { "mads",       CF_USE1                         },      // Multiply and Accumulate With Dynamic Addressing
  { "mar",        CF_USE1                         },      // Modify Aux Register
  { "mpy",        CF_USE1                         },      // Multiply
  { "mpya",       CF_USE1                         },      // Multiply and Accumulate Previous Product
  { "mpys",       CF_USE1                         },      // Multiply and Subtract Previous Product
  { "mpyu",       CF_USE1                         },      // Multiply Unsigned
  { "neg",        0                               },      // Negate Acc
  { "nmi",        0                               },      // Nonmaskable Interrupt
  { "nop",        0                               },      // No Operation
  { "norm",       0                               },      // Normalize Contents of Acc
  { "opl",        CF_USE1|CF_CHG1                 },      // OR With DBMS or Long Immediate
  { "opl",        CF_USE1|CF_USE2|CF_CHG2         },      // OR With DBMS or Long Immediate
  { "or",         CF_USE1                         },      // OR With Acc
  { "orb",        0                               },      // OR ACCB With Accumulator
  { "out",        CF_USE1|CF_USE2                 },      // Out Data to Port
  { "pac",        0                               },      // Load Acc <- P
  { "pop",        0                               },      // Pop Top of Stack to Low Acc
  { "popd",       CF_CHG1                         },      // Pop Top of Stack to Data Memory
  { "pshd",       CF_USE1                         },      // Push Data Memory Value Onto Stack
  { "push",       0                               },      // Push Low Acc Onto Stack
  { "ret",        CF_STOP                         },      // Return From Subroutine
  { "retc",       CF_USE1                         },      // Return Conditionally
  { "retcd",      CF_USE1                         },      // Return Conditionally Delayed
  { "retd",       0                               },      // Return From Subroutine Delayed
  { "rete",       CF_STOP                         },      // Enable Interrupts and Return From Interrupt
  { "reti",       CF_STOP                         },      // Return From Interrupt
  { "rol",        0                               },      // Rotate Acc Left
  { "rolb",       0                               },      // Rotate ACCB and Acc Left
  { "ror",        0                               },      // Rotate Acc Right
  { "rorb",       0                               },      // Rotate ACCB and Acc Right
  { "rpt",        CF_USE1                         },      // Repeat Next Instruction
  { "rptb",       CF_USE1                         },      // Repeat Block
  { "rptz",       CF_USE1                         },      // Repeat Preceded by Clearing Acc and P
  { "sacb",       0                               },      // Store Acc in ACCB
  { "sach",       CF_CHG1                         },      // Store High Acc With Shift
  { "sacl",       CF_CHG1                         },      // Store Low Acc With Shift
  { "samm",       CF_CHG1                         },      // Store Acc in Memory-Mapped Register
  { "sar",        CF_USE1|CF_CHG2                 },      // Store Aux Register
  { "sath",       0                               },      // Barrel Shift Acc as Specified by TREG1(4)
  { "satl",       0                               },      // Barrel Shift Acc as Specified by TREG1(3-0)
  { "sbb",        0                               },      // Subtract ACCB From Acc
  { "sbbb",       0                               },      // Subtract ACCB From Acc With Borrow
  { "sbrk",       CF_USE1                         },      // Subtract From Aux Register Short Immediate
  { "setc",       CF_CHG1                         },      // Set Control Bit
  { "sfl",        0                               },      // Shift Acc Left
  { "sflb",       0                               },      // Shift ACCB and Acc Left
  { "sfr",        0                               },      // Shift Acc Right
  { "sfrb",       0                               },      // Shift ACCB and Acc Right
  { "smmr",       CF_USE1|CF_CHG2                 },      // Store Memory-Mapped Register
  { "spac",       0                               },      // Subtract P From Acc
  { "sph",        CF_CHG1                         },      // Store High P Register
  { "spl",        CF_CHG1                         },      // Store Low P Register
  { "splk",       CF_USE1|CF_CHG2                 },      // Store Parallel Long Immediate
  { "spm",        CF_USE1                         },      // Store ACCB and Acc Right
  { "sqra",       CF_USE1                         },      // Square and Accumulate Previous Product
  { "sqrs",       CF_USE1                         },      // Square and Subtract Previous Product
  { "sst",        CF_USE1|CF_CHG2                 },      // Store Status Register
  { "sub",        CF_USE1                         },      // Subtract From Acc
  { "subb",       CF_USE1                         },      // Subtract From Acc With Borrow
  { "subc",       CF_USE1                         },      // Conditional Subtract
  { "subs",       CF_USE1                         },      // Subtract From Acc With Sign-Extension Suppressed
  { "subt",       CF_USE1                         },      // Subtract From Acc With Shift Specified by TREG1
  { "tblr",       CF_CHG1                         },      // Table Read
  { "tblw",       CF_USE1                         },      // Table Write
  { "trap",       0                               },      // Software Interrupt
  { "xc",         CF_USE1                         },      // Execute Conditionally
  { "xor",        CF_USE1                         },      // Exclusive-OR With Acc
  { "xorb",       0                               },      // Exclusive-OR of ACCB With Acc
  { "xpl",        CF_USE1|CF_CHG1                 },      // Exclusive-OR Data Memory Value
  { "xpl",        CF_USE1|CF_USE2|CF_CHG2         },      // Exclusive-OR Data Memory Value
  { "zalr",       CF_USE1                         },      // Zero Low Acc Load High Acc With Rounding
  { "zap",        0                               },      // Zero Acc and P
  { "zpr",        0                               },      // Zero P Register

  //
  //      TMS320C2x instructions
  //

  { "abs",        0                               },      // Absolute value of accumulator
  { "add",        CF_USE1                         },      // Add to accumulator with shift
  { "addc",       CF_USE1                         },      // Add to accumulator with carry
  { "addh",       CF_USE1                         },      // Add to high accumulator
  { "addk",       CF_USE1                         },      // Add to accumulator short immediate
  { "adds",       CF_USE1                         },      // Add to low accumulator with sign extension suppressed
  { "addt",       CF_USE1                         },      // Add to accumulator with shift specified by T register
  { "adlk",       CF_USE1                         },      // Add to accumulator long immediate with shift
  { "adrk",       CF_USE1                         },      // Add to auxiliary register short immediate
  { "and",        CF_USE1                         },      // And with accumulator
  { "andk",       CF_USE1                         },      // And immediate with accumulator with shift
  { "apac",       0                               },      // Add P register to accumulator
  { "b",          CF_USE1|CF_STOP                 },      // Branch unconditionally
  { "bacc",       CF_JUMP|CF_STOP                 },      // Branch to address specified by accumulator
  { "banz",       CF_USE1                         },      // Bnrach on auxiliary register not zero
  { "bbnz",       CF_USE1                         },      // Branch if tc bit != 0
  { "bbz",        CF_USE1                         },      // Branch if tc bit = 0
  { "bc",         CF_USE1                         },      // Branch on carry
  { "bgez",       CF_USE1                         },      // Branch if accumulator >= 0
  { "bgz",        CF_USE1                         },      // Branch if accumulator > 0
  { "bioz",       CF_USE1                         },      // Branch on i/o status = 0
  { "bit",        CF_USE1|CF_USE2                 },      // Test bit
  { "bitt",       CF_USE1                         },      // Test bit specifed by T register
  { "blez",       CF_USE1                         },      // Branch if accumulator <= 0
  { "blkd",       CF_USE1|CF_CHG2                 },      // Block move from data memory to data memory
  { "blkp",       CF_USE1|CF_CHG2                 },      // Block move from program memory to data memory
  { "blz",        CF_USE1                         },      // Branch if accumulator < 0
  { "bnc",        CF_USE1                         },      // Branch on no carry
  { "bnv",        CF_USE1                         },      // Branch if no overflow
  { "bnz",        CF_USE1                         },      // Branch if accumulator != 0
  { "bv",         CF_USE1                         },      // Branch on overflow
  { "bz",         CF_USE1                         },      // Branch if accumulator = 0
  { "cala",       CF_CALL|CF_JUMP                 },      // Call subroutine indirect
  { "call",       CF_USE1|CF_CALL                 },      // Call subroutine
  { "cmpl",       0                               },      // Complement accumulator
  { "cmpr",       0                               },      // Compare auxiliary register with auxiliary register ar0
  { "cnfd",       0                               },      // Configure block as data memory
  { "cnfp",       0                               },      // Configure block as program memory
  { "conf",       0                               },      // Configure block as data/program memory
  { "dint",       0                               },      // Disable interrupt
  { "dmov",       CF_USE1                         },      // Data move in data memory
  { "eint",       0                               },      // Enable interrupt
  { "fort",       0                               },      // Format serial port registers
  { "idle",       0                               },      // Idle until interrupt
  { "in",         CF_CHG1|CF_USE2                 },      // Input data from port
  { "lac",        CF_USE1                         },      // Load accumulator with shift
  { "lack",       CF_USE1                         },      // Load accumulator short immediate
  { "lact",       CF_USE1                         },      // Load accumulator with shift specified by T register
  { "lalk",       CF_USE1                         },      // Load accumulator long immediate with shift
  { "lar",        0                               },      // Load auxiliary register
  { "lark",       CF_CHG1|CF_USE2                 },      // Load auxiliary register short immediate
  { "larp",       0                               },      // Load auxiliary register pointer
  { "ldp",        CF_USE1                         },      // Load data memory page pointer
  { "ldpk",       CF_USE1                         },      // Load data memory page pointer immediate
  { "lph",        CF_USE1                         },      // Load high P register
  { "lrlk",       CF_USE1                         },      // Load auxiliary register long immediate
  { "lst",        CF_USE1                         },      // Load status register ST0
  { "lst1",       CF_USE1                         },      // Load status register ST1
  { "lt",         CF_USE1                         },      // Load T register
  { "lta",        CF_USE1                         },      // Load T register and accumulate previous product
  { "ltd",        CF_USE1                         },      // Load T register, accumulate previous product and move data
  { "ltp",        CF_USE1                         },      // Load T register and store P register in accumulator
  { "lts",        CF_USE1                         },      // Load T register and subtract previous product
  { "mac",        CF_USE1|CF_USE2                 },      // Multiply and accumulate
  { "macd",       CF_USE1|CF_USE2                 },      // Multiply and accumulate with data move
  { "mar",        CF_USE1                         },      // Modify auxiliary register
  { "mpy",        CF_USE1                         },      // Multiply (with T register, store product in P register)
  { "mpya",       CF_USE1                         },      // Multiply and accumulate previous product
  { "mpyk",       CF_USE1                         },      // Multiply immediate
  { "mpys",       CF_USE1                         },      // Multiply and subtract previous product
  { "mpyu",       CF_USE1                         },      // Multiply unsigned
  { "neg",        0                               },      // Negate accumulator
  { "nop",        0                               },      // No operation
  { "norm",       0                               },      // Normalize contents of accumulator
  { "or",         CF_USE1                         },      // Or with accumulator
  { "ork",        CF_USE1                         },      // Or immediate with accumulator with shift
  { "out",        CF_USE1|CF_USE2                 },      // Output data to port
  { "pac",        0                               },      // Load accumulator with P register
  { "pop",        0                               },      // Pop top of stack to low accumulator
  { "popd",       CF_CHG1                         },      // Pop top of stack to data memory
  { "pshd",       CF_USE1                         },      // Push data memory value onto stack
  { "push",       0                               },      // Push low accumulator onto stack
  { "rc",         0                               },      // Reset carry bit
  { "ret",        CF_STOP                         },      // Return from subroutine
  { "rfsm",       0                               },      // Reset serial port frame synchronization mode
  { "rhm",        0                               },      // Reset hold mode
  { "rol",        0                               },      // Rotate accumulator left
  { "ror",        0                               },      // Rotate acuumulator right
  { "rovm",       0                               },      // Reset overflow mode
  { "rpt",        CF_USE1                         },      // Repeat instruction as specified by data memory value
  { "rptk",       CF_USE1                         },      // Repeat instruction as specified by immediate value
  { "rsxm",       0                               },      // Reset sign extension mode
  { "rtc",        0                               },      // Reset test/control flag
  { "rtxm",       0                               },      // Reset serial port transmit mode
  { "rxf",        0                               },      // Reset external flag
  { "sach",       CF_CHG1                         },      // Store high accumulator with shift
  { "sacl",       CF_CHG1                         },      // Store low accumulator with shift
  { "sar",        CF_USE1|CF_CHG2                 },      // Store auxiliary register
  { "sblk",       CF_USE1                         },      // Subtract from accumulator long immediate with shift
  { "sbrk",       CF_USE1                         },      // Subtract from auxiliary register short immediate
  { "sc",         0                               },      // Set carry bit
  { "sfl",        0                               },      // Shift accumulator left
  { "sfr",        0                               },      // Shift accumulator right
  { "sfsm",       0                               },      // Set serial port frame synchronization mode
  { "shm",        0                               },      // Set hold mode
  { "sovm",       0                               },      // Set overflow mode
  { "spac",       0                               },      // Subtract P register from accumulator
  { "sph",        CF_CHG1                         },      // Store high P register
  { "spl",        CF_CHG1                         },      // Store low P register
  { "spm",        CF_USE1                         },      // Set P register output shift mode
  { "sqra",       CF_USE1                         },      // Square and accumulate
  { "sqrs",       CF_USE1                         },      // Square and subtract previous product
  { "sst",        CF_CHG1                         },      // Store status register ST0
  { "sst1",       CF_CHG1                         },      // Store status register ST1
  { "ssxm",       0                               },      // Set sign extension mode
  { "stc",        0                               },      // Set test/control flag
  { "stxm",       0                               },      // Set serial port transmit mode
  { "sub",        CF_USE1                         },      // Subtract from accumulator with shift
  { "subb",       CF_USE1                         },      // Subtract from accumulator with borrow
  { "subc",       CF_USE1                         },      // Conditional subtract
  { "subh",       CF_USE1                         },      // Subtract from high accumulator
  { "subk",       CF_USE1                         },      // Subtract from accumulator shoft immediate
  { "subs",       CF_USE1                         },      // Subtract from low accumulator with sign extension suppressed
  { "subt",       CF_USE1                         },      // Subtract from accumulator with shift specified by T register
  { "sxf",        0                               },      // Set external flag
  { "tblr",       CF_CHG1                         },      // Table read
  { "tblw",       CF_USE1                         },      // Table write
  { "trap",       0                               },      // Software interrupt
  { "xor",        CF_USE1                         },      // Exclusive or with accumulator
  { "xork",       CF_USE1                         },      // Exclusive or immediate with accumulator with shift
  { "zac",        0                               },      // Zero accumulator
  { "zalh",       CF_USE1                         },      // Zero low accumulator and load high accumulator
  { "zalr",       CF_USE1                         },      // Zero low accumulator and load high accumulator with rounding
  { "zals",       CF_USE1                         },      // Zero low accumulator and load high accumulator with sign extension suppressed
};

CASSERT(qnumber(Instructions) == TMS_last);
