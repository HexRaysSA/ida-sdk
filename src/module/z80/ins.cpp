/*
 *      Interactive disassembler (IDA).
 *      Version 2.05
 *      Copyright (c) 1990-93 by Ilfak Guilfanov. (2:5020/209@fidonet)
 *      ALL RIGHTS RESERVED.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

const instruc_t Instructions[] =
{

  { "",           0                               },              // Unknown Operation

  //
  //      Intel 8080/8085 instructions
  //

  { "aci",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Add immediate to A with carry
  { "adc",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Add reg to A with carry
  { "add",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Add <reg> to A
  { "adi",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Add immediate to A
  { "ana",        CF_USE1 | CF_CHG1 | CF_USE2     },              // And reg to A
  { "ani",        CF_USE1 | CF_CHG1 | CF_USE2     },              // And immediate to A
  { "call",       CF_USE1 | CF_CALL               },              // Call subroutine at <addr>
  { "cnz",        CF_USE1 | CF_CALL               },              // Call subroutine if non zero
  { "cz",         CF_USE1 | CF_CALL               },              // Call subroutine if zero
  { "cnc",        CF_USE1 | CF_CALL               },              // Call subroutine if carry clear
  { "cc",         CF_USE1 | CF_CALL               },              // Call subroutine if carry set
  { "cpo",        CF_USE1 | CF_CALL               },              // Call subroutine if odd  parity
  { "cpe",        CF_USE1 | CF_CALL               },              // Call subroutine if even parity
  { "cp",         CF_USE1 | CF_CALL               },              // Call subroutine if positive
  { "cm",         CF_USE1 | CF_CALL               },              // Call subroutine if negative
  { "cmc",        0                               },              // Complement carry
  { "cmp",        CF_USE1 | CF_USE2               },              // Compare register with A
  { "cpi",        CF_USE1 | CF_USE2               },              // Compare immediate data with A
  { "cma",        0                               },              // Complement A
  { "daa",        0                               },              // Decimal adjust A
  { "dad",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Add register pair to HL
  { "dcr",        CF_USE1 | CF_CHG1               },              // Decrement register
  { "dcx",        CF_USE1 | CF_CHG1               },              // Decrement register pair
  { "di",         0                               },              // Disable interrupts
  { "ei",         0                               },              // Enable interrupts
  { "hlt",        0                               },              // Halt
  { "in",         CF_CHG1 | CF_USE2               },              // Input from port to A
  { "inr",        CF_USE1 | CF_CHG1               },              // Increment register
  { "inx",        CF_USE1 | CF_CHG1               },              // Increment register pair
  { "jmp",        CF_USE1                         },              // Jump
  { "jnz",        CF_USE1                         },              // Jump if not zero
  { "jz",         CF_USE1                         },              // Jump if zero
  { "jnc",        CF_USE1                         },              // Jump if carry clear
  { "jc",         CF_USE1                         },              // Jump if carry set
  { "jpo",        CF_USE1                         },              // Jump if parity odd
  { "jpe",        CF_USE1                         },              // Jump if parity even
  { "jp",         CF_USE1                         },              // Jump if plus
  { "jm",         CF_USE1                         },              // Jump if minus
  { "lda",        CF_CHG1 | CF_USE2               },              // Load A direct from memory
  { "ldax",       CF_CHG1 | CF_USE2               },              // Load A indirect from memory using register pair
  { "lhld",       CF_CHG1 | CF_USE2               },              // Load HL direct from memory
  { "lxi",        CF_CHG1 | CF_USE2               },              // Load register pair with immediate data
  { "mov",        CF_CHG1 | CF_USE2               },              // Move register to register
  { "mvi",        CF_CHG1 | CF_USE2               },              // Move immediate data to register
  { "nop",        0                               },              // No Operation
  { "ora",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Or register with A
  { "ori",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Or immediate data to A
  { "out",        CF_USE1 | CF_USE2               },              // Output to port
  { "pchl",       CF_JUMP | CF_STOP               },              // Jump to instruction at (HL)
  { "pop",        CF_CHG1                         },              // Pop register pair from stack
  { "push",       CF_USE1                         },              // Push register pair onto stack
  { "ret",        CF_STOP                         },              // Return from subroutine
  { "rnz",        0                               },              // Return if non zero
  { "rz",         0                               },              // Return if zero
  { "rnc",        0                               },              // Return if carry clear
  { "rc",         0                               },              // Return if carry set
  { "rpo",        0                               },              // Return if parity odd
  { "rpe",        0                               },              // Return if parity even
  { "rp",         0                               },              // Return if plus
  { "rm",         0                               },              // Return if minus
  { "ral",        0                               },              // Rotate A left with carry
  { "rlc",        0                               },              // Rotate A left with branch carry
  { "rar",        0                               },              // Rotate A right with carry
  { "rrc",        0                               },              // Rotate A right with branch carry
  { "rst",        CF_USE1                         },              // Restart at vector <int>
  { "sbb",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract from A with borrow
  { "sbi",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract immediate from A with borrow
  { "stc",        0                               },              // Set carry
  { "sphl",       0                               },              // Exchange SP with HL
  { "sta",        CF_CHG1 | CF_USE2               },              // Store A direct memory
  { "stax",       CF_CHG1 | CF_USE2               },              // Store A indirect using register pair
  { "shld",       CF_CHG1 | CF_USE2               },              // Store HL
  { "sui",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract immediate from A
  { "sub",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract from A
  { "xra",        CF_USE1 | CF_CHG1 | CF_USE2     },              // XOR with A
  { "xri",        CF_USE1 | CF_CHG1 | CF_USE2     },              // XOR A with immediate data
  { "xchg",       0                               },              // Exchange DE with HL
  { "xthl",       0                               },              // Exchange HL with top of stack
  { "rim",        0                               },              // Read interrupt mask
  { "sim",        0                               },              // Store Interrupt mask

  //
  //      Z80 instructions
  //

  { "and",        CF_USE1 | CF_USE2 | CF_CHG1     },              // And with accumulator
  { "bit",        CF_USE1 | CF_USE2               },              // Test <bit> in operand
  { "call",       CF_USE2 | CF_CALL               },              // call (cond & uncond)
  { "ccf",        0                               },              // Complement carry flag
  { "cp",         CF_USE1 | CF_USE2               },              // Compare with accumulator
  { "cpd",        0                               },              // Compare accumulator with memory and\ndecrement address and byte counters
  { "cpdr",       0                               },              // Compare accumulator with memory and\ndecrement address and byte counter,\ncontinue until match is found or\nbyte counter is zero
  { "cpi",        0                               },              // Compare accumulator with memory and\nincrement address and byte counters
  { "cpir",       0                               },              // Compare accumulator with memory and\nincrement address and byte counter,\ncontinue until match is found or\nbyte counter is zero
  { "cpl",        0                               },              // Complement the accumulator
  { "dec",        CF_USE1 | CF_CHG1               },              // Decrement operand
  { "djnz",       CF_USE1                         },              // Decrement reg B and jump relative if zero
  { "ex",         CF_USE1 | CF_CHG1 | CF_USE2 | CF_CHG2 },        // Exchange operands
  { "exx",        0                               },              // Exchange register pairs and alt reg pairs
  { "halt",       0                               },              // Program execution stops
  { "im",         CF_USE1                         },              // Interrupt mode
  { "inc",        CF_USE1 | CF_CHG1               },              // Increment operand
  { "ind",        0                               },              // Input to memory and decrement pointer
  { "indr",       0                               },              // Input to memory and decrement pointer until\nbyte counter is zero
  { "ini",        0                               },              // Input to memory and increment pointer
  { "inir",       0                               },              // Input to memory and increment pointer until\nbyte counter is zero
  { "jp",         CF_USE2                         },              // Jump (conditional & unconditional)
  { "jr",         CF_USE1 | CF_USE2               },              // Jump relative (conditional & unconditional)
  { "ld",         CF_CHG1 | CF_USE2               },              // Move operand2 to operand1
  { "ldd",        0                               },              // Transfer data between memory and decrement\ndestination and source addresses
  { "lddr",       0                               },              // Transfer data between memory until byte\ncounter is zero, decrement destintation\nand source addresses
  { "ldi",        0                               },              // Transfer data between memory and increment\ndestination and source addresses
  { "ldir",       0                               },              // Transfer data between memory until byte\ncounter is zero, increment destination\nand source addresses
  { "neg",        0                               },              // Negate contents of accumulator
  { "or",         CF_USE1 | CF_CHG1 | CF_USE2     },              // Or with accumulator
  { "otdr",       0                               },              // Output from memory, decrement address\ncontinue until reg B is zero
  { "otir",       0                               },              // Output from memory, increment address\ncontinue until reg B is zero
  { "outd",       0                               },              // Output from memory, decrement address
  { "outi",       0                               },              // Output from memory, increment address
  { "res",        CF_USE1 | CF_CHG2 | CF_USE2     },              // Reset bit
  { "ret",        0                               },              // Return (cond & uncond)
  { "reti",       CF_STOP                         },              // Return from interrupt
  { "retn",       CF_STOP                         },              // Return from non-maskable interrupt
  { "rl",         CF_USE1 | CF_CHG1               },              // Rotate left through carry
  { "rla",        0                               },              // Rotate left through carry accumulator
  { "rlc",        CF_USE1 | CF_CHG1               },              // Rotate left branch carry
  { "rlca",       0                               },              // Rotate left accumulator
  { "rld",        0                               },              // Rotate one BCD digit left between the\naccumulator and memory
  { "rr",         CF_USE1 | CF_CHG1               },              // Rotate right through carry
  { "rra",        0                               },              // Rotate right through carry accumulator
  { "rrc",        CF_USE1 | CF_CHG1               },              // Rotate right branch carry
  { "rrca",       0                               },              // Rotate right branch  carry accumulator
  { "rrd",        0                               },              // Rotate one BCD digit right between the\naccumulator and memory
  { "scf",        0                               },              // Set carry flag
  { "sbc",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract from A with borrow
  { "set",        CF_USE1 | CF_CHG2 | CF_USE2     },              // Set bit
  { "sla",        CF_USE1 | CF_CHG1               },              // Shift left arithmetic
  { "sra",        CF_USE1 | CF_CHG1               },              // Shift right arithmetic
  { "srl",        CF_USE1 | CF_CHG1               },              // Shift right logical
  { "xor",        CF_USE1 | CF_CHG1 | CF_USE2     },              // Exclusive or with accumulator
  { "inp",        CF_USE1                         },              // Input from port (c) into operand
  { "outp",       CF_USE1                         },              // Output operand to port (c)
  { "srr",        CF_USE1                         },              // Shift left filling with 1
  //
  //      HD64180 extensions
  //
  { "in0",        CF_USE1 | CF_CHG1 | CF_USE2     },              // load register with input from port (n)
  { "mlt",        CF_USE1                         },              // multiplication of each half\nof the specified register pair\nwith the 16-bit result going to\nthe specified register pair
  { "otim",       0                               },              // load output port (c) with\nlocation (hl),\nincrement hl and b\ndecrement c
  { "otimr",      0                               },              // load output port (c) with\nlocation (hl),\nincrement hl and c\ndecrement b\nrepeat until b = 0
  { "otdm",       0                               },              // load output port (c) with\nlocation (hl),\ndecrement hl and b\ndecrement c
  { "otdmr",      0                               },              // load output port (c) with\nlocation (hl),\ndecrement hl and c\ndecrement b\nrepeat until b = 0
  { "out0",       CF_USE1                         },              // load output port (n) from register
  { "slp",        0                               },              // enter sleep mode
  { "tst",        CF_USE1                         },              // non-destructive'and' with accumulator and specified operand
  { "tstio",      CF_USE1                         },              // non-destructive 'and' of n and the contents of port (c)
  //
  //      A80 special instructions
  //
  { "lbcd",       CF_CHG1 | CF_USE2               },              // Move operand to BC
  { "lded",       CF_CHG1 | CF_USE2               },              // Move operand to DE
  { "lspd",       CF_CHG1 | CF_USE2               },              // Move operand to SP
  { "lixd",       CF_CHG1 | CF_USE2               },              // Move operand to IX
  { "liyd",       CF_CHG1 | CF_USE2               },              // Move operand to IY
  { "sbcd",       CF_CHG1 | CF_USE2               },              // Move BC to memory
  { "sded",       CF_CHG1 | CF_USE2               },              // Move DE to memory
  { "sspd",       CF_CHG1 | CF_USE2               },              // Move SP to memory
  { "sixd",       CF_CHG1 | CF_USE2               },              // Move IX to memory
  { "siyd",       CF_CHG1 | CF_USE2               },              // Move IY to memory
  { "xtix",       CF_USE1 | CF_CHG1 | CF_USE2 | CF_CHG2 },        // Exchange SP and IX
  { "xtiy",       CF_USE1 | CF_CHG1 | CF_USE2 | CF_CHG2 },        // Exchange SP and IY
  { "spix",       CF_CHG1 | CF_USE2               },              // Move IX to SP
  { "spiy",       CF_CHG1 | CF_USE2               },              // Move IY to SP
  { "pcix",       CF_USE2 | CF_STOP               },              // Jump indirect by IX
  { "pciy",       CF_USE2 | CF_STOP               },              // Jump indirect by IY
  { "mvra",       CF_CHG1 | CF_USE2               },              // Move A to R
  { "mvia",       CF_CHG1 | CF_USE2               },              // Move A to I
  { "mvar",       CF_CHG1 | CF_USE2               },              // Move R to A
  { "mvai",       CF_CHG1 | CF_USE2               },              // Move I to A
  { "dadix",      CF_USE1 | CF_CHG1 | CF_USE2     },              // Add operand to IX
  { "dadiy",      CF_USE1 | CF_CHG1 | CF_USE2     },              // Add operand to IY
  { "addc",       CF_USE1 | CF_CHG1 | CF_USE2     },              // Add operand to HL with carry
  { "addcix",     CF_USE1 | CF_CHG1 | CF_USE2     },              // Add operand to IX with carry
  { "addciy",     CF_USE1 | CF_CHG1 | CF_USE2     },              // Add operand to IY with carry
  { "subc",       CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract from HL with borrow
  { "subcix",     CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract from IX with borrow
  { "subciy",     CF_USE1 | CF_CHG1 | CF_USE2     },              // Subtract from IY with borrow
  { "jrc",        CF_USE2                         },              // Jump relative if carry
  { "jrnc",       CF_USE2                         },              // Jump relative if not carry
  { "jrz",        CF_USE2                         },              // Jump relative if zero
  { "jrnz",       CF_USE2                         },              // Jump relative if not zero
  { "cmpi",       0                               },              // Compare accumulator with memory and\nincrement address and byte counters
  { "cmpd",       0                               },              // Compare accumulator with memory and\ndecrement address and byte counters
  { "im0",        CF_USE1                         },              // Interrupt mode 0
  { "im1",        CF_USE1                         },              // Interrupt mode 1
  { "im2",        CF_USE1                         },              // Interrupt mode 2
  { "otd",        0                               },              // Output from memory, decrement address
  { "oti",        0                               },              // Output from memory, increment address

  // Intel 8085 undocumented instructions
  // (info from http://oak.oakland.edu/pub/cpm/maclib/i8085.lib)

  { "dsub",       0                               },               // (HL) <- (HL)-(BC), affects all flags
  { "arhl",       0                               },               // SHIFT HL RIGHT ONE BIT, (H7 IS DUPLICATED, L0 IS SHIFTED INTO CY)
  { "rdel",       0                               },               // ROTATE DE LEFT ONE BIT THRU CY, (E0 RECEIVES CY, CY RECEIVES D7)
  { "ldhi",       CF_USE1                         },               // (DE) <- (HL)+arg
  { "ldsi",       CF_USE1                         },               // (DE) <- (SP)+arg
  { "shlx",       0                               },               // ((DE)) <- (HL)
  { "lhlx",       0                               },               // (HL) <- ((DE))
  { "rstv",       0                               },               // RESTART 40H ON V (OVERFLOW)
  { "jx5",        CF_USE1                         },               // JUMP IF X5 SET
  { "jnx5",       CF_USE1                         },               // JUMP IF NOT X5 SET

  // Z380 instructions

  { "cplw",       CF_USE1                         },               // Complement HL register
  { "swap",       CF_USE1                         },               // Swap upper register word with lower register word
  { "inw",        CF_CHG1|CF_USE2                 },               // Input word
  { "outw",       CF_CHG1|CF_USE2                 },               // Output word
  { "ldw",        CF_CHG1|CF_USE2                 },               // Load word
  { "addw",       CF_CHG1|CF_USE2                 },               // Add word
  { "subw",       CF_CHG1|CF_USE2                 },               // Subtract word
  { "adcw",       CF_CHG1|CF_USE2                 },               // Add with carry word
  { "sbcw",       CF_CHG1|CF_USE2                 },               // Subtract with borrow word
  { "andw",       CF_CHG1|CF_USE2                 },               // AND logical word
  { "xorw",       CF_CHG1|CF_USE2                 },               // XOR logical word
  { "orw",        CF_CHG1|CF_USE2                 },               // OR logical word
  { "cpw",        CF_CHG1|CF_USE2                 },               // Compare word
  { "ddir",       CF_USE1                         },               // Decoder directive
  { "calr",       CF_USE1|CF_USE2                 },               // Call relative
  { "ldctl",      CF_CHG1|CF_USE2                 },               // Load control register
  { "mtest",      CF_USE1                         },               // Mode test
  { "exxx",       CF_USE1                         },               // Exchange Index Register with Alternate Bank
  { "exxy",       CF_USE1                         },               // Exchange Index Register with Alternate Bank
  { "exall",      CF_USE1                         },               // Exchange all registers with Alternate Bank
  { "setc",       CF_USE1                         },               // Set control bit
  { "resc",       CF_USE1                         },               // Reset control bit
  { "rlcw",       CF_USE1                         },               // Rotate Left Circular Word
  { "rrcw",       CF_USE1                         },               // Rotate Right Circular Word
  { "rlw",        CF_USE1                         },               // Rotate Left Word
  { "rrw",        CF_USE1                         },               // Rotate Right Word
  { "slaw",       CF_USE1                         },               // Shift Left Arithmetic Word
  { "sraw",       CF_USE1                         },               // Shift Right Arithmetic Word
  { "srlw",       CF_USE1                         },               // Shift Right Logical Word
  { "multw",      CF_USE1                         },               // Multiply Word
  { "multuw",     CF_USE1                         },               // Multiply Word Unsigned
  { "divuw",      CF_USE1                         },               // Divide unsigned
  { "outaw",      CF_CHG1|CF_USE1                 },               // Output word direct to port address
  { "inaw",       CF_CHG1|CF_USE1                 },               // Input word direct from port address
  { "outa",       CF_CHG1|CF_USE1                 },               // Output byte direct to port address
  { "ina",        CF_CHG1|CF_USE1                 },               // Input byte direct from port address
  { "negw",       CF_CHG1                         },               // Negate word
  { "exts",       CF_CHG1                         },               // Extend byte sign
  { "extsw",      CF_CHG1                         },               // Extend word sign
  { "btest",      0                               },               // Bank test
  { "ldiw",       0                               },               // Load and increment (word)
  { "ldirw",      0                               },               // Load and increment, repeat (word)
  { "lddw",       0                               },               // Load and decrement (word)
  { "lddrw",      0                               },               // Load and decrement, repeat (word)
  { "iniw",       0                               },               // Input and increment (word)
  { "inirw",      0                               },               // Input and increment, repeat (word)
  { "indw",       0                               },               // Input and decrement (word)
  { "indrw",      0                               },               // Input and decrement, repeat (word)
  { "outiw",      0                               },               // Output and increment (word)
  { "otirw",      0                               },               // Output and increment, repeat (word)
  { "outdw",      0                               },               // Output and decrement (word)
  { "otdrw",      0                               },               // Output and decrement, repeat (word)

  // Gameboy instructions

  { "ldh",        CF_CHG1|CF_USE2                 },
  { "stop",       CF_STOP                         },

};

CASSERT(sizeof(Instructions)/sizeof(Instructions[0]) == I5_last);
