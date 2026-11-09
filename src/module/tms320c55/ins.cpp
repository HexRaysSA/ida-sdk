/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "tms320c55.hpp"

const instruc_t Instructions[] =
{

  { "",           0                                                   }, // Unknown Operation

  // ARITHMETICAL OPERATIONS

  { "abdst",          CF_CHG1|CF_CHG2|CF_CHG3|CF_CHG4                 }, // Absolute Distance

  { "abs",            CF_CHG1                                         }, // Absolute Value
  { "abs",            CF_USE1|CF_CHG2                                 }, // Absolute Value

  { "add",            CF_CHG1                                         }, // Addition
  { "add",            CF_USE1|CF_CHG2                                 }, // Addition
  { "add",            CF_USE1|CF_USE2|CF_CHG3                         }, // Addition
  { "add",            CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Addition
  { "addv",           CF_CHG1                                         }, // Addition
  { "addv",           CF_USE1|CF_CHG2                                 }, // Addition
  { "addrv",          CF_CHG1                                         }, // Addition and Round
  { "addrv",          CF_USE1|CF_CHG2                                 }, // Addition and Round

  { "maxdiff",        CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Compare and Select Maximum
  { "dmaxdiff",       CF_USE1|CF_USE2|CF_CHG3|CF_CHG4|CF_CHG5         }, // Compare and Select 40-bit Maximum
  { "mindiff",        CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Compare and Select Minimum
  { "dmindiff",       CF_USE1|CF_USE2|CF_CHG3|CF_CHG4|CF_CHG5         }, // Compare and Select 40-bit Minimum

  { "addsubcc",       CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Conditional Add or Subtract
  { "addsubcc",       CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_CHG5         }, // Conditional Add or Subtract
  { "addsub2cc",      CF_USE1|CF_USE2|CF_USE3|CF_USE4|CF_USE5|CF_CHG6 }, // Conditional Add or Subtract

  { "sftcc",          CF_CHG1|CF_CHG2                                 }, // Conditional Shift

  { "subc",           CF_USE1|CF_CHG2                                 }, // Conditional Subtract
  { "subc",           CF_USE1|CF_USE2|CF_CHG3                         }, // Conditional Subtract

  { "addsub",         CF_USE1|CF_USE2|CF_CHG3                         }, // Paralleled Add - Subtract
  { "subadd",         CF_USE1|CF_USE2|CF_CHG3                         }, // Parallel Subtract - Add
  // "add","sub"

  { "mpy\0mpy",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply
  { "mpyr\0mpyr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply, and Round
  { "mpy40\0mpy40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply, on 40 bits
  { "mpyr40\0mpyr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply, and Round on 40 bits
  { "mac\0mpy",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Accumulate
  { "macr\0mpyr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Accumulate, and Round
  { "mac40\0mpy40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Accumulate, on 40 bits
  { "macr40\0mpyr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Accumulate, and Round on 40 bits
  { "mas\0mpy",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Subtract
  { "masr\0mpyr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Subtract, and Round
  { "mas40\0mpy40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Subtract, on 40 bits
  { "masr40\0mpyr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Subtract, and Round on 40 bits
  { "amar\0mpy",      CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply
  { "amar\0mpyr",     CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply, and Round
  { "amar\0mpy40",    CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply, on 40 bits
  { "amar\0mpyr40",   CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply, and Round on 40 bits
  { "mac\0mac",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Accumulate
  { "macr\0macr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Accumulate, and Round
  { "mac40\0mac40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Accumulate, on 40 bits
  { "macr40\0macr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Accumulate, and Round on 40 bits
  { "mas\0mac",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply and Subtract - Multiply and Accumulate
  { "masr\0macr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply and Subtract - Multiply and Accumulate, and Round
  { "mas40\0mac40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply and Subtract - Multiply and Accumulate, on 40 bits
  { "masr40\0macr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply and Subtract - Multiply and Accumulate, and Round on 40 bits
  { "amar\0mac",      CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Accumulate
  { "amar\0macr",     CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Accumulate, and Round
  { "amar\0mac40",    CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Accumulate, on 40 bits
  { "amar\0macr40",   CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Accumulate, and Round on 40 bits
  { "mas\0mas",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Subtract
  { "masr\0masr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Subtract, and Round
  { "mas40\0mas40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Subtract, on 40 bits
  { "masr40\0masr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Two Parallel Multiply and Subtract, and Round on 40 bits
  { "amar\0mas",      CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Subtract
  { "amar\0masr",     CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Subtract, and Round
  { "amar\0mas40",    CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Subtract, on 40 bits
  { "amar\0masr40",   CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Modify Auxiliary Register - Multiply and Subtract, and Round on 40 bits
  // "mac\0mac"
  { "mpy\0mac",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Multiply and Accumulate
  { "mpyr\0macr",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Multiply and Accumulate, and Round
  { "mpy40\0mac40",   CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Multiply and Accumulate, on 40 bits
  { "mpyr40\0macr40", CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_USE5|CF_CHG6 }, // Parallel Multiply - Multiply and Accumulate, and Round on 40 bits
  // "mac\0mac"
  // "mas\0mac"
  // "amar\0mac"
  { "amar",           CF_CHG1|CF_CHG2|CF_CHG3                         }, // Three Parallel Modify Auxiliary Registers

  { "firsadd",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4|CF_CHG5         }, // Parallel Multiply and Accumulate - Add
  { "firssub",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4|CF_CHG5         }, // Parallel Multiply and Accumulate - Subtract

  { "mpym\0mov",      CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Multiply - Store
  { "mpymr\0mov",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Multiply - Store, and Round
  { "macm\0mov",      CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Multiply and Accumulate - Store
  { "macmr\0mov",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Multiply and Accumulate - Store, and Round
  { "masm\0mov",      CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Multiply and Subtract - Store
  { "masmr\0mov",     CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Multiply and Subtract - Store, and Round
  { "add\0mov",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Add - Store
  { "sub\0mov",       CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Subtract - Store
  { "mov\0mov",       CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Parallel Load - Store
  { "mov\0aadd",      CF_USE1|CF_CHG2|CF_USE3|CF_CHG4                 }, // Parallel Load - aadd
  { "mov\0add",       CF_USE1|CF_CHG2|CF_USE3|CF_USE4|CF_CHG5         }, // Parallel Load - aadd
  { "amar\0amar",     CF_CHG1|CF_CHG2                                                             },
  { "add\0asub",      CF_USE1|CF_USE2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Add  - asub
  { "btst\0mov",      CF_USE1|CF_CHG2|CF_CHG3|CF_USE4|CF_CHG5         }, // Parallel Bit Test  - Store
  { "mov\0asub",      CF_USE1|CF_CHG2|CF_USE3|CF_CHG4                 }, // Parallel Load - aadd

  // "macm\0mov"
  // "masm\0mov"

  { "lms",            CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Least Mean Square

  { "max",            CF_CHG1                                         }, // Maximum Comparison
  { "max",            CF_USE1|CF_CHG2                                 }, // Maximum Comparison
  { "min",            CF_CHG1                                         }, // Minimum Comparison
  { "min",            CF_USE1|CF_CHG2                                 }, // Minimum Comparison

  { "cmp",            CF_USE1|CF_CHG2                                 }, // Memory Comparison
  { "cmpu",           CF_USE1|CF_CHG2                                 }, // Unsigned memory Comparison

  { "aadd",           CF_USE1|CF_CHG2                                 }, // Add Two Registers
  { "asub",           CF_USE1|CF_CHG2                                 }, // Subtract Two Registers
  { "amov",           CF_USE1|CF_CHG2                                 }, // Move From Register to Register
  // "aadd"
  // "asub"
  // "amov"
  { "amar",           CF_CHG1                                         }, // Auxiliary Register Modification

  // { "aadd",       CF_USE1|CF_CHG2                                     }, // Modify Data Stack Pointer

  { "sqr",            CF_CHG1                                         }, // Square
  { "sqr",            CF_CHG1|CF_USE2                                 }, // Square
  { "sqrr",           CF_CHG1                                         }, // Square and Round
  { "sqrr",           CF_CHG1|CF_USE2                                 }, // Square and Round
  { "mpy",            CF_CHG1                                         }, // Multiply
  { "mpy",            CF_CHG1|CF_CHG2                                 }, // Multiply
  { "mpy",            CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply
  { "mpyr",           CF_CHG1                                         }, // Multiply and Round
  { "mpyr",           CF_CHG1|CF_CHG2                                 }, // Multiply and Round
  { "mpyr",           CF_CHG1|CF_USE2|CF_CHG3                         }, // Multiply and Round
  { "mpyk",           CF_USE1|CF_CHG2                                 }, // Multiply by Constant
  { "mpyk",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply by Constant
  { "mpykr",          CF_USE1|CF_CHG2                                 }, // Multiply by Constant and Round
  { "mpykr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply by Constant and Round
  { "mpym",           CF_USE1|CF_CHG2                                 }, // Multiply Memory Value
  { "mpym",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Values
  { "mpymr",          CF_USE1|CF_CHG2                                 }, // Multiply Memory Value and Round
  { "mpymr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Values and Round
  { "mpym40",         CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Values on 40 bits
  { "mpymr40",        CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Values and Round on 40 bits
  { "mpymu",          CF_USE1|CF_USE2|CF_CHG3                         }, // Unsigned multiply Memory Values
  { "mpymru",         CF_USE1|CF_USE2|CF_CHG3                         }, // Unsigned multiply Memory Values and Round
  { "sqrm",           CF_USE1|CF_CHG2                                 }, // Square Memory Value
  { "sqrmr",          CF_USE1|CF_CHG2                                 }, // Square Memory Value, and Round
  { "mpymk",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Value by Constant
  { "mpymkr",         CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Value by Constant and Round

  { "sqa",            CF_CHG1                                         }, // Square and Accumulate
  { "sqa",            CF_CHG1|CF_USE2                                 }, // Square and Accumulate
  { "sqar",           CF_CHG1                                         }, // Square, Accumulate and Round
  { "sqar",           CF_CHG1|CF_USE2                                 }, // Square, Accumulate and Round
  { "mac",            CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate
  { "mac",            CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Multiply and Accumulate
  { "macr",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply, Accumulate and Round
  { "macr",           CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Multiply, Accumulate and Round
  { "mack",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply by Constant and Accumulate
  { "mack",           CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply by Constant and Accumulate
  { "mackr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply by Constant, Round and Accumulate
  { "mackr",          CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply by Constant, Round and Accumulate
  { "macm",           CF_USE1|CF_CHG2                                 }, // Multiply and Accumulate Memory Values
  { "macm",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate Memory Values
  { "macm",           CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Accumulate Memory Values
  { "macmr",          CF_USE1|CF_CHG2                                 }, // Multiply and Accumulate Memory Values, and Round
  { "macmr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate Memory Values, and Round
  { "macmr",          CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Accumulate Memory Values, and Round
  { "macm40",         CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate Memory Values, on 40 bits
  { "macm40",         CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Accumulate Memory Values, on 40 bits
  { "macmr40",        CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate Memory Values, and Round on 40 bits
  { "macmr40",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Accumulate Memory Values, and Round on 40 bits
  { "macmz",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate Memory Values
  { "macmrz",         CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Accumulate Memory Values, and Round
  { "sqam",           CF_USE1|CF_CHG2                                 }, // Square and Accumulate Memory Value
  { "sqam",           CF_USE1|CF_USE2|CF_CHG3                         }, // Square and Accumulate Memory Values
  { "sqamr",          CF_USE1|CF_CHG2                                 }, // Square and Accumulate Memory Value, and Round
  { "sqamr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Square and Accumulate Memory Values, and Round
  { "macmk",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Value by Constant and Accumulate
  { "macmk",          CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply Memory Value by Constant and Accumulate
  { "macmkr",         CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply Memory Value by Constant - Accumulate, and Round
  { "macmkr",         CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply Memory Value by Constant - Accumulate, and Round

  { "sqs",            CF_CHG1                                         }, // Square and Subtract
  { "sqs",            CF_CHG1|CF_USE2                                 }, // Square and Subtract
  { "sqsr",           CF_CHG1                                         }, // Square, Subtract and Round
  { "sqsr",           CF_CHG1|CF_USE2                                 }, // Square, Subtract and Round
  { "mas",            CF_USE1|CF_CHG2                                 }, // Multiply and Subtract
  { "mas",            CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Subtract
  { "masr",           CF_USE1|CF_CHG2                                 }, // Multiply, Subtract and Round
  { "masr",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply, Subtract and Round
  { "masm",           CF_USE1|CF_CHG2                                 }, // Multiply and Subtract Memory Value
  { "masm",           CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Subtract Memory Values
  { "masm",           CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Subtract Memory Values
  { "masmr",          CF_USE1|CF_CHG2                                 }, // Multiply and Subtract Memory Value, and Round
  { "masmr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Subtract Memory Values, and Round
  { "masmr",          CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Subtract Memory Values, and Round
  { "masm40",         CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Subtract Memory Values, on 40 bits
  { "masm40",         CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Subtract Memory Values, on 40 bits
  { "masmr40",        CF_USE1|CF_USE2|CF_CHG3                         }, // Multiply and Subtract Memory Values, and Round on 40 bits
  { "masmr40",        CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Multiply and Subtract Memory Values, and Round on 40 bits
  { "sqsm",           CF_USE1|CF_CHG2                                 }, // Square and Subtract Memory Values
  { "sqsm",           CF_USE1|CF_USE2|CF_CHG3                         }, // Square and Subtract Memory Values
  { "sqsmr",          CF_USE1|CF_CHG2                                 }, // Square and Subtract Memory Values, and Round
  { "sqsmr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Square and Subtract Memory Values, and Round

  { "neg",            CF_CHG1                                         }, // Negation
  { "neg",            CF_CHG1|CF_USE2                                 }, // Negation

  { "mant\0nexp",     CF_USE1|CF_CHG2|CF_USE3|CF_CHG4                 }, // Exponent and Mantissa
  { "exp",            CF_USE1|CF_CHG2                                 }, // Exponent

  { "cmpand",         CF_USE1|CF_CHG2|CF_CHG3                         }, // Compare and AND
  { "cmpandu",        CF_USE1|CF_CHG2|CF_CHG3                         }, // Unsigned compare and AND
  { "cmpor",          CF_USE1|CF_CHG2|CF_CHG3                         }, // Compare and OR
  { "cmporu",         CF_USE1|CF_CHG2|CF_CHG3                         }, // Unsigned compare and OR

  { "round",          CF_CHG1                                         }, // Round
  { "round",          CF_USE1|CF_CHG2                                 }, // Round

  { "sat",            CF_CHG1                                         }, // Saturate
  { "sat",            CF_USE1|CF_CHG2                                 }, // Saturate
  { "satr",           CF_CHG1                                         }, // Saturate and Round
  { "satr",           CF_USE1|CF_CHG2                                 }, // Saturate and Round

  { "sfts",           CF_CHG1|CF_USE2                                 }, // Signed Shift
  { "sfts",           CF_USE1|CF_USE2|CF_CHG3                         }, // Signed Shift
  { "sftsc",          CF_CHG1|CF_USE2                                 }, // Signed Shift with Carry
  { "sftsc",          CF_USE1|CF_USE2|CF_CHG3                         }, // Signed Shift with Carry

  { "sqdst",          CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Square distance

  { "sub",            CF_USE1                                         }, // Subtract
  { "sub",            CF_USE1|CF_CHG2                                 }, // Subtract
  { "sub",            CF_USE1|CF_USE2|CF_CHG3                         }, // Subtract
  { "sub",            CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Subtract

  // BIT MANIPULATION OPERATIONS

  { "band",           CF_USE1|CF_USE2|CF_CHG3                         }, // Bit Field Comparison

  { "bfxpa",          CF_USE1|CF_USE2|CF_CHG3                         }, // Bit Field Expand

  { "bfxtr",          CF_USE1|CF_USE2|CF_CHG3                         }, // Bit Field Extract

  { "btst",           CF_USE1|CF_CHG2|CF_CHG3                         }, // Bit Test
  { "bnot",           CF_USE1|CF_CHG2                                 }, // Bit NOT
  { "bclr",           CF_USE1|CF_CHG2                                 }, // Bit Clear
  { "bset",           CF_USE1|CF_CHG2                                 }, // Bit Set
  { "btstset",        CF_USE1|CF_CHG2|CF_CHG3                         }, // Bit Test and Set
  { "btstclr",        CF_USE1|CF_CHG2|CF_CHG3                         }, // Bit Test and Clear
  { "btstnot",        CF_USE1|CF_CHG2|CF_CHG3                         }, // Bit Test and NOT
  { "btstp",          CF_USE1|CF_USE2                                 }, // Bit Pair Test
  { "bclr",           CF_CHG1                                         }, // Bit Clear
  { "bset",           CF_CHG1                                         }, // Bit Set

  // EXTENDED AUXILIARY REGISTER OPERATIONS

  { "amar",           CF_USE1|CF_CHG2                                 }, // Load Effective Address to Extended Auxiliary Register
  { "popboth",        CF_CHG1                                         }, // Pop Extended Auxiliary Register from Stack Pointers
  { "pshboth",        CF_USE1                                         }, // Push Extended Auxiliary Register to Stack Pointers

  // LOGICAL OPERATIONS

  { "bcnt",           CF_USE1|CF_USE2|CF_CHG3|CF_CHG4                 }, // Count Bit Field

  { "not",            CF_CHG1                                         }, // NOT
  { "not",            CF_USE1|CF_CHG2                                 }, // NOT

  { "and",            CF_USE1                                         }, // AND
  { "and",            CF_USE1|CF_CHG2                                 }, // AND
  { "and",            CF_USE1|CF_USE2|CF_CHG3                         }, // AND

  { "or",             CF_USE1                                         }, // OR
  { "or",             CF_USE1|CF_CHG2                                 }, // OR
  { "or",             CF_USE1|CF_USE2|CF_CHG3                         }, // OR

  { "xor",            CF_USE1                                         }, // XOR
  { "xor",            CF_USE1|CF_CHG2                                 }, // XOR
  { "xor",            CF_USE1|CF_USE2|CF_CHG3                         }, // XOR

  { "sftl",           CF_USE1|CF_USE2                                 }, // Logical Shift
  { "sftl",           CF_USE1|CF_USE2|CF_CHG3                         }, // Logical Shift

  { "rol",            CF_CHG1|CF_USE2|CF_USE3|CF_CHG4                 }, // Rotate Left

  { "ror",            CF_USE1|CF_USE2|CF_USE3|CF_CHG4                 }, // Rotate Right

  // MOVE OPERATIONS

  { "swap",           CF_CHG1|CF_CHG2                                 }, // Swap Registers
  { "swapp",          CF_CHG1|CF_CHG2                                 }, // Swap Pair Registers
  { "swap4",          CF_CHG1|CF_CHG2                                 }, // Swap 4 Registers

  { "mov",            CF_USE1|CF_CHG2                                 }, // Move Data
  { "mov",            CF_USE1|CF_USE2|CF_CHG3                         }, // Move 2 Data
  { "mov40",          CF_USE1|CF_CHG2                                 }, // Move Data on 40 bits

  { "delay",          CF_USE1                                         }, // Memory Delay

  { "pop",            CF_CHG1                                         }, // Pop Top of Stack
  { "pop",            CF_CHG1|CF_CHG2                                 }, // Pop Top of Stack

  { "psh",            CF_USE1                                         }, // Pop Top of Stack
  { "psh",            CF_USE1|CF_USE2                                 }, // Pop Top of Stack

  // PROGRAM CONTROL OPERATIONS

  { "bcc",            CF_USE1|CF_USE2                                 }, // Branch Conditionally
  { "bccu",           CF_USE1|CF_USE2                                 }, // Branch Conditionally

  { "b",              CF_USE1|CF_STOP                                 }, // Branch Unconditionally

  { "callcc",         CF_USE1|CF_USE2|CF_CALL                         }, // Call Conditionally

  { "call",           CF_USE1|CF_CALL                                 }, // Call Unconditionally

  { "xcc",            CF_USE1                                         }, // Execute Conditionally
  { "xccpart",        CF_USE1                                         }, // Execute Conditionally

  { "idle",           0                                               }, // Idle

  { "nop",            0                                               }, // No Operation
  { "nop_16",         0                                               }, // No Operation

  { "rptblocal",      CF_USE1                                         }, // Repeat Block of Instructions Unconditionally
  { "rptb",           CF_USE1                                         }, // Repeat Block of Instructions Unconditionally

  { "rptcc",          CF_USE1|CF_USE2                                 }, // Repeat Single Instruction Conditionally

  { "rpt",            CF_USE1                                         }, // Repeat Single Instruction Unconditionally
  { "rptadd",         CF_USE1|CF_USE2                                 }, // Repeat Single Instruction Unconditionally and Add to Register
  { "rptsub",         CF_USE1|CF_USE2                                 }, // Repeat Single Instruction Unconditionally and Subtract to Register

  { "retcc",          CF_USE1                                         }, // Return Conditionally
  { "ret",            CF_STOP                                         }, // Return Unconditionally
  { "reti",           CF_STOP                                         }, // Return from Interrupt

  { "intr",           CF_USE1                                         }, // Software Interrupt

  { "reset",          0                                               }, // Software Reset

  { "trap",           CF_USE1                                         }, // Software Trap

};

CASSERT(qnumber(Instructions) == TMS320C55_last);
