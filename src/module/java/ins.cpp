/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include "ins.hpp"

// ATTENTION: if change mnemonic(s) change version in 'jas_rw.cc'
const instruc_t Instructions[] =
{

  { "nop",          0 },         // Do nothing
  { "aconst_null",  0 },         // Push null object reference
  { "iconst_m1",    0 },         // Push integer constant -1
  { "iconst_0",     0 },         // Push the integer 0
  { "iconst_1",     0 },         // Push the integer 1
  { "iconst_2",     0 },         // Push the integer 2
  { "iconst_3",     0 },         // Push the integer 3
  { "iconst_4",     0 },         // Push the integer 4
  { "iconst_5",     0 },         // Push the integer 5
  { "lconst_0",     0 },         // Push the long integer 0
  { "lconst_1",     0 },         // Push the long integer 1
  { "fconst_0",     0 },         // Push the single-precision foating point 0.0
  { "fconst_1",     0 },         // Push the single-precision foating point 1.0
  { "fconst_2",     0 },         // Push the single-precision foating point 2.0
  { "dconst_0",     0 },         // Push the double-precision foating point 0.0
  { "dconst_1",     0 },         // Push the double-precision foating point 1.0
  { "bipush",       CF_USE1 },   // Push one-byte integer
  { "sipush",       CF_USE1 },   // Push two-byte integer
  { "ldc",          CF_USE1 },   // Push item from constant pool (i1)
  { "ldc_w",        CF_USE1 },   // Push item from constant pool (i2)
  { "ldc2_w",       CF_USE1 },   // Push long or double from constant pool
  { "iload",        CF_USE1 },   // Push integer value of the local variable
  { "lload",        CF_USE1 },   // Push long value of the local variable
  { "fload",        CF_USE1 },   // Push single-float. val. of the local variable
  { "dload",        CF_USE1 },   // Push double-float. val. of the local variable
  { "aload",        CF_USE1 },   // Push object reference from the local variable
  { "iload_0",      0 },         // Push integer value of the local variable #0
  { "iload_1",      0 },         // Push integer value of the local variable #1
  { "iload_2",      0 },         // Push integer value of the local variable #2
  { "iload_3",      0 },         // Push integer value of the local variable #3
  { "lload_0",      0 },         // Push long value of the local variable #0
  { "lload_1",      0 },         // Push long value of the local variable #1
  { "lload_2",      0 },         // Push long value of the local variable #2
  { "lload_3",      0 },         // Push long value of the local variable #3
  { "fload_0",      0 },         // Push single-flt. val. of the local variable #0
  { "fload_1",      0 },         // Push single-flt. val. of the local variable #1
  { "fload_2",      0 },         // Push single-flt. val. of the local variable #2
  { "fload_3",      0 },         // Push single-flt. val. of the local variable #3
  { "dload_0",      0 },         // Push double-flt. val. of the local variable #0
  { "dload_1",      0 },         // Push double-flt. val. of the local variable #1
  { "dload_2",      0 },         // Push double-flt. val. of the local variable #2
  { "dload_3",      0 },         // Push double-flt. val. of the local variable #3
  { "aload_0",      0 },         // Push object reference from the local var. #0
  { "aload_1",      0 },         // Push object reference from the local var. #1
  { "aload_2",      0 },         // Push object reference from the local var. #2
  { "aload_3",      0 },         // Push object reference from the local var. #3
  { "iaload",       0 },         // Push integer from array
  { "laload",       0 },         // Push long from array
  { "faload",       0 },         // Push single float from array
  { "daload",       0 },         // Push double float from array
  { "aaload",       0 },         // Push object reference from array
  { "baload",       0 },         // Push signed byte from array
  { "caload",       0 },         // Push signed char from array
  { "saload",       0 },         // Push short from array
  { "istore",       CF_CHG1 },   // Pop integer value into local variable
  { "lstore",       CF_CHG1 },   // Pop long value into local variable
  { "fstore",       CF_CHG1 },   // Pop single float value into local variable
  { "dstore",       CF_CHG1 },   // Pop double float value into local variable
  { "astore",       CF_CHG1 },   // Pop object refernce into local variable
  { "istore_0",     0 },         // Pop integer value into local variable #0
  { "istore_1",     0 },         // Pop integer value into local variable #1
  { "istore_2",     0 },         // Pop integer value into local variable #2
  { "istore_3",     0 },         // Pop integer value into local variable #3
  { "lstore_0",     0 },         // Pop long value into local variable #0
  { "lstore_1",     0 },         // Pop long value into local variable #1
  { "lstore_2",     0 },         // Pop long value into local variable #2
  { "lstore_3",     0 },         // Pop long value into local variable #3
  { "fstore_0",     0 },         // Pop single float value into local variable #0
  { "fstore_1",     0 },         // Pop single float value into local variable #1
  { "fstore_2",     0 },         // Pop single float value into local variable #2
  { "fstore_3",     0 },         // Pop single float value into local variable #3
  { "dstore_0",     0 },         // Pop doublefloat value into local variable #0
  { "dstore_1",     0 },         // Pop doublefloat value into local variable #1
  { "dstore_2",     0 },         // Pop doublefloat value into local variable #2
  { "dstore_3",     0 },         // Pop doublefloat value into local variable #3
  { "astore_0",     0 },         // Pop object refernce into local variable #0
  { "astore_1",     0 },         // Pop object refernce into local variable #1
  { "astore_2",     0 },         // Pop object refernce into local variable #2
  { "astore_3",     0 },         // Pop object refernce into local variable #3
  { "iastore",      0 },         // Pop integer from array
  { "lastore",      0 },         // Pop long from array
  { "fastore",      0 },         // Pop single float from array
  { "dastore",      0 },         // Pop double float from array
  { "aastore",      0 },         // Pop object reference from array
  { "bastore",      0 },         // Pop signed byte from array
  { "castore",      0 },         // Pop signed char from array
  { "sastore",      0 },         // Pop short from array
  { "pop",          0 },         // Pop top stack word
  { "pop2",         0 },         // Pop top two stack word
  { "dup",          0 },         // Duplicate top stack word
  { "dup_x1",       0 },         // Duplicate top stack word and put two down
  { "dup_x2",       0 },         // Duplicate top stack word and put three down
  { "dup2",         0 },         // Duplicate top two stack word
  { "dup2_x1",      0 },         // Duplicate top two stack words and put two down
  { "dup2_x2",      0 },         // Duplicate top two stack words and put three down
  { "swap",         0 },         // Swap two top stack words
  { "iadd",         0 },         // Integer add
  { "ladd",         0 },         // Long add
  { "fadd",         0 },         // Single float add
  { "dadd",         0 },         // Double float add
  { "isub",         0 },         // Integer subtract
  { "lsub",         0 },         // Long subtract
  { "fsub",         0 },         // Single float subtract
  { "dsub",         0 },         // Double float subtract
  { "imul",         0 },         // Integer multiply
  { "lmul",         0 },         // Long multiply
  { "fmul",         0 },         // Single float multiply
  { "dmul",         0 },         // Double float multiply
  { "idiv",         0 },         // Integer divide
  { "ldiv",         0 },         // Long divide
  { "fdiv",         0 },         // Single float divide
  { "ddiv",         0 },         // Double float divide
  { "irem",         0 },         // Integer remainder
  { "lrem",         0 },         // Long remainder
  { "frem",         0 },         // Single float remainder
  { "drem",         0 },         // Double float remainder
  { "ineg",         0 },         // Integer negate
  { "lneg",         0 },         // Long negate
  { "fneg",         0 },         // Single float negate
  { "dneg",         0 },         // Double float negate
  { "ishl",         0 },         // Integer shift left
  { "lshl",         0 },         // Long shift left
  { "ishr",         0 },         // Integer logical shift right
  { "lshr",         0 },         // Long logical shift right
  { "iushr",        0 },         // Integer arithmetic shift right
  { "lushr",        0 },         // Long arithmeticshift right
  { "iand",         0 },         // Integer boolean AND
  { "land",         0 },         // Long boolean AND
  { "ior",          0 },         // Integer boolean OR
  { "lor",          0 },         // Long boolean OR
  { "ixor",         0 },         // Integer boolean XOR
  { "lxor",         0 },         // Long boolean XOR
  { "iinc",         CF_CHG1|CF_USE2 }, // Add 8-bit signed const to local variable
  { "i2l",          0 },         // Integer to Long conversion
  { "i2f",          0 },         // Integer to Single float conversion
  { "i2d",          0 },         // Integer to Double float conversion
  { "l2i",          0 },         // Long to Integer conversion
  { "l2f",          0 },         // Long to Single float conversion
  { "l2d",          0 },         // Long to Double float conversion
  { "f2i",          0 },         // Single float to Integer conversion
  { "f2l",          0 },         // Single float to Long conversion
  { "f2d",          0 },         // Single float to Double float conversion
  { "d2i",          0 },         // Double float to Integer conversion
  { "d2l",          0 },         // Double float to Long conversion
  { "d2f",          0 },         // Double float to Single float conversion
  { "int2byte",     0 },         // Integer to signed byte conversion
  { "int2char",     0 },         // Integer to unsigned short conversion
  { "int2short",    0 },         // Integer to signed short conversion
  { "lcmp",         0 },         // Long compare
  { "fcmpl",        0 },         // Single float compare (-1 on NaN)
  { "fcmpg",        0 },         // Single float compare (1 on NaN)
  { "dcmpl",        0 },         // Double float compare (-1 on NaN)
  { "dcmpg",        0 },         // Double float compare (1 on NaN)
  { "ifeq",         CF_USE1 },   // Branch if equal to 0
  { "ifne",         CF_USE1 },   // Branch if not equal to 0
  { "iflt",         CF_USE1 },   // Branch if less then 0
  { "ifge",         CF_USE1 },   // Branch if greater than or equal to 0
  { "ifgt",         CF_USE1 },   // Branch if greater than 0
  { "ifle",         CF_USE1 },   // Branch if less than or equal to 0
  { "if_icmpeq",    CF_USE1 },   // Branch if integers equal
  { "if_icmpne",    CF_USE1 },   // Branch if integers not equal
  { "if_icmplt",    CF_USE1 },   // Branch if integers less than
  { "if_icmpge",    CF_USE1 },   // Branch if integers grater than or equal to
  { "if_icmpgt",    CF_USE1 },   // Branch if integers grater than
  { "if_icmple",    CF_USE1 },   // Branch if integers less than or equal to
  { "if_acmpeq",    CF_USE1 },   // Branch if object references are equal
  { "if_acmpne",    CF_USE1 },   // Branch if object references not equal
  { "goto",         CF_USE1|CF_STOP }, // Branch always
  { "jsr",          CF_USE1|CF_CALL }, // Jump subroutine
  { "ret",          CF_USE1|CF_STOP },   // Return from subroutine
  { "tableswitch",  CF_USE1|CF_USE2|CF_USE3 }, // Access jump table by index and jump
  { "lookupswitch", CF_USE1|CF_USE2 }, // Access jump table by key match and jump
  { "ireturn",      CF_STOP },   // Return integer from function
  { "lreturn",      CF_STOP },   // Return long from function
  { "freturn",      CF_STOP },   // Return single float from function
  { "dreturn",      CF_STOP },   // Return double float from function
  { "areturn",      CF_STOP },   // Return object reference from function
  { "return",       CF_STOP },   // Return (void) from procedure
  { "getstatic",    CF_USE1 },   // Set static field from class
  { "putstatic",    CF_USE1 },   // Set static field in class
  { "getfield",     CF_USE1 },   // Fetch field from object
  { "putfield",     CF_CHG1 },   // Set field in object
  { "invokevirtual", CF_USE1|CF_USE2|CF_CALL }, // invoke instance method
  { "invokespecial", CF_USE1|CF_CALL }, // invoke instance method (super/private/init)
  { "invokestatic", CF_USE1|CF_CALL },     // invoke a class (static) method
  { "invokeinterface", CF_USE1|CF_USE2|CF_USE3|CF_CALL },  // invoke interface method
  { "invokedynamic", CF_USE1|CF_USE2|CF_CALL },         //
  { "new",          CF_USE1 },   // Create new object
  { "newarray",     CF_USE1 },   // Allocate new array
  { "anewarray",    CF_USE1 },   // Allocate new array of references to object
  { "arraylength",  0 },         // Get length of array
  { "athrow",       CF_STOP },   // Throw exception or error
  { "checkcast",    CF_USE1 },   // Make sure object is of given type
  { "instanceof",   CF_USE1 },   // Determine if an object is of given type
  { "monitorenter", 0 },         // Enter monitored region of code
  { "monitorexit",  0 },         // Exit monitored region of code
  { "wide",         0 },         // WIDE PREFIX of Command
  { "multianewarray", CF_USE1|CF_USE2 }, // Allocate new multidimensional array
  { "ifnull",       CF_USE1 },   // Branch if nullptr-ptr
  { "ifnonnull",    CF_USE1 },   // Branch if not nullptr-ptr
  { "goto_w",       CF_USE1 },   // Branch always (wide index)
  { "jsr_w",        CF_USE1 },   // Jump subroutine (wide index)
  { "breakpoint",   0 },         // Stop and pass control to breakpoint handler
  //{ "ret_w",        CF_USE1 },   // Return from subroutine (wide index)
  // Pseudocode for quick
  { "invokesuper",         CF_USE1|CF_CALL },
  { "invokevirtualobject", CF_USE1|CF_USE2|CF_CALL },
  { "invokeignored",       CF_USE1 },
  // SUN-dependet
  { "software",     0 },
  { "hardware",     0 }

};

CASSERT(qnumber(Instructions) == j_last);
