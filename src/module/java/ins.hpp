/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-2024 Hex-Rays
 *      JVM module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP


extern const instruc_t Instructions[];
enum nameNum ENUM_SIZE(uint16)
{
  j_nop = 0,        //   0 Do nothing
  j_aconst_null,    //   1 Push null object reference
  j_iconst_m1,      //   2 Push integer constant -1
  j_iconst_0,       //   3 Push the integer 0
  j_iconst_1,       //   4 Push the integer 1
  j_iconst_2,       //   5 Push the integer 2
  j_iconst_3,       //   6 Push the integer 3
  j_iconst_4,       //   7 Push the integer 4
  j_iconst_5,       //   8 Push the integer 5
  j_lconst_0,       //   9 Push the long integer 0
  j_lconst_1,       //  10 Push the long integer 1
  j_fconst_0,       //  11 Push the single-precision foating point 0.0
  j_fconst_1,       //  12 Push the single-precision foating point 1.0
  j_fconst_2,       //  13 Push the single-precision foating point 2.0
  j_dconst_0,       //  14 Push the double-precision foating point 2.0
  j_dconst_1,       //  15 Push the double-precision foating point 2.0
  j_bipush,         //  16 Push one byte signed integer
  j_sipush,         //  17 Push two-byte signed integer
  j_ldc,            //  18 Push item from constant pool (i1)
  j_ldcw,           //  19 Push item from constant pool (i2)
  j_ldc2w,          //  20 Push long or double from constant pool
  j_iload,          //  21 Push integer value of the local variable
  j_lload,          //  22 Push long value of the local variable
  j_fload,          //  23 Push single float value of the local variable
  j_dload,          //  24 Push double float value of the local variable
  j_aload,          //  25 Push object reference from the local variable
  j_iload_0,        //  26 Push integer value of the local variable #0
  j_iload_1,        //  27 Push integer value of the local variable #1
  j_iload_2,        //  28 Push integer value of the local variable #2
  j_iload_3,        //  29 Push integer value of the local variable #3
  j_lload_0,        //  30 Push long value of the local variable #0
  j_lload_1,        //  31 Push long value of the local variable #1
  j_lload_2,        //  32 Push long value of the local variable #2
  j_lload_3,        //  33 Push long value of the local variable #3
  j_fload_0,        //  34 Push single float value of the local variable #0
  j_fload_1,        //  35 Push single float value of the local variable #1
  j_fload_2,        //  36 Push single float value of the local variable #2
  j_fload_3,        //  37 Push single float value of the local variable #3
  j_dload_0,        //  38 Push double float value of the local variable #0
  j_dload_1,        //  39 Push double float value of the local variable #1
  j_dload_2,        //  40 Push double float value of the local variable #2
  j_dload_3,        //  41 Push double float value of the local variable #3
  j_aload_0,        //  42 Push object reference from the local variable #0
  j_aload_1,        //  43 Push object reference from the local variable #1
  j_aload_2,        //  44 Push object reference from the local variable #2
  j_aload_3,        //  45 Push object reference from the local variable #3
  j_iaload,         //  46 Push integer from array
  j_laload,         //  47 Push long from array
  j_faload,         //  48 Push single float from array
  j_daload,         //  49 Push double float from array
  j_aaload,         //  50 Push object refernce from array
  j_baload,         //  51 Push signed byte from array
  j_caload,         //  52 Push character from array
  j_saload,         //  53 Push short from array
  j_istore,         //  54 Pop integer value into local variable
  j_lstore,         //  55 Pop long value into local variable
  j_fstore,         //  56 Pop single float value into local variable
  j_dstore,         //  57 Pop double float value into local variable
  j_astore,         //  58 Pop object refernce into local variable
  j_istore_0,       //  59 Pop integer value into local variable #0
  j_istore_1,       //  60 Pop integer value into local variable #1
  j_istore_2,       //  61 Pop integer value into local variable #2
  j_istore_3,       //  62 Pop integer value into local variable #3
  j_lstore_0,       //  63 Pop long value into local variable #0
  j_lstore_1,       //  64 Pop long value into local variable #1
  j_lstore_2,       //  65 Pop long value into local variable #2
  j_lstore_3,       //  66 Pop long value into local variable #3
  j_fstore_0,       //  67 Pop single float value into local variable #0
  j_fstore_1,       //  68 Pop single float value into local variable #1
  j_fstore_2,       //  69 Pop single float value into local variable #2
  j_fstore_3,       //  70 Pop single float value into local variable #3
  j_dstore_0,       //  71 Pop double float value into local variable
  j_dstore_1,       //  72 Pop double float value into local variable #0
  j_dstore_2,       //  73 Pop double float value into local variable #1
  j_dstore_3,       //  74 Pop double float value into local variable #2
  j_astore_0,       //  75 Pop object refernce into local variable #0
  j_astore_1,       //  76 Pop object refernce into local variable #1
  j_astore_2,       //  77 Pop object refernce into local variable #2
  j_astore_3,       //  78 Pop object refernce into local variable #3
  j_iastore,        //  79 Pop integer from array
  j_lastore,        //  80 Pop long from array
  j_fastore,        //  81 Pop single float from array
  j_dastore,        //  82 Pop double float from array
  j_aastore,        //  83 Pop object refernce from array
  j_bastore,        //  84 Pop signed byte from array
  j_castore,        //  85 Pop character from array
  j_sastore,        //  86 Pop short from array
  j_pop,            //  87 Pop top stack word
  j_pop2,           //  88 Pop top two stack word
  j_dup,            //  89 Duplicate top stack word
  j_dup_x1,         //  90 Duplicate top stack word and put two down
  j_dup_x2,         //  91 Duplicate top stack word and put three down
  j_dup2,           //  92 Duplicate top two stack word
  j_dup2_x1,        //  93 Duplicate top two stack words and put two down
  j_dup2_x2,        //  94 Duplicate top two stack words and put three down
  j_swap,           //  95 Swap two top stack words
  j_iadd,           //  96 Integer add
  j_ladd,           //  97 Long add
  j_fadd,           //  98 Single float add
  j_dadd,           //  99 Double float add
  j_isub,           // 100 Integer subtract
  j_lsub,           // 101 Long subtract
  j_fsub,           // 102 Single float subtract
  j_dsub,           // 103 Double Float subtract
  j_imul,           // 104 Integer multiply
  j_lmul,           // 105 Long multiply
  j_fmul,           // 106 Single float multiply
  j_dmul,           // 107 Double Float multiply
  j_idiv,           // 108 Integer divide
  j_ldiv,           // 109 Long divide
  j_fdiv,           // 110 Single float divide
  j_ddiv,           // 111 Double Float divide
  j_irem,           // 112 Integer reminder
  j_lrem,           // 113 Long reminder
  j_frem,           // 114 Single float reminder
  j_drem,           // 115 Double Float reminder
  j_ineg,           // 116 Integer negate
  j_lneg,           // 117 Long negate
  j_fneg,           // 118 Single float negate
  j_dneg,           // 119 Double Float negate
  j_ishl,           // 120 Integer shift left
  j_lshl,           // 121 Long shift left
  j_ishr,           // 122 Integer logical shift right
  j_lshr,           // 123 Long logical shift right
  j_iushr,          // 124 Integer arithmetic shift right
  j_lushr,          // 125 Long arithmeticshift right
  j_iand,           // 126 Integer boolean AND
  j_land,           // 127 Long boolean AND
  j_ior,            // 128 Integer boolean OR
  j_lor,            // 129 Long boolean OR
  j_ixor,           // 130 Integer boolean XOR
  j_lxor,           // 131 Long boolean XOR
  j_iinc,           // 132 Add 8-bit signed const to local variable
  j_i2l,            // 133 Integer to Long conversion
  j_i2f,            // 134 Integer to single float conversion
  j_i2d,            // 135 Integer to double float conversion
  j_l2i,            // 136 Long to Integer conversion
  j_l2f,            // 137 Long to single float conversion
  j_l2d,            // 138 Long to double float conversion
  j_f2i,            // 139 Single float to Integer conversion
  j_f2l,            // 140 Single float to Long conversion
  j_f2d,            // 141 Single float to double float conversion
  j_d2i,            // 142 Double float to Integer conversion
  j_d2l,            // 143 Double float to Long conversion
  j_d2f,            // 144 Double float to double float conversion
  j_i2b,            // 145 Integer to signed byte conversion
  j_i2c,            // 146 Integer to unsigned short conversion
  j_i2s,            // 147 Integer to signed short conversion
  j_lcmp,           // 148 Long compare
  j_fcmpl,          // 149 Single float compare (-1 on NaN)
  j_fcmpg,          // 150 Single float compare (1 on NaN)
  j_dcmpl,          // 151 Double float compare (-1 on NaN)
  j_dcmpg,          // 152 Double float compare (1 on NaN)
  j_ifeq,           // 153 Branch if equal to 0
  j_ifne,           // 154 Branch if not equal to 0
  j_iflt,           // 155 Branch if less then 0
  j_ifge,           // 156 Branch if greater than or equal to 0
  j_ifgt,           // 157 Branch if greater than 0
  j_ifle,           // 158 Branch if less than or equal to 0
  j_if_icmpeq,      // 159 Branch if integers equal
  j_if_icmpne,      // 160 Branch if integers not equal
  j_if_icmplt,      // 161 Branch if integers less than
  j_if_icmpge,      // 162 Branch if integers grater than or equal to
  j_if_icmpgt,      // 163 Branch if integers grater than
  j_if_icmple,      // 164 Branch if integers less than or equal to
  j_if_acmpeq,      // 165 Branch if object references are equal
  j_if_acmpne,      // 166 Branch if object references not equal
  j_goto,           // 167 Branch always
  j_jsr,            // 168 Jump subroutine
  j_ret,            // 169 Return from subroutine
  j_tableswitch,    // 170 Access jump table by index and jump
  j_lookupswitch,   // 171 Access jump table by key match and jump
  j_ireturn,        // 172 Return integer from function
  j_lreturn,        // 173 Return long from function
  j_freturn,        // 174 Return single floatr from function
  j_dreturn,        // 175 Return double float from function
  j_areturn,        // 176 Return object reference from function
  j_return,         // 177 Return (void) from procedure
  j_getstatic,      // 178 Set static field from class
  j_putstatic,      // 179 Set static field in class
  j_getfield,       // 180 Fetch field from object
  j_putfield,       // 181 Set field in object
  j_invokevirtual,  // 182 invoke instance method
  j_invokespecial,  // 183 invoke instance method (superclass/init/...)
  j_invokestatic,   // 184 invoke a class (static) method
  j_invokeinterface,// 185 invoke interface method
  j_invokedynamic,  // 186 invoke instance method (select by paraneter)
  j_new,            // 187 Create new object
  j_newarray,       // 188 Allocate new array
  j_anewarray,      // 189 Allocate new array of refernces to object
  j_arraylength,    // 190 Get length of array
  j_athrow,         // 191 Throw exception or error
  j_checkcast,      // 192 Make sure object is of given type
  j_instanceof,     // 193 Determine if an object is of given type
  j_monitorenter,   // 194 Enter monitored region of code
  j_monitorexit,    // 195 Exit monitored region of code
  j_wide,           // 196 wide (prefix of command)
  j_multianewarray, // 197  Allocate new multi-dimensional array
  j_ifnull,         // 198 Branch if NULL-ptr
  j_ifnonnull,      // 199 Branch if not NULL-ptr
  j_goto_w,         // 200 Branch always (wide index)
  j_jsr_w,          // 201 Jump subroutine (wide index)
  j_breakpoint,     // 202 Stop and pass control to breakpoint handler
  //
  j_lastnorm,
  j_a_invokesuper = j_lastnorm,
  j_a_invokevirtualobject,
  j_a_invokeignored,
  // bottom of table ! (emu)
  j_a_software,
  j_a_hardware,
  //
  j_last
};

enum name_quick
{
  j_ldc_quick = j_lastnorm,    // 203     (18)
  j_ldcw_quick,                // 204     (19)
  j_ldc2w_quick,               // 205     (20)
  j_getfield_quick,            // 206     (180)
  j_putfield_quick,            // 207     (181)
  j_getfield2_quick,           // 208
  j_putfield2_quick,           // 209
  j_getstatic_quick,           // 210     (178)
  j_putstatic_quick,           // 211     (179)
  j_getstatic2_quick,          // 212
  j_putstatic2_quick,          // 213
  j_invokevirtual_quick,       // 214     (182)
  j_invokenonvirtual_quick,    // 215     (183)
  j_invokesuper_quick,         // 216
  j_invokestatic_quick,        // 217     (184)
  j_invokeinterface_quick,     // 218     (185)
  j_invokevirtualobject_quick, // 219
  j_invokeignored_quick,       // 220
  j_new_quick,                 // 221     (187)
  j_anewarray_quick,           // 222     (189)
  j_multianewarray_quick,      // 223     (197)
  j_checkcast_quick,           // 224     (192)
  j_instanceof_quick,          // 225     (193)
  j_invokevirtual_quick_w,     // 226
  j_getfield_quick_w,          // 227
  j_putfield_quick_w,          // 228
  j_quick_last
};

#define j_software   254
#define j_hardware   255
#endif
