/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-2024 Hex-Rays
 *      PDP11 module.
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
pdp_null = 0,           // Unknown Operation

pdp_halt,       // Stop CPU
pdp_wait,       // Wait interrupt
pdp_rti,        // Interrupt return
pdp_bpt,        // Trap to Debbuger
pdp_iot,        // Trap to 20 (i/o)
pdp_reset,      // Reset CPU and device
pdp_rtt,        // Interrupt return and ignore dbg-flag
pdp_mfpt,       // Load Processor Type          (* hi model)
pdp_jmp,        // Absolute jmp
pdp_rts,        // Return into subroutine
pdp_spl,        // Set Prior.
pdp_nop,        // Not operation
pdp_clc,        // Clear C bit in PSW
pdp_clv,        // Clear V bit in PSW
pdp_clz,        // Clear Z bit in PSW
pdp_cln,        // Clear N bit in PSW
pdp_ccc,        // Clear All Condition bits in PSW
pdp_sec,        // Set C bit in PSW
pdp_sev,        // Set V bit in PSW
pdp_sez,        // Set Z bit in PSW
pdp_sen,        // Set N bit in PSW
pdp_scc,        // Set All Condition bits bit in PSW
pdp_swab,       // Exchange byte in word
pdp_br,         // Relative jmp
pdp_bne,        // Jump if Z=0
pdp_beq,        // Jump if Z=1
pdp_bge,        // Jump if N^V=0
pdp_blt,        // Jump if N^V=1
pdp_bgt,        // Jump if Z|(N^V)=0
pdp_ble,        // Jump if Z|(N^V)=1
pdp_jsr,        // Call procedure
pdp_clr,        // Clear operand
pdp_com,        // Inverse operand
pdp_inc,        // Increment operand
pdp_dec,        // Decrement operand
pdp_neg,        // op = -op
pdp_adc,        // Add with Carry
pdp_sbc,        // Substract with Carry
pdp_tst,        // Test operand
pdp_ror,        // Cyclic shift rignt
pdp_rol,        // Cyclic shift left
pdp_asr,        // Arifmetic shift rignt
pdp_asl,        // Arifmetic shift left
pdp_mark,       // Return and empty stack
pdp_mfpi,       // Load from previous instruction space (*hi model)
pdp_mtpi,       // Store to previous instruction space  (*hi model)
pdp_sxt,        // N=>op
pdp_mov,        // Move operand
pdp_cmp,        // Compare operands
pdp_bit,        // Check Bit's
pdp_bic,        // Clear Bit's
pdp_bis,        // Set Bit's
pdp_add,        // Add operands
pdp_sub,        // Substract operands
pdp_mul,        // Multiple Reg          (*eis)
pdp_div,        // Divide Reg            (*eis)
pdp_ash,        // Multistep shift       (*eis)
pdp_ashc,       // Multistep shift 2 reg (*eis)
pdp_xor,        // Exclusive or          (*eis)
pdp_fadd,       // Floating Add         (*fis)
pdp_fsub,       // Floating Subtract    (*fis)
pdp_fmul,       // Floating Multiple    (*fis)
pdp_fdiv,       // Floating Divide      (*fis)
pdp_sob,        //
pdp_bpl,        // Jump if N=0
pdp_bmi,        // Jump if N=1
pdp_bhi,        // Jump if (!C)&(!Z)=0
pdp_blos,       // Jump if C|Z=1
pdp_bvc,        // Jump if V=0
pdp_bvs,        // Jump if V=1
pdp_bcc,        // Jump if C=0
pdp_bcs,        // Jump if C=1
pdp_emt,        // Trap to System
pdp_trap,       // Trap to user/compiler
pdp_mtps,       // Store PSW            (*lsi11 only)
pdp_mfpd,       // Load from previous data space (*hi model)
pdp_mtpd,       // Store to previous data space  (*hi model)
pdp_mfps,       // Load  PSW            (*lsi11 only)
    // FPU instruction
pdp_cfcc,       // Copy cond.codes into FPS to PSW
pdp_setf,       // Set Float
pdp_seti,       // Set Integer
pdp_setd,       // Set Double
pdp_setl,       // Set Long Integer
pdp_ldfps,      // Load FPS
pdp_stfps,      // Store FPS
pdp_stst,       // Load interrupt status
pdp_clrd,       // Clear
pdp_tstd,       // Test
pdp_absd,       // op = mod(op)
pdp_negd,       // op = -op
pdp_muld,       // Multiple
pdp_modd,       // Get int. part
pdp_addd,       // Add
pdp_ldd,        // Load in Acc
pdp_subd,       // Substract
pdp_cmpd,       // Compare
pdp_std,        // Store into Acc
pdp_divd,       // Divide
pdp_stexp,      // Store exponent
pdp_stcdi,      // Store and convert double/float to integer/long
pdp_stcdf,      // Store and convert double/float to float/double
pdp_ldexp,      // Load exponent
pdp_ldcif,      // Load and convert integer/long to double/float
pdp_ldcfd,      // Load and convert float/double to double/float
pdp_call,       // Jsr PC,
pdp_return,     // RTS PC
pdp_compcc,     // Complex Condition Codes

pdp_last

    };

#endif
