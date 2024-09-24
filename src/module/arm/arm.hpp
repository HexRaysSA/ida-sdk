/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2002 by Ilfak Guilfanov, Datarescue.
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _ARM_HPP
#define _ARM_HPP

#include "../idaidp.hpp"
#include <idd.hpp>
#include <dbg.hpp>
#include <segregs.hpp>
#include <typeinf.hpp>
#include <fixup.hpp>
#include <regfinder.hpp>
#include <cvt64.hpp>
#include <allins.hpp>
struct arm_t;

#define PROCMOD_NAME            arm
#define PROCMOD_NODE_NAME       " $arm"

//------------------------------------------------------------------
struct fptr_info_t
{
  ea_t addr;   // address where the fp register is set
  ushort reg;  // frame pointer for current function (usually R11 or R7)
};

//---------------------------------
// ARM insn.auxpref bits
#define aux_cond        0x0001  // set condition codes (S postfix is required)
#define aux_byte        0x0002  // byte transfer (B postfix is required)
#define aux_npriv       0x0004  // non-privileged transfer (T postfix is required)
#define aux_regsh       0x0008  // shift count is held in a register (see o_shreg)
#define aux_negoff      0x0010  // memory offset is negated in LDR,STR
#define aux_immcarry    0x0010  // carry flag is set to bit 31 of the immediate operand (see may_set_carry)
#define aux_wback       0x0020  // write back (! postfix is required)
#define aux_wbackldm    0x0040  // write back for LDM/STM (! postfix is required)
#define aux_postidx     0x0080  // post-indexed mode in LDR,STR
#define aux_ltrans      0x0100  // long transfer in LDC/STC (L postfix is required)
#define aux_wimm        0x0200  // thumb32 wide encoding of immediate constant (MOVW)
#define aux_sb          0x0400  // signed byte (SB postfix)
#define aux_sh          0x0800  // signed halfword (SH postfix)
#define aux_sw          (aux_sb|aux_sh) // signed word (SW postfix)
#define aux_h           0x1000  // halfword (H postfix)
#define aux_x           (aux_h|aux_byte) // doubleword (X postfix in A64)
#define aux_d           aux_x   // dual (D postfix in A32/T32)
#define aux_p           0x2000  // priviledged (P postfix)
#define aux_coproc      0x4000  // coprocessor instruction
#define aux_wide        0x8000  // wide (32-bit) thumb instruction (.W suffix)
#define aux_pac        0x10000  // Pointer Authentication Code instruction (see PAC_ flags)
#define aux_ns         0x20000  // non-secure branch (NS suffix)
#define aux_thumb32    0x40000  // (aux_wide is sometimes turned off for pretty-printing)

// assembler flags
#define UAS_GNU         0x0001  // GNU assembler
#define UAS_LEGACY      0x0002  // Legacy (pre-UAL) assembler

//---------------------------------

#define it_mask         insnpref        // mask field of IT-insn
#define amxop           insnpref        // AMX operation number

// data type of NEON and vector VFP instructions (for the suffix)
enum neon_datatype_t ENUM_SIZE(char)
{
  DT_NONE = 0,
  DT_8,
  DT_16,
  DT_32,
  DT_64,
  DT_S8,
  DT_S16,
  DT_S32,
  DT_S64,
  DT_U8,
  DT_U16,
  DT_U32,
  DT_U64,
  DT_I8,
  DT_I16,
  DT_I32,
  DT_I64,
  DT_P8,
  DT_P16,
  DT_F16,
  DT_F32,
  DT_F64,
  DT_P32, // unused?
  DT_P64, // for 128-bit form of PMULL instruction
};

//-------------------------------------------------------------------------
// we will store the suffix in insnpref, since it's used only by the IT instruction
// if we need two suffixes (VCVTxx), we'll store the second one in Op1.specflag1
inline void set_neon_suffix(insn_t &insn, neon_datatype_t suf1, neon_datatype_t suf2 = DT_NONE)
{
  if ( suf1 != DT_NONE )
  {
    insn.insnpref = char(0x80 | suf1);
    if ( suf2 != DT_NONE )
      insn.Op1.specflag1 = suf2;
  }
}

//-------------------------------------------------------------------------
inline neon_datatype_t get_neon_suffix(const insn_t &insn)
{
  if ( insn.insnpref & 0x80 )
    return neon_datatype_t(insn.insnpref & 0x7F);
  else
    return DT_NONE;
}

//-------------------------------------------------------------------------
inline neon_datatype_t get_neon_suffix2(const insn_t &insn)
{
  return neon_datatype_t(insn.Op1.specflag1);
}

//----------------------------------------------------------------------
inline char dtype_from_dt(neon_datatype_t dt)
{
  switch ( dt )
  {
    case DT_8:
    case DT_S8:
    case DT_U8:
    case DT_I8:
    case DT_P8:
      return dt_byte;
    case DT_16:
    case DT_S16:
    case DT_U16:
    case DT_I16:
    case DT_P16:
      return dt_word;
    case DT_32:
    case DT_S32:
    case DT_U32:
    case DT_I32:
      return dt_dword;
    case DT_64:
    case DT_S64:
    case DT_U64:
    case DT_I64:
    case DT_NONE:
    default:
      return dt_qword;
    case DT_F16:
      return dt_half;
    case DT_F32:
      return dt_float;
    case DT_F64:
      return dt_double;
  }
}

#define PROC_MAXOP 5
CASSERT(PROC_MAXOP <= UA_MAXOP);

// Operand types:
#define o_shreg       o_idpspec0           // Shifted register
                                           //  op.reg    - register
#define shtype        specflag2            //  op.shtype - shift type
#define shreg(x)      uchar((x).specflag1) //  op.shreg  - shift register
#define shcnt         value                //  op.shcnt  - shift counter

#define ishtype       specflag2            // o_imm - shift type
#define ishcnt        specval              // o_imm - shift counter

#define secreg(x)     uchar((x).specflag1) // o_phrase: the second register is here
#define ralign        specflag3            // o_phrase, o_displ: NEON alignment (power-of-two bytes, i.e. 8*(1<<a))
                                           // minimal alignment is 16 (a==1)

#define simd_sz       specflag1            // o_reg: SIMD vector element size
                                           // 0=scalar, 1=8 bits, 2=16 bits, 3=32 bits, 4=64 bits, 5=128 bits)
                                           // number of lanes is derived from the vector size (dtype)
#define simd_idx      specflag3            // o_reg: SIMD scalar index plus 1 (Vn.H[i])

// o_phrase: the second register is held in secreg (specflag1)
//           the shift type is in shtype (specflag2)
//           the shift counter is in shcnt (value)

#define o_reglist     o_idpspec1           // Register list (for LDM/STM)
#define reglist       specval              // The list is in op.specval
#define uforce        specflag1            // PSR & force user bit (^ suffix)

#define o_creglist    o_idpspec2           // Coprocessor register list (for CDP)
#define CRd           reg                  //
#define CRn           specflag1            //
#define CRm           specflag2            //

#define o_creg        o_idpspec3           // Coprocessor register (for LDC/STC)
                                           // System register number (MSR/MRS)

#define o_fpreglist   o_idpspec4           // Floating point register list
#define fpregstart    reg                  // First register
#define fpregcnt      value                // number of registers; 0: single register (NEON scalar)
#define fpregstep     specflag2            // register spacing (0: {Dd, Dd+1,... }, 1: {Dd, Dd+2, ...} etc)
#define fpregindex    specflag3            // NEON scalar index plus 1 (Dd[x])
#define NOINDEX       (char)254            // no index - all lanes (Dd[])

#define o_text        o_idpspec5           // Arbitrary text stored in the operand
                                           // structure starting at the 'value' field
                                           // up to 16 bytes (with terminating zero)
#define o_cond        o_idpspec5+1         // ARM condition as an operand
                                           // condition is stored in 'value' field

// The processor number of coprocessor instructions is held in cmd.Op1.specflag1:
#define procnum       specflag1

// bits stored in specflag1 for APSR register
#define APSR_nzcv       0x01
#define APSR_q          0x02
#define APSR_g          0x04
// for SPSR/CPSR
#define CPSR_c          0x01
#define CPSR_x          0x02
#define CPSR_s          0x04
#define CPSR_f          0x08
// for banked registers (R8-R12, SP, LR/ELR, SPSR), this flag is set
#define BANKED_MODE     0x80 // the mode is in low 5 bits (arm_mode_t)

//------------------------------------------------------------------
// Shift types:
enum shift_t
{
  LSL,          // logical left         LSL #0 - don't shift
  LSR,          // logical right        LSR #0 means LSR #32
  ASR,          // arithmetic right     ASR #0 means ASR #32
  ROR,          // rotate right         ROR #0 means RRX
  RRX,          // extended rotate right

  // ARMv8 shifts
  MSL,          // masked shift left (ones are shifted in from the right)

  // extending register operations
  UXTB,
  UXTH,
  UXTW,
  UXTX,         // alias for LSL
  SXTB,
  SXTH,
  SXTW,
  SXTX,
};

//------------------------------------------------------------------
// Bit definitions. Just for convenience:
#define BIT0    0x00000001
#define BIT1    0x00000002
#define BIT2    0x00000004
#define BIT3    0x00000008
#define BIT4    0x00000010
#define BIT5    0x00000020
#define BIT6    0x00000040
#define BIT7    0x00000080
#define BIT8    0x00000100
#define BIT9    0x00000200
#define BIT10   0x00000400
#define BIT11   0x00000800
#define BIT12   0x00001000
#define BIT13   0x00002000
#define BIT14   0x00004000
#define BIT15   0x00008000
#define BIT16   0x00010000
#define BIT17   0x00020000
#define BIT18   0x00040000
#define BIT19   0x00080000
#define BIT20   0x00100000
#define BIT21   0x00200000
#define BIT22   0x00400000
#define BIT23   0x00800000
#define BIT24   0x01000000
#define BIT25   0x02000000
#define BIT26   0x04000000
#define BIT27   0x08000000
#define BIT28   0x10000000
#define BIT29   0x20000000
#define BIT30   0x40000000
#define BIT31   0x80000000

#define HEX__(n) 0x##n##LU

/* 8-bit conversion function */
#define B8__(x) ((x&0x0000000F)?1:0) \
               +((x&0x000000F0)?2:0) \
               +((x&0x00000F00)?4:0) \
               +((x&0x0000F000)?8:0) \
               +((x&0x000F0000)?16:0) \
               +((x&0x00F00000)?32:0) \
               +((x&0x0F000000)?64:0) \
               +((x&0xF0000000)?128:0)

// for upto 8-bit binary constants
#define B8(d) ((unsigned char)B8__(HEX__(d)))

// for upto 16-bit binary constants, MSB first
#define B16(dmsb,dlsb) (((uint16)B8(dmsb)<< 8) | (uint16)B8(dlsb))

// for upto 32-bit binary constants, MSB first
#define B32(dmsb,db2,db3,dlsb) (((uint32)B8(dmsb)<<24) \
                              | ((uint32)B8(db2 )<<16) \
                              | ((uint32)B8(db3 )<< 8) \
                              |  (uint32)B8(dlsb))

// extract bit numbers high..low from val (inclusive, start from 0)
#define BITS(val, high, low) ( ((val)>>low) & ( (1<<(high-low+1))-1) )

// extract one bit
#define BIT(val, bit) ( ((val)>>bit) & 1 )

// return if mask matches the value
// mask has 1s for important bits and 0s for don't-care bits
// match has actual values for important bits
// e.g. : xx0x0 means mask is 11010 and match is aa0a0
#define MATCH(value, mask, match) ( ((value) & (mask)) == (match) )

//------------------------------------------------------------------
// The condition code of instruction will be kept in cmd.segpref:

#define cond            segpref

//---------------------------------
// PAC (Pointer Authentication Code) instruction suffix flags are stored in insnpref
// NB: we have only 8 bits!
#define pac_flags  insnpref

// bits 0..2: key used
// The Pointer Authentication specification defines five keys. Four
// keys for PAC* and AUT* instructions (combination of instruction/data
// and A/B keys), and a fifth key for use with the general purpose PACGA
// instruction
#define PAC_KEYMASK    0x07
#define PAC_KEY_IA     0x00 // Instruction address, using key A
#define PAC_KEY_IB     0x01 // Instruction address, using key B
#define PAC_KEY_DA     0x02 // Data address, using key A
#define PAC_KEY_DB     0x03 // Data address, using key B
#define PAC_KEY_GA     0x04 // Generic key (PACGA)
#define PAC_KEY_RES5   0x05 // reserved for future
#define PAC_KEY_RES6   0x06 // reserved for future
// bits 3..4: address used
#define PAC_ADRMASK   (3<<3) // address is:
#define PAC_ADR_GPR   (0<<3) // in general-purpose register that is specified by <Xd>
#define PAC_ADR_X17   (1<<3) // in X17
#define PAC_ADR_X30   (2<<3) // in X30(XLR)
// bits 5..7: modifier used
#define PAC_MODMASK   (3<<5) // modifier is :
#define PAC_MOD_GPR   (0<<5) // in general-purpose register or stack pointer that is specified by <Xn|SP>
#define PAC_MOD_ZR    (1<<5) // zero
#define PAC_MOD_X16   (2<<5) // in X16
#define PAC_MOD_SP    (3<<5) // in SP

//----------------------------------------------------------------------
// build a suffix for a PAC instruction
static inline bool get_pac_suffix(qstring *suf, const insn_t &insn)
{
//
  int key = insn.pac_flags & PAC_KEYMASK;
  const char *id = nullptr, *ab = nullptr;
  switch ( key )
  {
    case PAC_KEY_IA: id= "I"; ab="A"; break;
    case PAC_KEY_IB: id= "I"; ab="B"; break;
    case PAC_KEY_DA: id= "D"; ab="A"; break;
    case PAC_KEY_DB: id= "D"; ab="B"; break;
    case PAC_KEY_GA: id= "G"; ab="A"; break;
    default: return false;
  }
  int adr = insn.pac_flags & PAC_ADRMASK;
  int mod = insn.pac_flags & PAC_MODMASK;
  bool pre_ab = adr == PAC_ADR_X30 || adr == PAC_ADR_X17;
  switch ( insn.itype )
  {
    case ARM_pac:
    case ARM_aut:
      suf->append(id);
      if ( pre_ab )
        suf->append(ab);

      if ( adr == PAC_ADR_X17 )
        suf->append("17");
      else if ( adr != PAC_ADR_X30 && adr != PAC_ADR_GPR )
        return false;

      if ( mod == PAC_MOD_SP )
        suf->append("SP");
      else if ( mod == PAC_MOD_ZR )
        suf->append("Z");
      else if ( mod == PAC_MOD_X16 )
        suf->append("16");
      else if ( mod != PAC_MOD_GPR )
        return false;
      if ( !pre_ab )
        suf->append(ab);
      break;
    case ARM_xpac:
      if ( adr == PAC_ADR_X30 )
        suf->append("LR");// XPACLRI
      else if ( adr != PAC_ADR_GPR )
        return 0;
      suf->append(id);  // XPACD, XPACI,
      break;
    default:
      // AA, AB, AAZ, ABZ
      suf->append("A");
      suf->append(ab);
      if ( mod == PAC_MOD_ZR )
        suf->append("Z");
      break;
  }
  return true;
}

//------------------------------------------------------------------
// is insn PACIASP or PACIBSP ?
static inline bool is_paci_sp(const insn_t &insn)
{
  if ( insn.itype != ARM_pac )
    return false;
  int adr = insn.pac_flags & PAC_ADRMASK;
  int mod = insn.pac_flags & PAC_MODMASK;
  int key = insn.pac_flags & PAC_KEYMASK;
  if ( adr != PAC_ADR_X30
    || mod != PAC_MOD_SP )
    return false;
  return key == PAC_KEY_IA || key == PAC_KEY_IB;
}


//------------------------------------------------------------------
enum RegNo
{
  R0, R1,  R2,  R3,  R4,  R5,  R6,  R7,
  R8, R9, R10, R11, R12, R13, R14, R15,
  CPSR, CPSR_flg,
  SPSR, SPSR_flg,
  T, rVcs, rVds,         // virtual registers for code and data segments
  Racc0,                 // Intel xScale coprocessor accumulator
  FPSID, FPSCR, FPEXC,   // VFP system registers
  FPINST, FPINST2, MVFR0, MVFR1,
  // msr system registers
  SYSM_APSR,
  SYSM_IAPSR,
  SYSM_EAPSR,
  SYSM_XPSR,
  SYSM_IPSR,
  SYSM_EPSR,
  SYSM_IEPSR,
  SYSM_MSP,
  SYSM_PSP,
  SYSM_PRIMASK,
  SYSM_BASEPRI,
  SYSM_BASEPRI_MAX,
  SYSM_FAULTMASK,
  SYSM_CONTROL,
  Q0,  Q1,   Q2,  Q3,  Q4,  Q5,  Q6,  Q7,
  Q8,  Q9,  Q10, Q11, Q12, Q13, Q14, Q15,
  D0,  D1,   D2,  D3,  D4,  D5,  D6,  D7,
  D8,  D9,  D10, D11, D12, D13, D14, D15,
  D16, D17, D18, D19, D20, D21, D22, D23,
  D24, D25, D26, D27, D28, D29, D30, D31,
  S0,  S1,   S2,  S3,  S4,  S5,  S6,  S7,
  S8,  S9,  S10, S11, S12, S13, S14, S15,
  S16, S17, S18, S19, S20, S21, S22, S23,
  S24, S25, S26, S27, S28, S29, S30, S31,
  FIRST_FPREG=Q0,
  LAST_FPREG=S31,
  CF, ZF, NF, VF,

  // AArch64 registers
  // general-purpose registers
  X0,  X1,  X2,   X3,  X4,  X5,  X6,  X7,
  X8,  X9,  X10, X11, X12, X13, X14, X15,
  X16, X17, X18, X19, X20, X21, X22, X23,
  X24, X25, X26, X27, X28,
  X29, XFP = X29, // frame pointer
  X30, XLR = X30, // link register

  XZR, // zero register (special case of GPR=31)

  XSP, // stack pointer (special case of GPR=31)

  XPC, // PC (not available as actual register)

  // 128-bit SIMD registers
  V0,  V1,  V2,   V3,  V4,  V5,  V6,  V7,
  V8,  V9,  V10, V11, V12, V13, V14, V15,
  V16, V17, V18, V19, V20, V21, V22, V23,
  V24, V25, V26, V27, V28, V29, V30, V31,

  ARM_MAXREG,            // must be the last entry
};

// we use specflag1 to store register values
// so they must fit into a byte
CASSERT(ARM_MAXREG < 0x100);

extern const char *const arm_regnames[];

//------------------------------------------------------------------
//      r0         *    argument word/integer result
//      r1-r3           argument word
//
//      r4-r8        S  register variable
//      r9           S  (rfp) register variable (real frame pointer)
//
//      r10        F S  (sl) stack limit (used by -mapcs-stack-check)
//      r11        F S  (fp) argument pointer
//      r12             (ip) temp workspace
//      r13        F S  (sp) lower end of current stack frame
//      r14             (lr) link address/workspace
//      r15        F    (pc) program counter
//
//      f0              floating point result
//      f1-f3           floating point scratch
//
//      f4-f7        S  floating point variable

#define PC      R15
#define LR      R14
#define SP      R13
#define FP      R11
#define FP2     R7  // in thumb mode

// is it simply [Rx, Ry]?
// no shift, no negation, no post-index, no writeback
inline bool is_simple_phrase(const insn_t &insn, const op_t &x)
{
  return x.type == o_phrase
      && x.shtype == LSL
      && x.shcnt == 0
      && (insn.auxpref & (aux_negoff|aux_postidx|aux_wback)) == 0;
}

inline bool issp(int reg) { return reg == SP || reg == XSP; }
inline bool issp(const op_t &x) { return x.type == o_reg && issp(x.reg); }

#define is_a64reg(reg) ((reg) >= X0 && (reg) < ARM_MAXREG)

inline bool is_gr(int reg)
{
  return reg >= R0 && reg <= R14
      || reg >= X0 && reg <= X30;
}

// map double or quad fp regs to single precision register intervals
// this function can return wrong register number for Q16-Q31, V8-V15
// so it should be used only for comparison
inline int map_arm32_fpreg(int reg, int *p_size)
{
  int size = 0;
  if ( reg >= S0 && reg <= S31 )
  {
    size = 1;
  }
  else if ( reg >= D0 && reg <= D31 )
  {
    reg = S0 + (reg-D0)*2;
    size = 2;
  }
  else if ( reg >= Q0 && reg <= Q15 )
  {
    reg = S0 + (reg-Q0)*4;
    size = 4;
  }
  *p_size = size;
  return reg;
}

// return TRUE if two contiguous groups of FP registers overlap
// (e.g. D0 overlaps with Q0, S0 and S1)
inline bool arm_compare_fpregs32(int r1, int cnt1, int r2, int cnt2)
{
  int size1 = 0;
  int size2 = 0;
  r1 = map_arm32_fpreg(r1, &size1);
  r2 = map_arm32_fpreg(r2, &size2);
  return interval::overlap(r1, size1*cnt1, r2, size2*cnt2);
}

inline bool is_thread_id_sysreg(const insn_t &insn, int op)
{
  // assert: insn.ops[op+0].type == o_imm
  //      && insn.ops[op+1].type == o_creg
  //      && insn.ops[op+2].type == o_creg
  //      && insn.ops[op+3].type == o_imm
  // TPIDR_EL0
  return insn.ops[op+0].value == 3
      && insn.ops[op+1].reg   == 13
      && insn.ops[op+2].reg   == 0
      && insn.ops[op+3].value == 2;
}

// is callee-saved (preserved) register? (according to Procedure Call Standard)
/* Procedure Call Standard for the ARM Architecture:
5.1.1. A subroutine must preserve the contents of the registers r4-r8,
r10, r11 and SP (and r9 in PCS variants that designate r9 as v6).
Procedure Call Standard for the ARM 64-bit Architecture:
5.1.1. A subroutine invocation must preserve the contents of the
registers r19-r29 and SP.
*/
inline bool is_callee_saved_gr(int reg)
{
  return reg >= R4  && reg <= R11
      || reg >= X19 && reg <= X29;
}
/* Procedure Call Standard for the ARM Architecture:
5.1.2.1 Registers s16-s31 (d8-d15, q4-q7) must be preserved across
subroutine calls; registers s0-s15 (d0-d7, q0-q3) do not need to be
preserved (and can be used for passing arguments or returning results in
standard procedure-call variants)
Procedure Call Standard for the ARM 64-bit Architecture:
5.1.2. Registers v8-v15 must be preserved by a callee across subroutine
calls.
*/
inline bool is_callee_saved_vr(int reg)
{
  return reg >= S16 && reg <= S31
      || reg >= D8  && reg <= D15
      || reg >= Q4  && reg <= Q7
      || reg >= V8  && reg <= V15;
}

//----------------------------------------------------------------------
// get full value of the immediate operand
// (performing optional shift operator)
inline uval_t get_immfull(const op_t &x)
{
  // FIXME support other types of shift
  return x.type != o_imm  ? 0
       : x.value == 0     ? 0
       : x.ishcnt == 0    ? x.value
       : x.ishtype == LSL ? x.value << x.ishcnt
       : x.ishtype == MSL ? ((x.value + 1) << x.ishcnt) - 1
       :                    0;
}

//----------------------------------------------------------------------
// check if 'reg' is present in 'reglist' (only ARM32 GPRs supported!)
inline bool in_reglist(uint32 reglist, int reg)
{
  return (reg <= R15) && (reglist & (1u << reg)) != 0;
}

//----------------------------------------------------------------------
// calculate the total number of bytes represented by a register list
inline uval_t calc_reglist_size(uint32 reglist)
{
  return uval_t(4) * bitcount(reglist & 0xFFFF);
}

//----------------------------------------------------------------------
// find out pre- or post-indexed addressing mode of given operand <op>;
// returns base register or -1
inline int get_pre_post_delta(const insn_t &insn, const op_t &op)
{
  if ( (insn.auxpref & (aux_wback | aux_postidx)) != 0
    && (op.type == o_displ && op.addr != 0 || op.type == o_phrase) )
  {
    return op.phrase;
  }
  return -1;
}

//------------------------------------------------------------------
// PSR format:
//      bit     name    description
//      0       M0      M4..M0 are mode bits:
//      1       M1              10000   User
//      2       M2              10001   FIQ (fast interrupt request)
//      3       M3              10010   IRQ (interrupt request)
//      4       M4              10011   Supervisor
//                              10110   Monitor (security extensions)
//                              10111   Abort
//                              11010   Hyp (Hypervisor; virtualization extensions)
//                              11011   Undefined
//                              11111   System
//      5       T       Thumb state
//      6       F       FIQ disable
//      7       I       IRQ disable
//      8       A       Asynchronous abort disable
//      9       E       Endianness (0=little endian, 1=big endian)
//      10      IT2     IT7...IT0 If-Then execution state bits (ITSTATE)
//      11      IT3
//      12      IT4
//      13      IT5
//      14      IT6
//      15      IT7
//      16      GE0     GE3..GE0  Greater than or Equal flags (for SIMD instructions)
//      17      GE1
//      18      GE2
//      19      GE3
//      24      J       Jazelle state
//      25      IT0
//      26      IT1
//      27      Q       Cumulative saturation flag
//      28      V       Overflow
//      29      C       Carry/Borrow/Extend
//      30      Z       Zero
//      31      N       Negative/Less Than

enum arm_mode_t
{
  M_usr = B8(10000),
  M_fiq = B8(10001),
  M_irq = B8(10010),
  M_svc = B8(10011),
  M_mon = B8(10110),
  M_abt = B8(10111),
  M_hyp = B8(11010),
  M_und = B8(11011),
  M_sys = B8(11111),
};

//------------------------------------------------------------------
// Vector summary:
//      Address Exception               Mode on Entry
//      ------- ---------               -------------
//      0000    Reset                   Supervisor
//      0004    Undefined instruction   Undefined
//      0008    Software interrupt      Supervisor
//      000C    Abort (prefetch)        Abort
//      0010    Abort (data)            Abort
//      0014    Hypervisor trap         Hyp
//      0018    IRQ                     IRQ
//      001C    FIQ                     FIQ

//------------------------------------------------------------------
// Condition codes:
enum cond_t
{
  cEQ,          // 0000 Z                        Equal
  cNE,          // 0001 !Z                       Not equal
  cCS,          // 0010 C                        Unsigned higher or same
  cCC,          // 0011 !C                       Unsigned lower
  cMI,          // 0100 N                        Negative
  cPL,          // 0101 !N                       Positive or Zero
  cVS,          // 0110 V                        Overflow
  cVC,          // 0111 !V                       No overflow
  cHI,          // 1000 C & !Z                   Unsigned higher
  cLS,          // 1001 !C | Z                   Unsigned lower or same
  cGE,          // 1010 (N & V) | (!N & !V)      Greater or equal
  cLT,          // 1011 (N & !V) | (!N & V)      Less than
  cGT,          // 1100 !Z & ((N & V)|(!N & !V)) Greater than
  cLE,          // 1101 Z | (N & !V) | (!N & V)  Less than or equal
  cAL,          // 1110 Always
  cNV,          // 1111 Never
  cLAST
};

// used by dmb and smb isnstructions
enum barrier_type
{
  BARRIER_SY    = 0xF,
  BARRIER_ST    = 0xE,
  BARRIER_LD    = 0xD,
  BARRIER_ISH   = 0xB,
  BARRIER_ISHST = 0xA,
  BARRIER_ISHLD = 0x9,
  BARRIER_NSH   = 0x7,
  BARRIER_NSHST = 0x6,
  BARRIER_NSHLD = 0x5,
  BARRIER_OSH   = 0x3,
  BARRIER_OSHST = 0x2,
  BARRIER_OSHLD = 0x1
};

inline cond_t get_cond(const insn_t &insn)
{
  return cond_t(insn.cond);
}
inline bool has_cond(const insn_t &insn)
{
  return insn.cond != cAL;
}
inline bool is_negated_cond(cond_t cond)
{
  return (cond & 1) != 0;
}
inline cond_t invert_cond(cond_t cond)
{
  if ( cond < cLAST )
    return cond_t(cond ^ 1);
  return cLAST;
}
inline cond_t get_op_cond(const op_t &x)
{
  // assert: x.type == o_cond
  return cond_t(x.value & 0xF);
}

//----------------------------------------------------------------------
// see ARMExpandImm_C/ThumbExpandImm_C in ARM ARM
inline bool may_set_carry(ushort itype)
{
  switch ( itype )
  {
    case ARM_and:
    case ARM_bic:
    case ARM_eor:
    case ARM_mov:
    case ARM_mvn:
    case ARM_orn:
    case ARM_orr:
    case ARM_teq:
    case ARM_tst:
      return true;
  }
  return false;
}

//----------------------------------------------------------------------
// if true, then ASPR.C is set to bit 31 of the immediate constant
inline bool imm_sets_carry(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case ARM_and:
    case ARM_bic:
    case ARM_eor:
    case ARM_mov:
    case ARM_mvn:
    case ARM_orn:
    case ARM_orr:
      // flags are updated if S suffix is used
      return (insn.auxpref & (aux_immcarry|aux_cond)) == (aux_immcarry|aux_cond);
    case ARM_teq:
    case ARM_tst:
      // these two always update flags
      return (insn.auxpref & aux_immcarry) != 0;
  }
  return false;
}


//----------------------------------------------------------------------
struct pushreg_t
{
  ea_t ea;              // instruction ea
  uval_t off;           // offset from the frame top (sp delta)
  uval_t width;         // size of allocated area in bytes
  int reg;              // register number (-1 means stack space allocation)
  DECLARE_COMPARISONS(pushreg_t);
};
typedef qvector<pushreg_t> pushregs_t;

struct pushinfo_t : public pushregs_t
{
  enum { PUSHINFO_VERSION = 2 };
  uint32 flags;
#define APSI_VARARG     0x01      // is vararg function?
#define APSI_FIRST_VARG_MASK 0x06 // index of the first register in push {rx..r3}
#define APSI_HAVE_SSIZE 0x08      // pushinfo_t structure contains its own size (field 'cb')
#define APSI_OFFSET_WO_DELTA 0x10 // do not use delta-coding for <off>
  inline int get_first_vararg_reg(void) { return (flags & APSI_FIRST_VARG_MASK) >> 1; }
  uval_t savedregs;     // size of the 'saved regs' area
  eavec_t prolog_insns; // additional prolog instruction addresses
                        // (in addition to instructions from pushregs_t)
  uval_t fpd;           // frame pointer delta

  int cb;               // size of this structure (it would be better if
                        // this field was the first one)

  // vararg info
  uval_t gr_top;        // offset from the frame top general registers
                        // vararg save area
  uval_t vr_top;        // offset from the frame top FP/SIMD registers
                        // vararg save area
  uval_t gr_width;      // size of general registers vararg save area
  uval_t vr_width;      // size of FP/SIMD registers vararg save area

  pushinfo_t(void)
    : flags(APSI_HAVE_SSIZE),
      savedregs(0), fpd(0),
      cb(sizeof(pushinfo_t)),
      gr_top(0), vr_top(0), gr_width(0), vr_width(0)
  {}
  DECLARE_COMPARISONS(pushinfo_t);

  void serialize(bytevec_t *packed, ea_t ea) const;
  bool deserialize(memory_deserializer_t *mmdsr, ea_t ea);

  void save_to_idb(arm_t &pm, ea_t ea) const;
  bool restore_from_idb(arm_t &pm, ea_t ea);

  void mark_prolog_insns(arm_t &pm);
};

//----------------------------------------------------------------------
enum arm_base_arch_t
{
  // values taken from ARM IHI 0045C, Tag_CPU_arch
  // https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst#3352the-target-related-attributes
  arch_ARM_old  = 0,    // Pre-v4
  arch_ARMv4    = 1,    // e.g. SA110
  arch_ARMv4T   = 2,    // e.g. ARM7TDMI
  arch_ARMv5T   = 3,    // e.g. ARM9TDMI
  arch_ARMv5TE  = 4,    // e.g. ARM946E-S
  arch_ARMv5TEJ = 5,    // e.g. ARM926EJ-S
  arch_ARMv6    = 6,    // e.g. ARM1136J-S
  arch_ARMv6KZ  = 7,    // e.g. ARM1176JZ-S
  arch_ARMv6T2  = 8,    // e.g. ARM1156T2F-S
  arch_ARMv6K   = 9,    // e.g. ARM1136J-S
  arch_ARMv7    = 10,   // e.g. Cortex A8, Cortex M3
  arch_ARMv6M   = 11,   // e.g. Cortex M1
  arch_ARMv6SM  = 12,   // v6-M with the System extensions
  arch_ARMv7EM  = 13,   // v7-M with DSP extensions
  arch_ARMv8    = 14,   // ARMv8-A
  arch_ARMv8R   = 15,   // Arm v8-R
  arch_ARMv8MB  = 16,   // Arm v8-M.baseline (ARMv6-M compatibility)
  arch_ARMv8M   = 17,   // Arm v8-M.mainline (ARMv7-M compatibility)
  arch_ARMv81A  = 18,   // Arm v8.1-A
  arch_ARMv82A  = 19,   // Arm v8.2-A
  arch_ARMv83A  = 20,   // Arm v8.3-A
  arch_ARMv81M  = 21,   // Arm v8.1-M.mainline
  arch_ARMv9    = 22,   // Arm v9-A
  arch_curr_max = arch_ARMv9,
  arch_ARM_meta = 9999, // decode everything
};

enum arm_arch_profile_t
{
  arch_profile_unkn = 0, // Architecture profile is not applicable (e.g. pre v7, or cross-profile code)
  arch_profile_A = 'A',  // The application profile (e.g. for Cortex A8)
  arch_profile_R = 'R',  // The real-time profile (e.g. for Cortex R4)
  arch_profile_M = 'M',  // The microcontroller profile (e.g. for Cortex M3)
  arch_profile_S = 'S',  // Application or real-time profile (i.e. the 'classic' programmer's model)
};

enum fp_arch_t
{
  fp_arch_none  = 0, // The user did not permit this entity to use instructions requiring FP hardware
  fp_arch_v1    = 1, // The user permitted use of instructions from v1 of the floating point (FP) ISA
  fp_arch_v2    = 2, // Use of the v2 FP ISA was permitted (implies use of the v1 FP ISA)
  fp_arch_v3    = 3, // Use of the v3 FP ISA was permitted (implies use of the v2 FP ISA)
  fp_arch_v3_16 = 4, // Use of the v3 FP ISA was permitted, but only citing registers D0-D15, S0-S31
  fp_arch_v4    = 5, // Use of the v4 FP ISA was permitted (implies use of the non-vector v3 FP ISA)
  fp_arch_v4_16 = 6, // Use of the v4 FP ISA was permitted, but only citing registers D0-D15, S0-S31
  fp_arch_v8    = 7, // Use of the ARM v8-A FP ISA was permitted
  fp_arch_v8_16 = 8, // Use of the ARM v8-A FP ISA was permitted, but only citing registers D0-D15, S0-S31
};

enum adv_simd_arch_t
{
  adv_simd_arch_none = 0, // The user did not permit this entity to use the Advanced SIMD Architecture (Neon)
  adv_simd_arch_base = 1, // Use of the Advanced SIMD Architecture (Neon) was permitted
  adv_simd_arch_fma  = 2, // Use of Advanced SIMD Architecture (Neon) with fused MAC operations was permitted
  adv_simd_arch_v8   = 3, // Use of the ARM v8-A Advanced SIMD Architecture (Neon) was permitted
};

struct arm_arch_t
{
  arm_base_arch_t base_arch;
  arm_arch_profile_t profile;
  fp_arch_t fp_arch;
  adv_simd_arch_t neon_arch;

  int arm_isa_use = 0;   // 0 = no ARM instructions (e.g. v7-M)
                         // 1 = allow ARM instructions
  int thumb_isa_use = 0; // 0 = no Thumb instructions
                         // 1 = 16-bit Thumb instructions + BL
                         // 2 = plus 32-bit Thumb instructions
  int xscale_arch = 0;   // 0 = no XScale extension
                         // 1 = XScale extension (MAR/MRA etc)
  int wmmx_arch = 0;     // 0 = no WMMX
                         // 1 = WMMX v1
                         // 2 = WMMX v2
  int hp_ext = 0;        // 0 = no half-precision extension
                         // 1 = VFPv3/Advanced SIMD optional half-precision extension
  int t2_ee = 0;         // 0 = no Thumb2-EE extension
                         // 1 = Thumb2-EE extension (ENTERX and LEAVEX)
  qstring arch_name;     // e.g. ARMv7-M
  qstring core_name;     // e.g. ARM1176JZF-S

  bool be8 = false;      // image is BE-8, i.e. little-endian code but big-endian data
  bool arm64_32 = false; // 32-bit address space, ARM64 instructions

  static const char *get_canonical_name(unsigned archno);
  bool set_from_name(const char *name); // arch name or core name
  bool set_options(const char *opts); // semicolon-delimited option string
  void save_to_idb(arm_t &pm) const;
  bool restore_from_idb(arm_t &pm);
  qstring to_string() const;
  arm_arch_t()
    : base_arch(arch_ARM_old),
      profile(arch_profile_unkn),
      fp_arch(fp_arch_none),
      neon_arch(adv_simd_arch_none)
  {}

  bool is_mprofile() const
  {
    if ( profile == arch_profile_unkn )
    {
      return base_arch >= arch_ARMv6M && base_arch <= arch_ARMv7EM;
    }
    return profile == arch_profile_M;
  }
};

//------------------------------------------------------------------
struct mmtype_t
{
  const char *name;
  const type_t *type;
  const type_t *fields;
  tinfo_t tif;
};

//------------------------------------------------------------------
void term_ana(void);
void move_it_blocks(ea_t from, ea_t to, asize_t size);
int get_it_size(const insn_t &insn);

uint64 expand_imm_vfp(uint8 imm8, int sz);
bool idaapi equal_ops(const op_t &x, const op_t &y);

int may_be_func(const insn_t &insn);
bool is_branch_insn(const insn_t &insn);
bool is_push_insn(const insn_t &insn, uint32 *reglist=nullptr);
bool is_pop_insn(const insn_t &insn, uint32 *reglist=nullptr, bool allow_ed=false);
bool is_like_tail_call(const insn_t &insn);
bool is_indirect_jump(const insn_t &insn);
int arm_create_switch_xrefs(ea_t insn_ea, const switch_info_t &si);
void mark_arm_codeseqs(void);
#if defined(NALT_HPP) && defined(_XREF_HPP)
int arm_calc_switch_cases(casevec_t *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si);
#endif

bool create_func_frame64(func_t *pfn, bool reanalyze);
int  arm_get_frame_retsize(const func_t *pfn);
bool get_insn_op_literal(const insn_t &insn, const op_t &x, ea_t ea, void *value, bool force=false);

void use_arm_arg_types(
        ea_t ea,
        func_type_data_t *fti,
        funcargvec_t *rargs);

//----------------------------------------------------------------------
typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

ea_t arm_calc_step_over(ea_t ip);
ea_t arm_get_macro_insn_head(ea_t ip);
int arm_get_dbr_opnum(const insn_t &insn);
ssize_t arm_get_reg_name(qstring *buf, int _reg, size_t width, int reghi);
ssize_t arm_get_one_reg_name(qstring *buf, int _reg, size_t width);
bool ana_neon(insn_t &insn, uint32 code, bool thumb);
void opimm_vfp(op_t &x, uint32 imm8, int sz);
void ana_hint(insn_t &insn, int hint);
int get_it_info(ea_t ea);
int arm_get_reg_index(const char *name, bool as_mainreg, bitrange_t *pbitrange, bool is_a64);

//======================================================================
// common inline functions used by analyzer
//----------------------------------------------------------------------
inline void oreglist(op_t &x, int regs)
{
  x.type = o_reglist;
  x.dtype = dt_dword;
  x.reglist = regs;
}

//----------------------------------------------------------------------
inline void onear(op_t &x, uval_t target, bool arm64=false)
{
  x.type = o_near;
  x.dtype = dt_code;
  x.addr = arm64 ? target : uint32(target);
}

//----------------------------------------------------------------------
inline void otext(op_t &x, const char *txt)
{
  x.type = o_text;
  qstrncpy((char *)&x.value, txt, sizeof(x) - qoffsetof(op_t, value));
}

//----------------------------------------------------------------------
// Get register number
inline uchar getreg(uint32 code, int lbit)
{
  return uchar((code >> lbit) & 0xF);
}

//----------------------------------------------------------------------
// Create operand of register type
inline void fillreg(op_t &x, uint32 code, int lbit)
{
  x.reg = getreg(code, lbit);
  x.type = o_reg;
  x.dtype = dt_dword;
}

//----------------------------------------------------------------------
inline void opreg(op_t &x, int rgnum)
{
  x.reg = uint16(rgnum);
  x.type = o_reg;
  x.dtype = dt_dword;
}

struct reg_mode_t
{
  uint16 reg;
  uchar mode;
};

//----------------------------------------------------------------------
// Create operand of banked_reg type
extern const reg_mode_t banked0[32];
extern const reg_mode_t banked1[32];
inline bool opbanked(op_t &x, int R, uchar sysm)
{
  const reg_mode_t &rm = R ? banked1[sysm] : banked0[sysm];
  if ( rm.reg == 0xFFFF )
    return false;
  x.reg = rm.reg;
  x.specflag1 = rm.mode | BANKED_MODE;
  x.type = o_reg;
  x.dtype = dt_dword;
  return true;
}

//----------------------------------------------------------------------
// Create operand of immediate type
inline void op_imm(op_t &x, uval_t value)
{
  x.type = o_imm;
  x.dtype = dt_dword;
  x.value = value;
  x.ishtype = LSL;
  x.ishcnt = 0;
}

//----------------------------------------------------------------------
// Create operand of immediate type (4 bits)
inline void op_imm4(op_t &x, uint32 code, int lbit)
{
  op_imm(x, getreg(code, lbit));
}

// is the current insn inside an it-block?
inline bool inside_itblock(int itcnd)
{
  return itcnd != -1;
}

//======================================================================
// common data sructures and functions for emulator
//----------------------------------------------------------------------

// since these is a lot of recursion in this module, we will keep
// all data as local as possible. no static data since we will have
// to save/restore it a lot

int calc_fpreglist_size(const insn_t &ins);
int calc_advsimdlist_size(const insn_t &ins);

// return true if 'x' is 'const' in LDR Rd, =const
inline bool is_ldr_literal(const insn_t &insn, const op_t &x)
{
  return x.type == o_mem
      && (insn.itype == ARM_ldr || insn.itype == ARM_ldrpc
       || insn.itype == ARM_ldur || insn.itype == ARM_ldxr
       || insn.itype == ARM_fldd || insn.itype == ARM_flds
       || insn.itype == ARM_vldr);
}

//----------------------------------------------------------------------
inline bool creglist_is_crd_cref(const insn_t &insn)
{
  return insn.itype == ARM_cdp || insn.itype == ARM_cdp2;
}
inline bool creglist_is_crn_cref(const insn_t &insn)
{
  return insn.itype != ARM_mcrr
      && insn.itype != ARM_mrrc
      && insn.itype != ARM_mcrr2
      && insn.itype != ARM_mrrc2;
}

//----------------------------------------------------------------------
// tuning parameters for reg_tracker_t
struct regtrack_info_t
{
  uint16 vals_size;       // max number of possible values returned by
                          // find_op_values, find_reg_values;
                          // 0 - no limit;
  uint16 op_recursion;    // max level of recursion when calculating
                          // operands of the emulated instruction, e.g.
                          //   LDR R0, =addr
                          //   LDR R0, [R0,#4]
                          //   ADD R0, #4
                          // needs 2 levels (one for addressing, one for
                          // addition);
                          // 0 - no limit;
  uint16 bblk_recursion;  // max level of recursion when reconstructing
                          // the execution flow;
                          // 0 - no limit;
  uint16 cache_size;      // max size of the cache for one register;
                          // 0 - no limit;
  uint16 max_xrefs;       // max number of xrefs to analyze
                          // 0 - no limit;
};

//----------------------------------------------------------------------
// Since we have to know if an instruction belongs to an IT-block or not,
// we keep all this information in a map
struct it_info_t
{
  uint8 size;
  uint8 cond;
  uint8 mask;
  it_info_t(void) : size(0), cond(0), mask(0) {}
  it_info_t(uval_t x) :
    size(x&0xFF),
    cond((x >> 8)&0xFF),
    mask((x >> 16)&0xFF)
  {
  }
  it_info_t(uint8 s, uint8 c, uint8 m) : size(s), cond(c), mask(m) {}
  operator uval_t(void) const { return size | (cond << 8) | (mask << 16); }
};
using it_blocks_t = std::map<ea_t, it_info_t>;    // first_it_block_ea -> info

//------------------------------------------------------------------
#define BL_FORCE_JUMP 0
#define BL_FORCE_CALL 1
bool idaapi arm_bl_force(ea_t ea, int option, bool hide_errors);

struct bl_force_flow_ah_t : public action_handler_t
{
  bool is_jump;
  bl_force_flow_ah_t(bool _is_jump) : is_jump(_is_jump) {}
  virtual int idaapi activate(action_activation_ctx_t *) override
  {
    return arm_bl_force(
            get_screen_ea(),
            is_jump ? BL_FORCE_JUMP : BL_FORCE_CALL,
            false);
  }

  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

//-------------------------------------------------------------------------
namespace O
{
  struct reg_tracker_t;
  struct rvi_vec_t;
  bool can_resolve_seg(ea_t ea);
  reg_tracker_t *alloc_reg_tracker(arm_t &pm);
  void free_reg_tracker(reg_tracker_t *rt);
}
struct opinfo_helpers_t;
struct cfh_t;
class calcrel_helper_t;

DECLARE_PROC_LISTENER(pm_idb_listener_t, struct arm_t);
DECLARE_LISTENER(pm_ui_listener_t, struct arm_t, arm);

//-------------------------------------------------------------------------
struct arm_reg_finder_t;
arm_reg_finder_t *alloc_reg_finder(const arm_t &pm);
void free_reg_finder(arm_reg_finder_t *rf);

#define PROCMOD_T arm_t
struct arm_t : public procmod_t
{
  arm_t();
  ~arm_t();

  pm_idb_listener_t idb_listener = pm_idb_listener_t(*this);
  pm_ui_listener_t ui_listener = pm_ui_listener_t(*this);
  struct eh_parse_t *eh_parse = nullptr;

  //----------------------------------------------------------------------
  netnode helper;           // altval(-1): idp flags
#define CALLEE_TAG   'A'    // altval(ea): callee address for indirect calls
#define DXREF_TAG    'd'    // altval(ea): resolved address for complex calculation (e.g. ADD R1, PC)
#define DELAY_TAG    'D'    // altval(ea) == DELAY_MARK: analyze ea for a possible offset
#define ITBLOCK_TAG  'I'    // altval(ea): packed it_info_t
#define FPTR_REG_TAG 'F'    // supval(ea): frame pointer info fptr_info_t
#define FIXED_STKPNT 'x'    // charval(ea): may not modify sp value at this address
#define PUSHINFO_TAG 's'    // blob(ea): packed pushinfo_t
#define ARCHINFO_TAG 'a'    // blob(0): packed arm_arch_t
#define LITERAL_EA   'L'    // charval(insn_ea):  =const operand number of load literal instruction
#define MAYBE_STKVAR 't'    // charval(ea) == opno+1: may create stkvar for the operand

#define DELAY_MARK 1 // possible offset marked for reanalysis
#define DELAY_DONE 2 // reanalysis completed, don't mark again to prevent endless loops

  void set_callee(ea_t ea, ea_t callee) { helper.easet(ea, callee, CALLEE_TAG); }
  ea_t get_callee(ea_t ea) { return helper.eaget(ea, CALLEE_TAG); }
  void del_callee(ea_t ea) { helper.eadel(ea, CALLEE_TAG); }

  void set_dxref(ea_t ea, ea_t dxref) { helper.easet(ea, dxref, DXREF_TAG); }
  ea_t get_dxref(ea_t ea) { return helper.eaget(ea, DXREF_TAG); }
  void del_dxref(ea_t ea) { helper.eadel(ea, DXREF_TAG); }

  // literal instruction
  void set_lit_opnum(ea_t insn_ea, uchar nop) { helper.charset_ea(insn_ea, nop, LITERAL_EA); }
  uchar get_lit_opnum(ea_t insn_ea) { return helper.charval_ea(insn_ea, LITERAL_EA); }
  void del_lit_opnum(ea_t insn_ea) { helper.chardel_ea(insn_ea, LITERAL_EA); }

  // fixed stkpnt
  void fix_stkpnt(ea_t ea) { helper.charset_ea(ea, 1, FIXED_STKPNT); }
  bool is_fixed_stkpnt(ea_t ea) const { return helper.charval_ea(ea, FIXED_STKPNT) != 0; }
  void del_stkpnt(ea_t ea) { helper.chardel_ea(ea, FIXED_STKPNT); }

  // possible stkvar
  void set_possible_stkvar(ea_t insn_ea, int nop) { helper.charset_ea(insn_ea, uchar(nop + 1), MAYBE_STKVAR); }
  int get_possible_stkvar(ea_t insn_ea) { return helper.charval_ea(insn_ea, MAYBE_STKVAR) - 1; }
  void del_possible_stkvar(ea_t insn_ea) { helper.chardel_ea(insn_ea, MAYBE_STKVAR); }

  //----------------------------------------------------------------------
#define IDP_SIMPLIFY       0x0001
#define IDP_NO_PTR_DEREF   0x0002
//                         0x0004 // reserved, see reg.cpp
#define IDP_ARM5           0x0008
#define IDP_NO_SETSGR      0x0010
#define IDP_NO_BL_JUMPS    0x0020
#define IDP_MOVT_MASK      0x0F00 // handling of MOV(W)/MOVT pairs
#define IDP_MOVT_SHIFT          8 // see MOVT_
// MOVT pair handling options
#define MOVT_NONE 0 // do nothing (old behavior)
#define MOVT_ADDR 1 // only convert if resulting value is valid address
#define MOVT_ALL  2 // convert all pairs regardless of the value

  // - simplify instructions and replace them by pseudo-instructions
  // - disable detection of BL instructions used for long jumps (not calls)
  //   in Thumb mode
  // - convert valid addresses
  ushort idpflags = IDP_SIMPLIFY
                  | IDP_ARM5
                  | IDP_NO_BL_JUMPS
                  | (MOVT_ADDR<<IDP_MOVT_SHIFT);

  inline bool simplify()    const { return (idpflags & IDP_SIMPLIFY) != 0; }
  inline bool deref_ptrs()  const { return (idpflags & IDP_NO_PTR_DEREF) == 0; }
  inline bool may_setsgr()  const { return (idpflags & IDP_NO_SETSGR) == 0; }
  inline bool no_bl_jumps() const { return (idpflags & IDP_NO_BL_JUMPS) != 0; }
  inline uint8 arm_movt_convert() const { return (idpflags & IDP_MOVT_MASK) >> 8; }

  bool convert_movw_movt(const insn_t &movt_insn, ea_t ea_movw) const;

  //----------------------------------------------------------------------
  arm_arch_t arch;
  arm_arch_t tarch;         // temporary (unsaved) arch info that's being changed by the user
  qstring default_arch;
  qstring arm_arch;

  inline bool has_arm()    const { return arch.arm_isa_use != 0; }
  inline bool has_thumb()  const { return arch.thumb_isa_use != 0; }
  inline bool has_thumb2() const { return arch.thumb_isa_use >= 2; }
  inline bool has_xscale() const { return arch.xscale_arch != 0; }
  inline bool has_vfp()    const { return arch.fp_arch != fp_arch_none; }
  inline bool has_neon()   const { return arch.neon_arch != adv_simd_arch_none; }
#ifndef ENABLE_LOWCNDS
  inline bool has_armv5()  const { return arch.base_arch >= arch_ARMv5T; }
  inline bool has_armv7a() const { return arch.base_arch == arch_ARMv7 || arch.base_arch > arch_ARMv7EM; }
  inline bool has_armv8()  const { return arch.base_arch >= arch_ARMv8; }
  inline bool is_mprofile() const { return arch.is_mprofile(); }
#endif
  inline bool is_be8() const { return arch.be8 != 0; }
  inline bool is_thumb_ea(ea_t ea) const
  {
    if ( !has_arm() )
      return true;
    sel_t t = get_sreg(ea, T);
    return t != BADSEL && t != 0;
  }

  // "In ARMv8-A, the mapping of instruction memory is always little-endian"
  inline uint32 get_insn32(ea_t ea) const
  {
    uint32 insn = get_dword(ea);
    if ( inf_is_be() && is_be8() )
      insn = swap32(insn);
    return insn;
  }
  inline uint16 get_insn16(ea_t ea) const
  {
    uint16 insn = get_word(ea);
    if ( inf_is_be() && is_be8() )
      insn = swap16(insn);
    return insn;
  }

  intvec_t custom_format_fids;
  bl_force_flow_ah_t bl_force_jump = bl_force_flow_ah_t(true);
  bl_force_flow_ah_t bl_force_call = bl_force_flow_ah_t(false);
  ea_t got_ea = BADADDR;    // .got start address
  int mnem_width = 0;
  bool file_loaded = 0;
  bool initing = false;
  bool warn_about_max_xrefs = true;
  bool recursing = false;

  it_blocks_t it_blocks;

  //----------------------------------------------------------------------
  // tuning parameters for reg_tracker_t (set from configuration file by
  // set_idp_options)
  regtrack_info_t regtrack_inf =
  {
    100,  // vals_size
    100,  // op_recursion
    2000, // bblk_recursion
    5000, // cache_size
    256,  // max_xrefs
  };
  O::reg_tracker_t *reg_tracker = nullptr;

  arm_reg_finder_t *reg_finder = nullptr;

  //----------------------------------------------------------------------
  // invalidate the cache of calculated register values from <ea> until the
  // next function;
  // if <ea> is BADADDR the clear the whole cache
  void o_invalidate_reg_cache(ea_t ea, int msgid);
  // clear all
  void o_term_reg_cache();
  // find all values loaded into register
  void find_reg_values(O::rvi_vec_t *ret, ea_t ea, int reg);

  //----------------------------------------------------------------------
  mmtype_t *mmtypes = nullptr;
  size_t mmtypes_cnt = 0;
  mmtype_t *mm_array_types = nullptr;
  size_t mm_array_types_cnt = 0;

  int get_arm_simd_types(
        simd_info_vec_t *outtypes,
        const simd_info_t *pattern,
        const argloc_t *argloc,
        bool do_create);
  void term_arm_simdtypes();
  void register_custom_formats(void);
  void unregister_custom_formats(void);

  //----------------------------------------------------------------------
  cfh_t *cfh = nullptr;
#ifdef __EA64__
  fixup_type_t cfh_pg21_id = 0;  // ids of fixup handlers
  fixup_type_t cfh_hi12_id = 0;
  fixup_type_t cfh_lo12_id = 0;
  fixup_type_t cfh_lo21_id = 0;
  fixup_type_t cfh_b14_id = 0;
  fixup_type_t cfh_b19_id = 0;
  fixup_type_t cfh_b26_id = 0;
  int ref_pg21_id = 0;                  // ids of refinfo handlers
  int ref_hi12_id = 0;
  int ref_lo12_id = 0;
  int ref_lo21_id = 0;

  bool emulate_ldr_str_add_operand(const insn_t &insn, const op_t &op) const;
#endif
  // ids of fixup handlers
  fixup_type_t cfh_prel31_id = 0;
  // ids of refinfo handlers
  int ref_prel31_id = 0;

  void init_custom_refs();
  void term_custom_refs();

  //----------------------------------------------------------------------
  // see the comment in arm_is_switch()
  bool checking_for_switch = false;

  //----------------------------------------------------------------------
  inline bool is_gas(void) const
  {
    return (ash.uflag & UAS_GNU) != 0;
  }
  inline bool is_ual(void) const
  {
    return (ash.uflag & UAS_LEGACY) == 0;
  }

  //----------------------------------------------------------------------
  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  void restore_arch();
  void load_from_idb();
  void arm_set_gotea(ea_t ea);
  static ea_t get_got_from_segment();
  void arm_get_abi_info(qstrvec_t *abi_names, qstrvec_t *abi_opts, comp_t);
  void arm_set_compiler(bool init_abibits);
  void header(outctx_t &ctx);
  void assumes(outctx_t &ctx);
  void segstart(outctx_t &ctx, segment_t *seg);
  void segend(outctx_t &ctx, segment_t *seg);
  void del_function_marks(const func_t *pfn);
  const char *get_regname(int rn);

  void init_ana(void);
  void term_ana(void);
  int ana64(insn_t &insn, calcrel_helper_t *crh);
  int ana_arm(insn_t &insn, calcrel_helper_t *crh=nullptr);
  int ana_thumb(insn_t &insn, calcrel_helper_t *crh=nullptr);
  bool ana_coproc(insn_t &insn, uint32 code);
  bool ana_vfp_insns(insn_t &insn, uint32 code);
  bool ana_neon(insn_t &insn, uint32 code, bool thumb);
  inline bool is_undef_vfp(uint32 code, bool thumb) const;
  inline bool supported_vfp_neon_insn(uint32 code) const;
  void check_displ(const insn_t &insn, op_t &x, bool alignPC=false) const;
  void addressing_mode(
        insn_t &insn,
        op_t &x,
        uint32 code,
        calcrel_helper_t *crh);
  bool op_sysm(op_t &x, int code1, int code2) const;
  bool thumb32(insn_t &insn, int code1, int code2, calcrel_helper_t *crh);
  int do_ana(insn_t &insn, calcrel_helper_t *crh);
  int ana(insn_t *out_ins);
  int get_it_info(ea_t ea, ea_t *it_insn_ea=nullptr);
  void move_it_blocks(ea_t from, ea_t to, asize_t size);
  bool build_movl_macro(insn_t *s, const insn_t &insn);
  bool build_adrl_macro(insn_t *s, const insn_t &insn);
  bool simplify_to_mov(insn_t *s);
  bool build_macro(insn_t &insn, bool may_go_forward);
  bool is_arm64(const insn_t &insn) const;
  bool is_arm64(void) const;
  bool is_arm64_ea(ea_t ea) const;
  bool check_for_t_changes(ea_t start, size_t size) const;
  int a64_branch(insn_t &insn, uint32 code, calcrel_helper_t *crh);
  int decode64(insn_t &insn, calcrel_helper_t *crh);

  int emu(const insn_t &insn);
  void add_it_block(const insn_t &insn);
  void del_it_block(ea_t ea);
  void del_insn_info(ea_t ea);
  bool copy_insn_optype(const insn_t &insn, const op_t &x, ea_t ea, bool force=false);
  inline void add_stkpnt(func_t *pfn, const insn_t &insn, sval_t v) const;
  void trace_sp(func_t *pfn, const insn_t &insn);
  bool verify_sp(func_t *pfn);
  bool recalc_spd_after_cond_jump(func_t *pfn, const insn_t &insn);
  inline void save_idpflags() { helper.altset(-1, idpflags); }
  void add_dxref(ea_t from, ea_t target);
  ea_t find_callee(const insn_t &insn, const op_t &x);
  void emulate_ldr_str_base_offset(
        const insn_t &insn,
        ea_t base,
        const O::rvi_vec_t &offs,
        char op_dtyp,
        bool swap_base_off);
  bool emulate_ldr_str_reg_based(const insn_t &insn, const op_t &op);
  bool emulate_ldr_str_with_displ(const insn_t &insn, const op_t &op);
  bool emulate_ldr_str(const insn_t &insn, const op_t &op);
  bool emulate_add_reg_based(const insn_t &insn, int reg1, int reg2);
  void arm_splitSRrange1(ea_t from, ea_t to, sel_t v, uchar tag) const;
  bool is_arm_call_insn(const insn_t &insn);
  bool range_uses_lr(ea_t ea1, ea_t ea2);
  bool is_bl_call(const insn_t &_insn, ea_t ea);
  bool is_bx_pc_nop(const insn_t &insn) const;
  void propagate_t_bit_to(const insn_t &insn, ea_t ea, bool use_low_bit) const;
  bool same_reg_value(
        ea_t ea,
        const op_t &op,
        int r1,
        const op_t *r1_moved,
        bool ignore_r1_changes = false);
  void set_arch_from_loader_arch_info();
  bool is_sp_alias(ea_t ea, int reg);
  int arm_calc_next_eas(eavec_t *res, const insn_t &insn, bool over);
  bool is_return_insn(const insn_t &insn, bool only_lr=false);
  bool recognize_many_branches(ea_t ea, insn_t *insn, bool t);
  bool try_code_start(ea_t ea, bool respect_low_bit);
  bool try_offset(ea_t ea);
  ea_t calc_next_exec_insn(
        const insn_t &ins,
        const regval_t *regvalues,
        const opinfo_helpers_t &oh,
        bool is_mprofile);

  //----------------------------------------------------------------------
  // Is register 'reg' spoiled by the current instruction?
  // If flag <use_pcs> is set then it is assumed that call instruction
  // doesn't spoil callee-saved registers (according to Procedure Call
  // Standard the are r4-r8, r10, r11, SP for AArch32, r19-r29, SP for
  // AArch64). If this flag is not set then this function assumes that
  // call instruction spoils LR and r0 (return value).
  bool spoils(const insn_t &insn, int reg, bool use_pcs = false);
  // If flag <use_pcs> is set then it is assumed that call instruction
  // doesn't spoil callee-saved registers else this function assumes that
  // call instruction spoils everything (why?).
  int  spoils(const insn_t &insn, const uint32 *regs, int n, bool use_pcs = false);
  // is PSR (Program Status Register) spoiled by the instruction ?
  static bool spoils_psr(const insn_t &insn);


  bool get_fptr_info(fptr_info_t *fpi, ea_t func_ea) const;
  ushort get_fptr_reg(ea_t func_ea) const
  {
    fptr_info_t fpi;
    return get_fptr_info(&fpi, func_ea) ? fpi.reg : ushort(-1);
  }
  ea_t get_fp_ea(ea_t func_ea) const
  {
    fptr_info_t fpi;
    return get_fptr_info(&fpi, func_ea) ? fpi.addr : BADADDR;
  }
  void set_fptr_info(ea_t func_ea, const fptr_info_t &fpi)
  {
    set_fptr_info(func_ea, fpi.reg, fpi.addr);
  }
  void set_fptr_info(ea_t func_ea, ushort reg, ea_t addr);

  bool is_sub_rn_fp(const func_t *pfn, const insn_t &insn) const;
  sval_t calc_sp_delta(
        func_t *pfn,
        const insn_t &insn,
        bool can_use_regfinder = true);
  bool arm_calc_spdelta(sval_t *spdelta, const insn_t &insn);
  bool isfp(const func_t *pfn, int reg) const;
  bool is_sp_based(const insn_t &insn, const op_t &x);
  sval_t special_func_spd(const insn_t &insn) const;
  static bool is_start_func_hint(const insn_t &_insn);
  void try_delay_offset(ea_t ea);
  int sp_based(const insn_t &insn, const op_t &x);
  bool uses(const insn_t &insn, int reg) const;
  bool arm_set_op_type(
        const insn_t &insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name,
        ea_t *golang_strlit_ea=nullptr);
  bool arm_set_op_type(
        const insn_t &insn,
        const op_t &x,
        const tinfo_t &tif,
        const char *name,
        eavec_t *visited,
        ea_t *golang_strlit_ea);
  bool is_str_to_stack(sval_t *stkoff, const insn_t &insn);
  bool create_golang_strlit(const insn_t &insn, ea_t strlit_ea);
  int use_arm_regarg_type(ea_t ea, const funcargvec_t &rargs);
  void use_arm_arg_types(ea_t ea, func_type_data_t *fti, funcargvec_t *rargs);
  bool is_glue_adr_insn(const insn_t &insn) const;
  flags64_t set_immd_bit(const insn_t &insn, int n, flags64_t F) const;
  bool good_target(ea_t from, uval_t pcval, bool possible_code = false);
  ea_t get_thumb_glue_target(ea_t ea) const;
  bool detect_thumb_arm_thunk(
        ea_t *target,
        size_t *thunk_len,
        const insn_t &insn);
  bool handle_thumb_arm_thunk(const insn_t &insn);
  int is_jump_func(func_t *pfn, ea_t *jump_target, ea_t *function_pointer);
  bool is_arm_sane_insn(const insn_t &insn, int asn_flags);
#define ASN_STRICT_CHECK  0x01 // forbid conditional non-branch insns
                               // should we also forbid SVN?
#define ASN_THUMB         0x02 // use thumb mode
#define ASN_CHECK_MODE    0x04 // check thumb/arm mode of the next insn
  bool try_decode(
        insn_t *insn,
        ea_t ea,
        bool is_thumb,
        int asn_flags = ASN_STRICT_CHECK);
  int arm_is_align_insn(ea_t ea) const;
  bool is_rt_switch8(switch_info_t *_si, const insn_t &insn);
  void convert_dcd(ea_t ea, ea_t callee_ip);
  bool lr_points_to_next_insn(const insn_t &insn, ea_t *value=nullptr);
  bool arm_get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        int tid,
        getreg_t *getreg,
        const regval_t *rv) const;
  ea_t arm_next_exec_insn(
        ea_t ea,
        int tid,
        getreg_t *getreg,
        const regval_t *regvalues);
  bool arm_update_call_stack(call_stack_t *stack, int tid, getreg_t *getreg, const regval_t *rv);
  bool get_call_addr(call_stack_info_t *si, ea_t pc, bool is_a64);
  void force_offset(
        ea_t ea,
        int n,
        ea_t base=0,
        reftype_t reftype=reftype_t(-1)) const;
  enum
  {
    MBF_DETECT_JUMP_FUNC = 0x01,
    MBF_THUMB            = 0x02, // decode insns as if the T bit is set
    MBF_ARM              = 0x04, // decode insns as if the T bit is not set
  };
  int may_be_func(
        const insn_t &insn,
        uint32 mbf_flags=MBF_DETECT_JUMP_FUNC);
  int may_be_func_recurse(
        const insn_t &insn,
        uint32 mbf_flags);
  bool skip_simple_insns_and_probe_for_push(
        const insn_t &insn,
        uint32 mbf_flags);
  bool decode_thumb_or_arm_insn(
        insn_t *insn,
        ea_t ea,
        uint32 mbf_flags);
  void get_reg_accesses(reg_accesses_t *accvec, const insn_t &insn) const;
  void test_get_reg_accesses() const;
  bool get_arm_callregs(callregs_t *callregs, cm_t cc);
  bool is_big_udt(cm_t cc, const tinfo_t &tif, bool as_retval);
  bool alloc_args(func_type_data_t *fti, int nfixed);
  bool calc_arm_arglocs(func_type_data_t *fti);
  bool calc_arm_varglocs(func_type_data_t *fti, regobjs_t *regargs, int nfixed);
  bool calc_arm_retloc(argloc_t *retloc, const tinfo_t &rettype, cm_t cc);
  bool adjust_arm_argloc(argloc_t *argloc, const tinfo_t *tif, int size);
  bool alloc_args64(func_type_data_t *fti, int nfixed);
  void arm_lower_func_arg_types(intvec_t *argnums, const func_type_data_t &fti);
  bool arm_get_reg_info(const char **main_name, bitrange_t *pbitrange, const char *name);
  bool create_func_frame32(func_t *pfn, bool reanalyze);
  bool create_func_frame64(func_t *pfn, bool reanalyze);
  bool create_func_frame(func_t *pfn, bool reanalyze = false);
  sval_t find_subsp_ofs(const insn_t &insn) const;
  sval_t check_fp_changes(int *finalreg, const insn_t &strt, int fpreg) const;
  bool adjust_frame_size(
        func_t *pfn,
        const insn_t &insn,
        int reg,
        sval_t spoff) const;
  int is_cfguard_reg(int *reg, ea_t ea, bool is_indirect) const;
  int is_cfguard_thunk(const insn_t &insn, int *p_reg);
  bool is_chkstk_darwin(ea_t ea) const;
  special_func_t get_spec_func_type(ea_t ea) const;

  void arm_move_segm(ea_t from, const segment_t *s, bool changed_netmap);
  void arm_erase_info(ea_t ea1, ea_t ea2);
  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded);
  void correct_code_sequences(void);
  bool is_be_proc() const;

  ushort basearch_to_field() const;
  ushort vfp_to_field() const;

  void arm_upgrade_fbase_to700();
  void arm_upgrade_fptr_to700();

  const char *cond2str(cond_t cond) const;
  void footer(outctx_t &ctx) const;
  bool outspec(outctx_t &ctx, uchar stype) const;
  void get_hint(qstring *out, int *important_lines, const char *name);
  void init_sys_regs() const;

  // regfinder.cpp
  void invalidate_reg_cache(ea_t to, ea_t from) const;
  void invalidate_reg_cache() const;
  void set_regfinder_debug(bool flag) const;
  bool find_regval(
        uval_t *value,
        ea_t ea,
        int reg,
        int max_depth = 0) const;
  bool find_opval(
        uval_t *value,
        const insn_t &insn,
        const op_t &op, // o_imm, o_reg, o_shreg, o_mem, o_displ, o_phrase
        int max_depth = 0) const;
  bool find_rvi(
        reg_value_info_t *rvi,
        ea_t ea,
        int reg,
        int max_depth = 0) const;
  bool find_rvi(
        reg_value_info_t *rvi,
        const insn_t &insn,
        const op_t &op, // o_imm, o_reg, o_shreg, o_mem, o_displ, o_phrase
        int max_depth = 0) const;
  bool find_sp_value(sval_t *spval, ea_t ea, int reg = -1) const;
  bool find_sp_value(
        sval_t *spval,
        func_t *pfn, // non-nullptr
        const insn_t &insn,
        const op_t &op) const;
  const op_t *make_canonical_op(
        op_t *op,
        const op_t &arm_op,
        const insn_t &insn,
        bool before) const;
  bool find_addr_rvi(
        reg_value_info_t *addr,
        const op_t &op, // o_mem, o_displ, o_phrase
        const insn_t &insn,
        bool before = true,
        int max_depth = 0) const;

#ifdef CVT64
  // convert ARM-related supvals/blobs to 64bit database
  int cvt64(
        qstring *errmsg,
        nodeidx_t node,
        uchar tag,
        nodeidx_t idx,
        const uchar *data,
        size_t datlen);
#endif
};
extern int data_id;

//----------------------------------------------------------------------
class reg_formatter_t
{
  const processor_t &ph;
  qstring outbuf;

  const char *regname(int rn) const;
  void format_with_suffix(int rn, int fields);

public:
  reg_formatter_t(const processor_t &_ph) : ph(_ph) {}
  void format_a64(int regnum, char dtype, int elsize = 0, int index = -1);
  void format_with_index(int rn, int index=-1);
  void format_any_reg(int rn, const op_t &x, bool ignore_suffix=false);
  op_dtype_t format_phreg(const op_t &x, int regidx);
  const qstring &get_regname() const { return outbuf; }
};

//----------------------------------------------------------------------
struct arm_saver_t
{
  arm_t &pm;
  insn_t insn; // current instruction
  bool flow;

  arm_saver_t(arm_t &_pm) : pm(_pm), insn(), flow(true) {}
  arm_saver_t(arm_t &_pm, const insn_t &insn_) : pm(_pm), insn(insn_), flow(true) {}

  void handle_operand(const op_t &x, bool isload);
  void emulate(void);
  void handle_indirect_jump(const op_t &x, bool is_call);
  void handle_code_ref(
        const op_t &x,
        ea_t ea,
        bool iscall,
        bool and_apply_type = true);
  bool decode_insn(ea_t ea);
  bool decode_next_insn();
  bool decode_and_detect_glue_code(
        ea_t ea,
        int flags,
#define DGC_HANDLE 0x0001  // create offsets and names
#define DGC_FIND   0x0002  // ea points to the end of the glue code
        ea_t *p_target = nullptr,
        ea_t *p_fptr = nullptr,
        size_t *p_glue_size = nullptr);
  bool detect_glue_code(
        int flags,
        ea_t *p_target = nullptr,
        ea_t *p_fptr = nullptr,
        size_t *p_glue_size = nullptr);
  bool arm_is_switch();
  bool check_for_switch(switch_info_t *si);
  // trace the switches between thumb and normal modes
  bool trace_thumb_arm_mode_switch() const;

  DEFINE_EA_HELPER_FUNCS(pm.eah());
};

//------------------------------------------------------------------
cfh_t *alloc_cfh();
void free_cfh(cfh_t *ptr);

#endif // _ARM_HPP
