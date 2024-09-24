/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Texas Instruments's TMS5320C55
 *
 */

//lint -e704 shift right of signed quantity
//lint -e1764 could be declared const

#include "tms320c55.hpp"
#include <segregs.hpp>

#define MAX_BYTE_USER_PARALLELIZED 0x5F
#define BYTE_MMAP                  0x98
#define BYTE_PORT1                 0x99
#define BYTE_PORT2                 0x9A
#define BYTE_LR                    0x9C
#define BYTE_CR                    0x9D

//--------------------------------------------------------------------------
// class to store a bytes cache
#define BYTES_SIZE 32 // maximum cache size (maximum number of bytes)
class bytes_c
{
public:
  bytes_c(insn_t &_insn) : insn(_insn), size(0), i(0)
  {
    memset(bytes, 0, sizeof(bytes));
  }
private:
  insn_t &insn;
  int bytes[BYTES_SIZE];
  int size;
  int i;
public:
  void reset(void) { i = 0; }
  int get_next(void);
  int get(int j) const { return bytes[j]; }
  void set_cache(bytevec_t &bytes);
};

//--------------------------------------------------------------------------
// get the next byte
int bytes_c::get_next(void)
{
  if ( i == size )
  {
    // if ( size >= CACHE_SIZE ) return nullptr;
    // load a new byte into the cache
    bytes[size] = get_byte(insn.ea+size);
    size++;
  }
  return bytes[i++];
}

//--------------------------------------------------------------------------
// set cache contents
void bytes_c::set_cache(bytevec_t &_bytes)
{
  int n = _bytes.size();
  n = qmin(n, qnumber(bytes));    //lint !e666 expression with side effects
  for ( size_t j=0; j < n; j++ )
    bytes[j] = _bytes[j];
  size = n;
  reset();
}

#define OP_MASK_N 15 // maximum nomber of op_mask_t for an instruction

struct mask_t;

// function to generate an operand
typedef void (*func_op_mask_t)(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &optional_op);

typedef struct
{
  func_op_mask_t func; // function to set operand
  int64 mask;            // mask of operand
} op_mask_t;

struct mask_t
{
  int64 code;     // full opcode of instruction
  int64 mask;     // full mask of instruction
  char size;      // number of bytes for instruction
  ushort itype;                         //lint !e958 padding is required to align members
  op_mask_t op_mask[OP_MASK_N];         //lint !e958 padding is required to align members
                        // function and mask to set operands
};

//--------------------------------------------------------------------------
// verify if a given byte match a byte (0 <= n <= mask_t.size-1) from a code and mask
static bool byte_match_code_mask(const mask_t *mask, int64 byte, char n, char lbytesize = 8)
{
  // compute nshift and nmask
  int nshift = (mask->size - 1 - n) * lbytesize;
  int64 nmask  = 0;
  for ( int i = 0; i < lbytesize; i++ )
    nmask = (nmask << 1) | 1;

  // shift code and mask to get current byte
  int64 mask_code = (mask->code >> nshift) & nmask;
  int64 mask_mask = (mask->mask >> nshift) & nmask;
  byte &= nmask;

  return (mask_code & mask_mask) == (byte & mask_mask);
}

//--------------------------------------------------------------------------
#define OP_BITS 30 // bits effectively reserved for masks (other bits are reserved for special operators)
#define OP_MASK (~(int64(0xFFFFFFFF) << OP_BITS)) // effective mask
#define OP_MASK_5 (~(make_uint64(0x3FFFFFF,   0) << (OP_BITS+8))) // effective mask
#define OP_MASK_6 (~(make_uint64(0x3FFFF,     0) << (OP_BITS+16))) // effective mask
#define OP_OP_NULL 0
#define OP_OP_IMM  1
#define OP_IMM(imm)  ((OP_OP_IMM << OP_BITS)|(imm))  // return offset = imm
#define OP_TRUE      OP_IMM(1)                       // return offset = 1
#define OP_OP_NOT  2
#define OP_NOT(mask) ((OP_OP_NOT << OP_BITS)|(mask)) // return (~offset) & 1
// return a masked operand or the result of a special operation
#define OP_IMM_5(imm)  (make_int64(0x00000000,   0x40)|(imm))  // return offset = imm
#define OP_IMM_6(imm)  (make_int64(0x00000000, 0x4000)|(imm))  // return offset = imm
#define OP_TRUE_5      OP_IMM_5(1)                       // return offset = 1
#define OP_TRUE_6      OP_IMM_6(1)                       // return offset = 1

static int64 get_masked_operand(int64 code, int64 mask)
{
  if ( mask == 0 )
    return 0;
  bool no = false;
  // special operations
  switch ( mask >> OP_BITS )
  {
    case OP_OP_NULL:
      break;
    case OP_OP_IMM:
      return mask & OP_MASK;
    case OP_OP_NOT:
      no = true;
      break;
    default:
      break;
  }
  code &= (mask & OP_MASK);
  while ( (mask & 1) == 0 )
  {
    code = code >> 1;
    mask = mask >> 1;
  }
  if ( no )
    code = (~code) & 1;
  return code;
}


//--------------------------------------------------------------------------
static int get_signed(int byte, int mask)
{
  int bits = mask >> 1;
  int sign = bits + 1;
  if ( byte & sign ) // offset < 0
    byte = ( byte & bits ) - sign;
  else // offset >= 0
    byte = byte & mask;
  return byte;
}

//--------------------------------------------------------------------------
inline int get_signed64(int64 byte, int mask)
{
  return get_signed((int)byte, mask);
}

//--------------------------------------------------------------------------
inline int get_unsigned(int byte, int mask)
{
  byte = byte & mask;
  return byte;
}

//--------------------------------------------------------------------------
static int64 get_masked_operand_5(int64 code, int64 mask)
{
  if ( mask == 0 )
    return 0;
  bool no = false;
  // special operations
  int Switch=mask >> (OP_BITS+8);
  switch ( Switch )
  {
    case OP_OP_NULL: break;
    case OP_OP_IMM:
      return mask & OP_MASK_5;
    case OP_OP_NOT:
      no = true;
      break;
    default:
      INTERR(10262);
  }
  code &= (mask & OP_MASK_5);
  while ( (mask & 1) == 0 )
  {
    code = code >> 1;
    mask = mask >> 1;
  }
  if ( no )
    code = (~code) & 1;
  return code;
}

//--------------------------------------------------------------------------
static int64 get_masked_operand_6(int64 code, int64 mask, bool /*bTest*/)
{
  if ( mask == 0 )
    return 0;
  bool no = false;
  // special operations
  int Switch = mask >> (OP_BITS+16);
  switch ( Switch )
  {
    case OP_OP_NULL: break;
    case OP_OP_IMM:
      return mask & OP_MASK_6;
    case OP_OP_NOT:
      no = true;
      break;
    default:
      INTERR(10263);
  }
  code &= mask & OP_MASK_6;
  while ( (mask & 1) == 0 )
  {
    code = code >> 1;
    mask = mask >> 1;
  }
  if ( no )
    code = (~code) & 1;
  return code;
}

//--------------------------------------------------------------------------
// process mask->op_mask[op_mask_n] on insn.ops[op_n] (if op.n not modified) and eventually modify op_n
bool tms320c55_t::process_masks_operand(
        insn_t &insn,
        const mask_t *mask,
        int64 code,
        int64 op_mask_n,
        unsigned *p_opnum,
        bool bTest)
{
  // initialize an operand to work on
  op_t work;
  unsigned opnum = *p_opnum;
  if ( opnum < UA_MAXOP )
    work = insn.ops[opnum];
  else
    work = insn.ops[UA_MAXOP-1];

  const op_mask_t *op_mask = &mask->op_mask[int(op_mask_n)];
  if ( op_mask->func == nullptr )
    return false;

  int64 opv = mask->size == 5 ? get_masked_operand_5(code, op_mask->mask)
            : mask->size == 6 ? get_masked_operand_6(code, op_mask->mask, bTest)
            :                   get_masked_operand(code, op_mask->mask);
  op_mask->func(mask, opv, &work, insn, optional_op);

  if ( work.type != o_void ) // if the operand was modified
  {
    if ( work.n == opnum ) // the function worked on the current operand
    {
      if ( opnum >= UA_MAXOP )
        return false; // error if not enough operands in insn
      insn.ops[opnum] = work; // save the new operand
      *p_opnum = ++opnum; // go to the next operand
    }
    else // the function modified the previous operand
    {
      if ( work.n >= UA_MAXOP )
        return false;
      insn.ops[work.n] = work; // save the new precedent operand (modified)
    }
  }
  return true;
}

//--------------------------------------------------------------------------
// get number of bytes for a given instruction opcode (left-aligned in dword)
static int get_insn_size(const mask_t *masks, uint32 opcode)
{
  const mask_t *p = masks;
  while ( p->mask != 0 )
  {
    if ( p->size <= 4 && (p->mask & (opcode>>(8*(4-p->size)))) == p->code )
      return p->size;
    p++;
  }
  return 0;
}

//--------------------------------------------------------------------------
// analyze code by processing all necessary masks
void tms320c55_t::process_masks(
        insn_t &insn,
        const mask_t *masks,
        ushort itype_null,
        bytes_c &bytes,
        char lbytesize)
{
  insn.itype = itype_null;
  insn.size  = 1;

  const mask_t *p = masks;
  while ( p->mask != 0 )
  {
    bytes.reset();
    ushort nbytes = 0;
    while ( nbytes < p->size
         && byte_match_code_mask(p, bytes.get_next(), (uchar &)nbytes, lbytesize) )
    {
      nbytes++;
    }
    if ( nbytes == p->size ) // if bytes matches all bytes from code and mask
    {
      int i;
      insn.itype = p->itype;
      insn.size  = nbytes;
      // compute full code
      int64 code = 0;
      for ( i = 0; i < nbytes; i++ )
        code = (code << lbytesize) | bytes.get(i);
      // process operands
      unsigned opnum = 0;
      for ( i = 0; i < OP_MASK_N; i++ )
      {
        bool bTest = p->size == 6 && i == 2;
        if ( !process_masks_operand(insn, p, code, i, &opnum, bTest) )
          break;
      }
      return;
    }
    p++;
  }
}

//--------------------------------------------------------------------------
// permit a mask_func_n to work on the last operand
static bool get_last_op(op_t *op, const insn_t &insn)
{
  int n;
  for ( n = 0; n < 6; n++ ) // find the first o_void operand
    if ( insn.ops[n].type == o_void )
      break;

  if ( n == 0 )
    return false; // no precedent operand
  *op = insn.ops[n-1]; // copy the precedent operand to the current position
  return true;
}

//--------------------------------------------------------------------------
// format instruction name
static void get_name_chars(
        char *buf,
        size_t bufsize,
        bool incl_chars,
        const char *name,
        const char *chars)
{
  char *bufend = qstpncpy(buf, name, bufsize);
  if ( incl_chars )
    qstrncpy(bufend, chars, bufsize - (bufend-buf));
}

//--------------------------------------------------------------------------
// instructions

// find instruction insn+"chars" with same operands:
//  parallel indicate an instructions on 2 lines
//  name1_chars indicate if we must have "chars" added to the first line
//  name2_chars indicate if we must have "chars" added to the second line
// instructions in instruc_t Instructions[] must be sorted as follow:
//  insn1 - insn2 - ... - insn"chars"1 - insn"chars"2 - ...
static bool find_insn_suffix(
        insn_t &insn,
        const char *chars,
        ushort itype_last,
        bool parallel,
        bool name1_chars,
        bool name2_chars)
{
  const char *insn_name1 = Instructions[insn.itype].name;
  char insn_name1_chars[MAXSTR];
  get_name_chars(insn_name1_chars, sizeof(insn_name1_chars), name1_chars, insn_name1, chars);

  const char *insn_name2 = nullptr;
  char insn_name2_chars[MAXSTR];
  insn_name2_chars[0] = '\0';
  if ( parallel )
  {
    insn_name2 = strchr(insn_name1, 0)+1;
    get_name_chars(insn_name2_chars, sizeof(insn_name2_chars), name2_chars, insn_name2, chars);
  }

  ushort i = insn.itype + 1;
  // jump over same instruction names (but eventually different number of params)
  while ( streq(Instructions[i].name, insn_name1)
       && (!parallel || streq(strchr(Instructions[i].name, 0)+1, insn_name2)) )   //-V575 potential null pointer
  {
    if ( ++i == itype_last )
      return false;
  }

  // loop until current instruction names are the same as what we are searching for (name or name+chars)
  while ( !streq(Instructions[i].name, insn_name1_chars)
       || (parallel && !streq(strchr(Instructions[i].name, 0)+1, insn_name2_chars)) )
  {
    if ( ++i == itype_last )
      return false;
  }

 // loop until current instruction has same params
  uint32 insn_feature = Instructions[insn.itype].feature;
  while ( Instructions[i].feature != insn_feature )
  {
    if ( ++i == itype_last )
      return false;
  }

  insn.itype = i;
  return true;
}

#define insn_chars(NAME, CHARS, PARALLEL, NAME1_CHARS, NAME2_CHARS)    \
  static void NAME(const mask_t *, int64 offset, op_t *, insn_t &insn, char &) \
  {                                                                    \
    if ( (offset & 1) != 0 )                                           \
    {                                                                  \
      bool ok = find_insn_suffix(insn, CHARS, TMS320C55_last, PARALLEL,\
                                 NAME1_CHARS, NAME2_CHARS);            \
      if ( !ok )                                                       \
        error("interr: ana: adjust_insn_suffix");                      \
    }                                                                  \
  }

insn_chars(insn_1_R_2_R, "r", true, true, true)    // insn_1_R_2_R   %
insn_chars(insn_1_40_2_40, "40", true, true, true) // insn_1_40_2_40 g
insn_chars(insn_1_2_R, "r", true, false, true)     // insn_1_2_R     %
insn_chars(insn_1_2_40, "40", true, false, true)   // insn_1_2_40    g
insn_chars(insn_1_R, "r", false, true, false)      // insn_1_R       %
insn_chars(insn_1_40, "40", false, true, false)    // insn_1_40      g
insn_chars(insn_1_R_2, "r", true, true, false)     // insn_1_R_2     %
insn_chars(insn_1_U, "u", false, true, false)      // insn_1_U       u
insn_chars(insn_1_P, "p", false, true, false)      // insn_1_P       swap()
insn_chars(insn_1_4, "4", false, true, false)      // insn_1_4       swap()

// set user parellel
static void insn_UP(const mask_t *, int64, op_t *, insn_t &insn, char &)
{
  insn.SpecialModes |= TMS_MODE_USER_PARALLEL;
}

// built-in parallelism
static void blt_prll(const mask_t *, int64, op_t *, insn_t &insn, char &)
{ // count the number of actual operands
  insn.Parallel = 0;
  for ( int i = 0; i < UA_MAXOP; i++ )
  {
    if ( insn.ops[i].type == o_void )
      break;
    insn.Parallel++;
  }
}

// simulated user parallelism
// static void usr_prll(const mask_t *mask, int64 offset, op_t *op)
// {
//   if ( offset & 1 )
//   {
//     blt_prll(mask, offset, op);
//     insn.SpecialModes |= TMS_MODE_SIMULATE_USER_PARALLEL;
//   }
// }
// ? actually not used, but will probably be used for non-documented opcodes
//   need also to add new instructions "ins1\nins2" in ins.hpp & ins.cpp

// immediates

#define op_imm(NAME, DTYP)                                                \
  static void op_##NAME(const mask_t *, int64 offset, op_t *op, insn_t &, char &) \
  {                                                                       \
    op->type  = o_imm;                                                    \
    op->value = (uval_t)offset;                                           \
    op->dtype = dt_##DTYP;                                                \
  }

op_imm(k8, byte)  // op_k8
op_imm(k16, word) // op_k16
#define op_k4 op_k8
#define op_k5 op_k8
#define op_k7 op_k8
#define op_k9 op_k16
#define op_k12 op_k16

//--------------------------------------------------------------------------
static void op_min_k4(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_imm;
  op->value = (uval_t)-offset;
  op->dtype = dt_byte;
  op->tms_signed = true;
}

//--------------------------------------------------------------------------
static void op_K8(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_imm;
  op->value = get_signed64(offset, 0xFF);
  op->dtype = dt_byte;
  op->tms_signed = true;
}

//--------------------------------------------------------------------------
static void op_K16(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_imm;
  op->value = get_signed64(offset, 0xFFFF);
  op->dtype = dt_word;
  op->tms_signed = true;
}

//--------------------------------------------------------------------------
/*
static void op_K23(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_imm;
  op->value = get_unsigned(offset, 0x7FFFFF);
  op->dtype  = dt_3byte;
}
*/

//--------------------------------------------------------------------------
static void op_1(const mask_t *, int64, op_t *op, insn_t &, char &)
{
  op->type  = o_imm;
  op->value = 1;
  op->dtype = dt_byte;
}

//--------------------------------------------------------------------------
static void op_min_1(const mask_t *, int64, op_t *op, insn_t &, char &)
{
  op->type  = o_imm;
  op->value = uval_t(-1);
  op->dtype = dt_byte;
  op->tms_signed = true;
}

//--------------------------------------------------------------------------
// registers

static void op_src(const mask_t *, int64 offset, op_t *op, insn_t &, char &optional_op) // FSSS, FDDD
{
  op->type  = o_reg;
  op->dtype = dt_word;
  op->reg   = AC0 + uint16(offset);
  optional_op = op->n;
}

#define op_dst op_src
#define op_ACw op_src
#define op_ACx op_src
#define op_ACy op_src
#define op_ACz op_src
#define op_TAx op_src // ARx or Tx
#define op_TAy op_src // ARy or Ty

// optional operand
static void opt_src(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // FSSS, FDDD
{
  if ( optional_op != -1
    && insn.ops[uchar(optional_op)].type == o_reg
    && insn.ops[uchar(optional_op)].reg == AC0 + offset )
  {
    return; // no operand if same than the source
  }
  // add the operand
  op_src(mask, offset, op, insn, optional_op);
  optional_op = -1;
  insn.itype++;
}

#define opt_dst opt_src
#define opt_ACy opt_src


#define op_reg(NAME, REG)                                                \
  static void op_##NAME(const mask_t *, int64 offset, op_t *op, insn_t &, char &)\
  {                                                                      \
    op->type  = o_reg;                                                   \
    op->dtype = dt_word;                                                 \
    op->reg   = REG + uint16(offset);                                    \
  }

op_reg(Tx, T0)     // op_Tx
op_reg(TCx, TC1)   // op_TCx
op_reg(TRNx, TRN0) // op_TRNx
#define op_TCy op_TCx
op_reg(ARx, AR0)   // op_ARx
op_reg(DPH, DPH)       // op_DPH
op_reg(PDP, PDP)       // op_PDP
op_reg(BK03, BK03)     // op_BK03
op_reg(BK47, BK47)     // op_BK47
op_reg(BKC, BKC)       // op_BKC
op_reg(CSR, CSR)       // op_CSR
op_reg(BRC0, BRC0)     // op_BRC0
op_reg(BRC1, BRC1)     // op_BRC1
op_reg(SP, SP)         // op_SP
op_reg(SSP, SSP)       // op_SSP
op_reg(CDP, CDP)       // op_CDP
op_reg(RPTC, RPTC)     // op_RPTC
op_reg(STx_55, ST0_55) // op_STx_55
op_reg(DP, DP)         // op_DP
op_reg(BSA01, BSA01)   // op_BSA01
op_reg(BSA23, BSA23)   // op_BSA23
op_reg(BSA45, BSA45)   // op_BSA45
op_reg(BSA67, BSA67)   // op_BSA67
op_reg(BSAC, BSAC)     // op_BSAC
op_reg(TRN0, TRN0)     // op_TRN0
op_reg(TRN1, TRN1)     // op_TRN1
op_reg(TC1, TC1)       // op_TC1
op_reg(TC2, TC2)       // op_TC2
op_reg(CARRY, CARRY)   // op_CARRY
op_reg(BORROW, BORROW) // op_BORROW
op_reg(RETA, RETA)     // op_RETA
op_reg(MDP05, MDP05)   // op_MDP05
op_reg(MDP67, MDP67)   // op_MDP67

//--------------------------------------------------------------------------
static void op_xsrc(const mask_t *, int64 offset, op_t *op, insn_t &, char &) // XSSS, XDDD
{ // AC0 AC1 AC2 AC3 XSP XSSP XDP XCDP XAR0 -> XAR7
  static const ushort regs[] =
  {
    AC0,  AC1,  AC2,  AC3,  XSP,  XSSP, XDP,  XCDP,
    XAR0, XAR1, XAR2, XAR3, XAR4, XAR5, XAR6, XAR7
  };
  op->type = o_reg;
  op->dtype = dt_dword;
  op->reg = regs[int(offset)];
}
#define op_xdst op_xsrc

//--------------------------------------------------------------------------
static void op_Xmem(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // XXXMMM, YYYMMM
{
  op_ARx(mask, offset >> 3, op, insn, optional_op);
  op->tms_modifier = TMS_MODIFIER_REG + (offset & 0x7);
}
#define op_Ymem op_Xmem

//--------------------------------------------------------------------------
static void op_Cmem(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // mm
{
  op_CDP(mask, 0, op, insn, optional_op);
  op->tms_modifier = TMS_MODIFIER_REG + (offset & 0x3);
}

//--------------------------------------------------------------------------
static void op_mem(
        const mask_t *mask,
        int64 offset,
        op_t *op,
        op_dtype_t dtype,
        insn_t &insn,
        char optional_op,
        bool ARn_mod = false) // AAAAAAAI
{
  insn.OpMem = 1 + op->n;
  if ( !(offset & 1) ) // @dma
  { // direct memory address
    sel_t cpl = get_sreg(insn.ea, CPL);
    if ( cpl == BADSEL )
      cpl = 0;
    if ( !cpl )
    { // use DP
      op->type         = o_mem;
      op->tms_regH     = DPH;
      op->tms_regP     = DP;
      op->addr         = ea_t(offset >> 1);
      op->tms_modifier = TMS_MODIFIER_DMA;
    }
    else
    { // use SP
      op->type  = o_reg;
      op->reg   = SP;
      op->value = ea_t(offset >> 1);
      op->tms_modifier = TMS_MODIFIER_REG_OFFSET;
    }
  }
  else
  { // indirect memory access
    if ( (offset & 0x1F) == 0x11 ) // xxx1 0001
    {
      int bits = int(offset >> 5);
      switch ( bits )
      {
        case 0: // *ABS16(#k16)
          op->type         = o_mem;
          op->tms_regH     = DPH;
          op->addr         = (get_byte(insn.ea+insn.size) << 8)
                           | get_byte(insn.ea+insn.size+1);
          op->tms_modifier = TMS_MODIFIER_ABS16;
          insn.size += 2;
          break;
        case 1: // *(#k23)
          op->type         = o_mem;
          op->addr         = (get_byte(insn.ea+insn.size) << 16)
                           | (get_byte(insn.ea+insn.size+1) << 8)
                           | get_byte(insn.ea+insn.size+2);
          op->tms_modifier = TMS_MODIFIER_PTR;
          insn.size += 3;
          break;
        case 2: // port(#k16)
          op->type         = o_io;
          op->addr         = (get_byte(insn.ea+insn.size) << 8)
                           | get_byte(insn.ea+insn.size+1);
          op->tms_modifier = TMS_MODIFIER_PORT;
          insn.size += 2;
          break;
        case 3: // *CDP
        case 4: // *CDP+
        case 5: // *CDP-
          op_CDP(mask, 0, op, insn, optional_op);
          op->tms_modifier= TMS_MODIFIER_REG + uchar(bits)-3;
          break;
        case 6: // *CDP(#K16)
        case 7: // *+CDP(#K16)
          op_CDP(mask, 0, op, insn, optional_op);
          op->value = get_signed((get_byte(insn.ea+insn.size) << 8)
                                | get_byte(insn.ea+insn.size+1), 0xFFFF);
          op->tms_modifier = TMS_MODIFIER_REG_OFFSET + uchar(bits)-6;
          insn.size += 2;
          break;
      }
    }
    else
    {
      op_ARx(mask, offset >> 5, op, insn, optional_op);
      int bits = (offset >> 1) & 0xF;
      if ( (offset & 0x11) == 0x01 ) // xxx0 xxx1
      {
        switch ( bits )
        {
          case 0: // *ARn
          case 1: // *ARn+
          case 2: // *ARn-
            op->tms_modifier= TMS_MODIFIER_REG + uchar(bits);
            break;
          case 3: // *(ARn+T0)
            op->tms_modifier= TMS_MODIFIER_REG_P_T0;
            break;
          case 4: // *(ARn-T0)
            op->tms_modifier= TMS_MODIFIER_REG_M_T0;
            break;
          case 5: // *ARn(T0)
            op->tms_modifier= TMS_MODIFIER_REG_T0;
            break;
          case 6: // *ARn(#K16)
          case 7: // *+ARn(#K16)
            op->value = get_signed((get_byte(insn.ea+insn.size) << 8)
                                  | get_byte(insn.ea+insn.size+1), 0xFFFF);
            op->tms_modifier = TMS_MODIFIER_REG_OFFSET + uchar(bits)-6;
            insn.size += 2;
            break;
        }
      }
      else // xxx1 xxx1
      {
        int lbits = (offset >> 1) & 0x7;
        sel_t arms = get_sreg(insn.ea, ARMS);
        if ( arms == BADSEL )
          arms = 0;
        if ( ARn_mod || !arms )
        {
          switch ( lbits )
          {
            case 1: // *(ARn+T1)
              op->tms_modifier= TMS_MODIFIER_REG_P_T1;
              break;
            case 2: // *(ARn-T1)
              op->tms_modifier= TMS_MODIFIER_REG_M_T1;
              break;
            case 3: // *ARn(T1)
            case 4: // *+ARn
            case 5: // *-ARn
            case 6: // *(ARn+T0B)
            case 7: // *(ARn-T0B)
              op->tms_modifier= TMS_MODIFIER_REG_T1 + uchar(lbits)-3;
              break;
          }
        }
        else
        { // *ARn(short(#value))
          op->value = lbits;
          op->tms_modifier = TMS_MODIFIER_REG_SHORT_OFFSET;
        }
      }
    }
  }
  op->dtype = dtype;
}

//--------------------------------------------------------------------------
static void op_Smem(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // AAAAAAAI //-V669 'optional_op' argument is a non-constant reference
{
  op_mem(mask, offset, op, dt_word, insn, optional_op);
}

//--------------------------------------------------------------------------
static void op_Lmem(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // AAAAAAAI //-V669 'optional_op' argument is a non-constant reference
{
  op_mem(mask, offset, op, dt_dword, insn, optional_op);
}

//--------------------------------------------------------------------------
static void op_ARn_mod(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // AAAAAAAI //-V669 'optional_op' argument is a non-constant reference
{
  op_mem(mask, offset, op, dt_word, insn, optional_op, true);
}

//--------------------------------------------------------------------------
// @dma = bit number
static void op_Baddr(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // AAAAAAAI //-V669 'optional_op' argument is a non-constant reference
{
  if ( !(offset & 1) ) // @dma
  {
    op->type  = o_imm;
    op->value = ea_t(offset >> 1);
    op->dtype = dt_byte;
    op->tms_prefix = '@';
    op->tms_signed = false;
  }
  else
  {
    op_mem(mask, offset, op, dt_byte, insn, optional_op);
  }
}

//lint -emacro(572,fn_operator) excessive shift value
#define fn_operator(NAME, OPERATOR)                                           \
  static void fn_##NAME(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &) \
  {                                                                           \
    if ( offset & 1 )                                                         \
    {                                                                         \
      get_last_op(op, insn);                                                  \
      op->tms_operator1 |= TMS_OPERATOR_##OPERATOR & 0xFF;                    \
      /*lint -e572 Excessive shift value*/                                    \
      op->tms_operator2 |= (TMS_OPERATOR_##OPERATOR >> 8);                    \
    }                                                                         \
  }

fn_operator(not, NOT)   // fn_not
fn_operator(T3, T3)     // fn_T3 U
fn_operator(uns, UNS)   // fn_uns u
fn_operator(rnd, RND)   // fn_rnd %
fn_operator(hb, HB)     // fn_hb
fn_operator(lb, LB)     // fn_lb
fn_operator(hi, HI)     // fn_hi
fn_operator(lo, LO)     // fn_lo
fn_operator(sat, SAT)   // fn_sat = fn_uns
fn_operator(dbl, DBL)   // fn_dbl
fn_operator(pair, PAIR) // fn_pair
fn_operator(dual, DUAL) // fn_dual

//--------------------------------------------------------------------------
static void op_BitIn(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_reg;
  op->dtype = dt_byte;
  op->reg   = (offset & 1) ? TC2 : CARRY;
}
#define op_BitOut op_BitIn

//--------------------------------------------------------------------------
static void op_swap(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op)
{
  insn.Op1.type  = o_reg;
  insn.Op1.dtype = dt_word;
  insn.Op2.type  = o_reg;
  insn.Op2.dtype = dt_word;
  switch ( offset )
  {
    case 0x00: insn.Op1.reg = AC0; insn.Op2.reg = AC2; break;
    case 0x01: insn.Op1.reg = AC1; insn.Op2.reg = AC3; break;
    case 0x04: insn.Op1.reg = T0;  insn.Op2.reg = T2;  break;
    case 0x05: insn.Op1.reg = T1;  insn.Op2.reg = T3;  break;
    case 0x08: insn.Op1.reg = AR0; insn.Op2.reg = AR2; break;
    case 0x09: insn.Op1.reg = AR1; insn.Op2.reg = AR3; break;
    case 0x0C: insn.Op1.reg = AR4; insn.Op2.reg = T0;  break;
    case 0x0D: insn.Op1.reg = AR5; insn.Op2.reg = T1;  break;
    case 0x0E: insn.Op1.reg = AR6; insn.Op2.reg = T2;  break;
    case 0x0F: insn.Op1.reg = AR7; insn.Op2.reg = T3;  break;
    case 0x10: insn_1_P(mask, 1, op, insn, optional_op); insn.Op1.reg = AC0; insn.Op2.reg = AC2; break;
    case 0x14: insn_1_P(mask, 1, op, insn, optional_op); insn.Op1.reg = T0;  insn.Op2.reg = T2;  break;
    case 0x18: insn_1_P(mask, 1, op, insn, optional_op); insn.Op1.reg = AR0; insn.Op2.reg = AR2; break;
    case 0x1C: insn_1_P(mask, 1, op, insn, optional_op); insn.Op1.reg = AR4; insn.Op2.reg = T0;  break;
    case 0x1E: insn_1_P(mask, 1, op, insn, optional_op); insn.Op1.reg = AR6; insn.Op2.reg = T2;  break;
    case 0x2C: insn_1_4(mask, 1, op, insn, optional_op); insn.Op1.reg = AR4; insn.Op2.reg = T0;  break;
    case 0x38: insn.Op1.reg = AR0; insn.Op2.reg = AR1; break;
    default:   insn.itype = TMS320C55_null;
  }
}

//--------------------------------------------------------------------------
// get address for the branch offset base
// in case of parallel execution, this is the end of the second, parallel instruction
static ea_t get_next_ip(insn_t &insn)
{
  ea_t next = insn.ip + insn.size;
  if ( insn.size <= 3 )
  {
    uchar nextbyte = get_byte(insn.ea + insn.size);
    if ( nextbyte <= MAX_BYTE_USER_PARALLELIZED && (nextbyte & 1) )
    {
      // next instruction is executed in parallel, so take it into account
      insn_t tmp;
      next += decode_insn(&tmp, insn.ea + insn.size);
    }
  }
  return next;
}

//--------------------------------------------------------------------------
// code addresses

static void op_l4(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &) // llll
{
  op->type  = o_near;
  op->addr  = (get_next_ip(insn) + offset) & 0xFFFFFF;
  op->dtype = dt_code;
}

static void op_L7(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &) // LLLLLLL
{
  op->type  = o_near;
  op->addr  = (get_next_ip(insn) + get_signed64(offset, 0x7F)) & 0xFFFFFF;
  op->dtype = dt_code;
}

static void op_L8(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &) // LLLLLLLL
{
  op->type  = o_near;
  op->addr  = (get_next_ip(insn) + get_signed64(offset, 0xFF)) & 0xFFFFFF;
  op->dtype = dt_code;
}

static void op_L16(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &) // LLLLLLLL LLLLLLLL
{
  op->type  = o_near;
  op->addr  = (get_next_ip(insn) + get_signed64(offset, 0xFFFF)) & 0xFFFFFF;
  op->dtype = dt_code;
}

static void op_pmad(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &)
{
  op->type  = o_near;
  op->addr  = (get_next_ip(insn) + offset) & 0xFFFFFF;
  op->dtype = dt_code;
}

static void op_P24(const mask_t *, int64, op_t *op, insn_t &insn, char &) // get_byte included
{
  op->type  = o_near;
  op->addr  = (get_byte(insn.ea+insn.size+0) << 16)
            | (get_byte(insn.ea+insn.size+1) << 8)
            |  get_byte(insn.ea+insn.size+2);
  op->dtype = dt_code;
  insn.size += 3;
}

// data addresses

static void op_D16(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_mem;
  op->addr  = ea_t(offset);
  op->dtype = dt_word;
}

// various

static void op_SHIFTW(const mask_t *, int64 offset, op_t *op, insn_t &, char &)
{
  op->type  = o_shift;
  op->value = (signed short)get_signed64(offset, 0x3F);
}

//--------------------------------------------------------------------------
// shift left
static void shl_SHIFTW(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_SHIFTL_IMM;
  op->tms_shift_value = (signed short)get_signed64(offset, 0x3F);
  if ( short(op->tms_shift_value) < 0 )
  {
    op->tms_shift       = TMS_OP_SHIFTR_IMM;
    op->tms_shift_value = -op->tms_shift_value;   //lint !e2501 negation of value of unsigned type
  }
}

//--------------------------------------------------------------------------
// shift left out of brackets
static void slo_SHIFTW(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op)
{
  shl_SHIFTW(mask, offset, op, insn, optional_op);
  op->tms_shift |= TMS_OP_SHIFT_OUT;
}

//--------------------------------------------------------------------------
// shift right
static void shl_SHFT(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_SHIFTL_IMM;
  op->tms_shift_value = (uint16)offset;
}

//--------------------------------------------------------------------------
static void shl_Tx(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_SHIFTL_REG;
  op->tms_shift_value = T0 + uint16(offset);
}

//--------------------------------------------------------------------------
static void shl_T2(const mask_t *, int64, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_SHIFTL_REG;
  op->tms_shift_value = T2;
}

//--------------------------------------------------------------------------
static void shl_16(const mask_t *, int64, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_SHIFTL_IMM;
  op->tms_shift_value = 16;
}

//--------------------------------------------------------------------------
static void shr(const mask_t *, int64 imm, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_SHIFTR_IMM;
  op->tms_shift_value = uint16(imm);
}

//--------------------------------------------------------------------------
static void eq_K16(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_EQ;
  op->tms_shift_value = (uint16)get_signed64(offset, 0xFFFF);
}

//--------------------------------------------------------------------------
static void neq_0(const mask_t *, int64, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_shift       = TMS_OP_NEQ;
  op->tms_shift_value = 0;
}

//--------------------------------------------------------------------------
static void RELOP(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &) // cc
{
  get_last_op(op, insn);
  op->type      = o_relop;
  op->tms_relop = offset & 0x3;
}

//--------------------------------------------------------------------------
static void RELOP_dst(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op)
{
  get_last_op(op, insn);
  op->tms_relop_type = TMS_RELOP_REG;
  ushort sav = op->reg;
  op_src(mask, offset, op, insn, optional_op);
  op->type  = o_relop;
  op->value = op->reg;
  op->reg   = sav;
}

//--------------------------------------------------------------------------
static void RELOP_K8(const mask_t *, int64 offset, op_t *op, insn_t &insn, char &)
{
  get_last_op(op, insn);
  op->tms_relop_type = TMS_RELOP_IMM;
  op->value = (signed short)get_signed64(offset, 0xFF);
}

//--------------------------------------------------------------------------
static void op_cond(const mask_t *mask, int64 offset, op_t *op, insn_t &insn, char &optional_op) // CCC CCCC
{
  op->reg = 0;
  if ( (offset>>4) <= 0x5 ) // <= 101 xxxx
  { // src <comparison operator> 0
    op_src(mask, offset & 0xF, op, insn, optional_op);
    op->type  = o_cond;
    op->value = offset & 0x70;
  }
  else if ( (offset>>2) == 0x18 ) // == 110 00xx
  { // overflow(ACx)
    op_src(mask, offset & 0x3, op, insn, optional_op);
    op->type  = o_cond;
    op->value = offset & 0x7C;
  }
  else if ( (offset>>2) == 0x19 ) // == 110 01xx
  { // TC1, TC2, CARRY, reserved
    if ( offset == 0x67 ) // 110 0111
      insn.itype = TMS320C55_null; // reserved
    else
    {
      op->type  = o_cond;
      op->value = (uval_t)offset;
    }
  }
  else if ( (offset>>2) == 0x1A ) // == 110 10xx
  { // TC1 & TC2, TC1 & !TC2, !TC1 & TC2, !TC1 & !TC2
    op->type  = o_cond;
    op->value = (uval_t)offset;
  }
  else if ( (offset>>2) == 0x1B ) // == 110 11xx
  {
    insn.itype = TMS320C55_null; // reserved
  }
  else if ( (offset>>2) == 0x1C ) // == 111 00xx
  { // !overflow(ACx)
    op_src(mask, offset & 0x3, op, insn, optional_op);
    op->type  = o_cond;
    op->value = offset & 0x7C;
  }
  else
  {
    if ( offset == 0x77 ) // 111 0111
      insn.itype = TMS320C55_null; // reserved
    else
    {
      op->type  = o_cond;
      op->value = (uval_t)offset;
    }
  }
}

//--------------------------------------------------------------------------
//lint -e648 overflow in computing constant for operator '<<': signed shift result (0x80000000) sets the sign bit of the shift expression's type ('int') and becomes negative expanded from macro 'OP_NOT'
static const mask_t masks[] =
{
  // 0000000E XDDDX000 error manual
  { 0x000000,   0xFE0000,   3, TMS320C55_rptcc,     {{ op_k8,       0x0000FF         }, { op_cond,       0x007F00   }}},
  { 0x020000,   0xFE0000,   3, TMS320C55_retcc,     {{ op_cond,     0x007F00         }}},
  { 0x040000,   0xFE0000,   3, TMS320C55_bcc,       {{ op_L8,       0x0000FF         }, { op_cond,       0x007F00   }}},
  { 0x060000,   0xFE0000,   3, TMS320C55_b,         {{ op_L16,      0x00FFFF         }}},
  { 0x080000,   0xFE0000,   3, TMS320C55_call,      {{ op_L16,      0x00FFFF         }}},
  // 0000101E GGGGGGGG Glllllll error manual
  { 0x0C0000,   0xFE0000,   3, TMS320C55_rpt,       {{ op_k16,      0x00FFFF         }}},
  { 0x0E0000,   0xFE0000,   3, TMS320C55_rptb,      {{ op_pmad,     0x00FFFF         }}},
  { 0x100000,   0xFE0F00,   3, TMS320C55_and1,      {{ op_ACx,      0x003000         }, { shl_SHIFTW,    0x00003F   }, { opt_ACy,    0x00C000         }}},
  { 0x100100,   0xFE0F00,   3, TMS320C55_or1,       {{ op_ACx,      0x003000         }, { shl_SHIFTW,    0x00003F   }, { opt_ACy,    0x00C000         }}},
  { 0x100200,   0xFE0F00,   3, TMS320C55_xor1,      {{ op_ACx,      0x003000         }, { shl_SHIFTW,    0x00003F   }, { opt_ACy,    0x00C000         }}},
  { 0x100300,   0xFE0F00,   3, TMS320C55_add2,      {{ op_ACx,      0x003000         }, { shl_SHIFTW,    0x00003F   }, { op_ACy,     0x00C000         }}},
  { 0x100400,   0xFE0F00,   3, TMS320C55_sub2,      {{ op_ACx,      0x003000         }, { shl_SHIFTW,    0x00003F   }, { op_ACy,     0x00C000         }}},
  { 0x100500,   0xFE0F00,   3, TMS320C55_sfts2,     {{ op_ACx,      0x003000         }, { op_SHIFTW,     0x00003F   }, { opt_ACy,    0x00C000         }}},
  { 0x100600,   0xFE0F00,   3, TMS320C55_sftsc2,    {{ op_ACx,      0x003000         }, { op_SHIFTW,     0x00003F   }, { opt_ACy,    0x00C000         }}}, // SFTA
  { 0x100700,   0xFE0F00,   3, TMS320C55_sftl2,     {{ op_ACx,      0x003000         }, { op_SHIFTW,     0x00003F   }, { opt_ACy,    0x00C000         }}},
  { 0x100800,   0xFE0F00,   3, TMS320C55_exp,       {{ op_ACx,      0x003000         }, { op_Tx,         0x000030   }}},
  { 0x100900,   0xFE0F00,   3, TMS320C55_mant_nexp, {{ op_ACx,      0x003000         }, { op_ACy,        0x00C000   }, { blt_prll,   0                }, { op_ACx,    0x003000   }, { op_Tx,      0x000030   }}},
  { 0x100A00,   0xFE0F00,   3, TMS320C55_bcnt,      {{ op_ACx,      0x003000         }, { op_ACy,        0x0000C0   }, { op_TCx,     0x000001         }, { op_Tx,     0x000030   }}},
  { 0x100C00,   0xFE0F00,   3, TMS320C55_maxdiff,   {{ op_ACx,      0x003000         }, { op_ACy,        0x0000C0   }, { op_ACz,     0x00C000         }, { op_ACw,    0x000030   }}},
  { 0x100D00,   0xFE0F00,   3, TMS320C55_dmaxdiff,  {{ op_ACx,      0x003000         }, { op_ACy,        0x0000C0   }, { op_ACz,     0x00C000         }, { op_ACw,    0x000030   }, { op_TRNx,    0x000001   }}},
  { 0x100E00,   0xFE0F00,   3, TMS320C55_mindiff,   {{ op_ACx,      0x003000         }, { op_ACy,        0x0000C0   }, { op_ACz,     0x00C000         }, { op_ACw,    0x000030   }}},
  { 0x100F00,   0xFE0F00,   3, TMS320C55_dmindiff,  {{ op_ACx,      0x003000         }, { op_ACy,        0x0000C0   }, { op_ACz,     0x00C000         }, { op_ACw,    0x000030   }, { op_TRNx,    0x000001   }}},
  { 0x120000,   0xFE0300,   3, TMS320C55_cmp,       {{ insn_1_U,     0x000004         }, { op_src,        0x00F000   }, { RELOP,      0x000C00         }, { RELOP_dst, 0x0000F0   }, { op_TCx,     0x000001   }}},
  { 0x120100,   0xFE0308,   3, TMS320C55_cmpand,    {{ insn_1_U,     0x000004         }, { op_src,        0x00F000   }, { RELOP,      0x000C00         }, { RELOP_dst, 0x0000F0   }, { op_TCy,     0x000002   }, { op_TCx,    0x000001   }}},
  { 0x120108,   0xFE0308,   3, TMS320C55_cmpand,    {{ insn_1_U,     0x000004         }, { op_src,        0x00F000   }, { RELOP,      0x000C00         }, { RELOP_dst, 0x0000F0   }, { op_TCy,     0x000002   }, { fn_not,    OP_TRUE    }, { op_TCx,    0x000001   }}},
  { 0x120200,   0xFE0308,   3, TMS320C55_cmpor,     {{ insn_1_U,     OP_NOT(0x000004) }, { op_src,        0x00F000   }, { RELOP,      0x000C00         }, { RELOP_dst, 0x0000F0   }, { op_TCy,     0x000002   }, { op_TCx,    0x000001   }}},
  { 0x120208,   0xFE0308,   3, TMS320C55_cmpor,     {{ insn_1_U,     OP_NOT(0x000004) }, { op_src,        0x00F000   }, { RELOP,      0x000C00         }, { RELOP_dst, 0x0000F0   }, { op_TCy,     0x000002   }, { fn_not,    OP_TRUE    }, { op_TCx,    0x000001   }}},
  { 0x120300,   0xFE0308,   3, TMS320C55_rol,       {{ op_BitOut,   0x000001         }, { op_src,        0x00F000   }, { op_BitIn,   0x000002         }, { op_dst,    0x0000F0   }}},
  { 0x120308,   0xFE0308,   3, TMS320C55_ror,       {{ op_BitIn,    0x000002         }, { op_src,        0x00F000   }, { op_BitOut,  0x000001         }, { op_dst,    0x0000F0   }}},
  { 0x140000,   0xFE000F,   3, TMS320C55_aadd,      {{ op_TAx,      0x00F000         }, { op_TAy,        0x0000F0   }}},
  { 0x140001,   0xFE000F,   3, TMS320C55_amov,      {{ op_TAx,      0x00F000         }, { op_TAy,        0x0000F0   }}},
  { 0x140002,   0xFE000F,   3, TMS320C55_asub,      {{ op_TAx,      0x00F000         }, { op_TAy,        0x0000F0   }}},
  { 0x140004,   0xFE000F,   3, TMS320C55_aadd,      {{ op_k8,       0x00FF00         }, { op_TAx,        0x0000F0   }}},
  { 0x140005,   0xFE000F,   3, TMS320C55_amov,      {{ op_k8,       0x00FF00         }, { op_TAx,        0x0000F0   }}},
  { 0x140006,   0xFE000F,   3, TMS320C55_asub,      {{ op_k8,       0x00FF00         }, { op_TAx,        0x0000F0   }}},
  { 0x140008,   0xFE000F,   3, TMS320C55_aadd,      {{ op_TAx,      0x00F000         }, { op_TAy,        0x0000F0   }}},
  { 0x140009,   0xFE000F,   3, TMS320C55_amov,      {{ op_TAx,      0x00F000         }, { op_TAy,        0x0000F0   }}},
  { 0x14000A,   0xFE000F,   3, TMS320C55_asub,      {{ op_TAx,      0x00F000         }, { op_TAy,        0x0000F0   }}},
  { 0x14000C,   0xFE000F,   3, TMS320C55_aadd,      {{ op_k8,       0x00FF00         }, { op_TAx,        0x0000F0   }}},
  { 0x14000D,   0xFE000F,   3, TMS320C55_amov,      {{ op_k8,       0x00FF00         }, { op_TAx,        0x0000F0   }}},
  { 0x14000E,   0xFE000F,   3, TMS320C55_asub,      {{ op_k8,       0x00FF00         }, { op_TAx,        0x0000F0   }}},
  { 0x160000,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k7,       0x0007F0         }, { op_DPH,        0          }}},
  { 0x160001,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k7,       0x0007F0         }, { op_MDP05,      0          }}},
  { 0x160002,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k7,       0x0007F0         }, { op_MDP67,      0          }}},
  { 0x160003,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k9,       0x001FF0         }, { op_PDP,        0          }}},
  { 0x160004,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k12,      0x00FFF0         }, { op_BK03,       0          }}},
  { 0x160005,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k12,      0x00FFF0         }, { op_BK47,       0          }}},
  { 0x160006,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k12,      0x00FFF0         }, { op_BKC,        0          }}},
  { 0x160008,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k12,      0x00FFF0         }, { op_CSR,        0          }}},
  { 0x160009,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k12,      0x00FFF0         }, { op_BRC0,       0          }}},
  { 0x16000A,   0xFE000F,   3, TMS320C55_mov2,      {{ op_k12,      0x00FFF0         }, { op_BRC1,       0          }}},
  // 0001011E xxxxxxxk kkkk11xx error manual
  { 0x180000,   0xFE0000,   3, TMS320C55_and3,      {{ op_k8,       0x00FF00         }, { op_src,        0x00000F   }, { op_dst,     0x0000F0         }}},
  { 0x1A0000,   0xFE0000,   3, TMS320C55_or3,       {{ op_k8,       0x00FF00         }, { op_src,        0x00000F   }, { op_dst,     0x0000F0         }}},
  { 0x1C0000,   0xFE0000,   3, TMS320C55_xor3,      {{ op_k8,       0x00FF00         }, { op_src,        0x00000F   }, { op_dst,     0x0000F0         }}},
  { 0x1E0000,   0xFE0002,   3, TMS320C55_mpyk2,     {{ insn_1_R,     0x000001         }, { op_K8,         0x00FF00   }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0x1E0002,   0xFE0002,   3, TMS320C55_mack3,     {{ insn_1_R,     0x000001         }, { op_Tx,         0x00000C   }, { op_K8,      0x00FF00         }, { op_ACx,    0x0000C0   }, { opt_ACy,    0x000030   }}},
  { 0x20,       0xFE,       1, TMS320C55_nop },
  { 0x2200,     0xFE00,     2, TMS320C55_mov2,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x2400,     0xFE00,     2, TMS320C55_add1,      {{ op_src,      0x00F0           }, { opt_dst,       0x000F     }}},
  { 0x2600,     0xFE00,     2, TMS320C55_sub1,      {{ op_src,      0x00F0           }, { opt_dst,       0x000F     }}},
  { 0x2800,     0xFE00,     2, TMS320C55_and2,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x2A00,     0xFE00,     2, TMS320C55_or2,       {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x2C00,     0xFE00,     2, TMS320C55_xor2,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x2E00,     0xFE00,     2, TMS320C55_max1,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x3000,     0xFE00,     2, TMS320C55_min1,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x3200,     0xFE00,     2, TMS320C55_abs1,      {{ op_src,      0x00F0           }, { opt_dst,       0x000F     }}},
  { 0x3400,     0xFE00,     2, TMS320C55_neg1,      {{ op_src,      0x00F0           }, { opt_dst,       0x000F     }}},
  { 0x3600,     0xFE00,     2, TMS320C55_not1,      {{ op_src,      0x00F0           }, { opt_dst,       0x000F     }}},
  { 0x3800,     0xFE00,     2, TMS320C55_psh2,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x3A00,     0xFE00,     2, TMS320C55_pop2,      {{ op_src,      0x00F0           }, { op_dst,        0x000F     }}},
  { 0x3C00,     0xFE00,     2, TMS320C55_mov2,      {{ op_k4,       0x00F0           }, { op_dst,        0x000F     }}},
  { 0x3E00,     0xFE00,     2, TMS320C55_mov2,      {{ op_min_k4,   0x00F0           }, { op_dst,        0x000F     }}},
  { 0x4000,     0xFE00,     2, TMS320C55_add2,      {{ op_k4,       0x00F0           }, { op_dst,        0x000F     }}},
  { 0x4200,     0xFE00,     2, TMS320C55_sub2,      {{ op_k4,       0x00F0           }, { op_dst,        0x000F     }}},
  { 0x4400,     0xFEC0,     2, TMS320C55_mov2,      {{ op_ACx,      0x0030           }, { fn_hi,         OP_TRUE    }, { op_TAx,     0x000F           }}},
  { 0x4440,     0xFED0,     2, TMS320C55_sfts2,     {{ op_dst,      0x000F           }, { op_min_1,      0          }}},
  { 0x4450,     0xFED0,     2, TMS320C55_sfts2,     {{ op_dst,      0x000F           }, { op_1,          0          }}},
  { 0x4480,     0xFEF0,     2, TMS320C55_mov2,      {{ op_SP,       0                }, { op_TAx,        0x000F     }}},
  { 0x4490,     0xFEF0,     2, TMS320C55_mov2,      {{ op_SSP,      0                }, { op_TAx,        0x000F     }}},
  { 0x44A0,     0xFEF0,     2, TMS320C55_mov2,      {{ op_CDP,      0                }, { op_TAx,        0x000F     }}},
  { 0x44C0,     0xFEF0,     2, TMS320C55_mov2,      {{ op_BRC0,     0                }, { op_TAx,        0x000F     }}},
  { 0x44D0,     0xFEF0,     2, TMS320C55_mov2,      {{ op_BRC1,     0                }, { op_TAx,        0x000F     }}},
  { 0x44E0,     0xFEF0,     2, TMS320C55_mov2,      {{ op_RPTC,     0                }, { op_TAx,        0x000F     }}},
  { 0x4600,     0xFE09,     2, TMS320C55_bclr2,     {{ op_k4,       0x00F0           }, { op_STx_55,     0x0006     }}},
  { 0x4601,     0xFE09,     2, TMS320C55_bset2,     {{ op_k4,       0x00F0           }, { op_STx_55,     0x0006     }}},
  // 0100011E xxxx1000 error manual
  // 0100011E xxxx1001 error manual
  // 0100011E xxxx1010 error manual
  // 0100011E xxxx1100 error manual
  { 0x4800,     0xFE07,     2, TMS320C55_rpt,       {{ op_CSR,      0                }}},
  { 0x4801,     0xFE07,     2, TMS320C55_rptadd,    {{ op_CSR,      0                }, { op_TAx,        0x00F0     }}},
  { 0x4802,     0xFE07,     2, TMS320C55_rptadd,    {{ op_CSR,      0                }, { op_k4,         0x00F0     }}},
  { 0x4803,     0xFE07,     2, TMS320C55_rptsub,    {{ op_CSR,      0                }, { op_k4,         0x00F0     }}},
  { 0x4804,     0xFE07,     2, TMS320C55_ret },
  { 0x4805,     0xFE07,     2, TMS320C55_reti },
  { 0x4A00,     0xFE80,     2, TMS320C55_b,         {{ op_L7,       0x007F           }}},
  { 0x4A80,     0xFE80,     2, TMS320C55_rptblocal, {{ op_pmad,     0x007F           }}},
  { 0x4C00,     0xFE00,     2, TMS320C55_rpt,       {{ op_k8,       0x00FF           }}},
  { 0x4E00,     0xFE00,     2, TMS320C55_aadd,      {{ op_K8,       0x00FF           }, { op_SP,         0          }}},
  { 0x5000,     0xFE07,     2, TMS320C55_sftl2,     {{ op_dst,      0x00F0           }, { op_1,          0          }}},
  { 0x5001,     0xFE07,     2, TMS320C55_sftl2,     {{ op_dst,      0x00F0           }, { op_min_1,      0          }}},
  { 0x5002,     0xFE07,     2, TMS320C55_pop1,      {{ op_dst,      0x00F0           }}},
  { 0x5003,     0xFE07,     2, TMS320C55_pop1,      {{ op_ACx,      0x0030           }, { fn_dbl,        OP_TRUE    }}},
  { 0x5004,     0xFE07,     2, TMS320C55_popboth,   {{ op_xsrc,     0x00F0           }}}, // not in documentation
  { 0x5005,     0xFE07,     2, TMS320C55_pshboth,   {{ op_xsrc,     0x00F0           }}}, // not in documentation
  { 0x5006,     0xFE07,     2, TMS320C55_psh1,      {{ op_dst,      0x00F0           }}},
  { 0x5007,     0xFE07,     2, TMS320C55_psh1,      {{ op_ACx,      0x0030           }, { fn_dbl,        OP_TRUE    }}},
  { 0x5200,     0xFE0C,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_ACx,        0x0003     }, { fn_hi,      OP_TRUE          }}},
  { 0x5208,     0xFE0F,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_SP,         0          }}},
  { 0x5209,     0xFE0F,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_SSP,        0          }}},
  { 0x520A,     0xFE0F,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_CDP,        0          }}},
  { 0x520C,     0xFE0F,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_CSR,        0          }}},
  { 0x520D,     0xFE0F,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_BRC1,       0          }}},
  { 0x520E,     0xFE0F,     2, TMS320C55_mov2,      {{ op_TAx,      0x00F0           }, { op_BRC0,       0          }}},
  { 0x5400,     0xFE0F,     2, TMS320C55_addv1,     {{ op_ACx,      0x0030           }, { opt_ACy,       0x00C0     }}},
  { 0x5401,     0xFE0F,     2, TMS320C55_addrv1,    {{ op_ACx,      0x0030           }, { opt_ACy,       0x00C0     }}},
  { 0x5402,     0xFE0E,     2, TMS320C55_sqa1,      {{ insn_1_R,     0x0001           }, { op_ACx,        0x0030     }, { opt_ACy,    0x00C0           }}},
  { 0x5404,     0xFE0E,     2, TMS320C55_sqs1,      {{ insn_1_R,     0x0001           }, { op_ACx,        0x0030     }, { opt_ACy,    0x00C0           }}},
  { 0x5406,     0xFE0E,     2, TMS320C55_mpy1,      {{ insn_1_R,     0x0001           }, { op_ACx,        0x0030     }, { opt_ACy,    0x00C0           }}},
  { 0x5408,     0xFE0E,     2, TMS320C55_sqr1,      {{ insn_1_R,     0x0001           }, { op_ACx,        0x0030     }, { opt_ACy,    0x00C0           }}},
  { 0x540A,     0xFE0E,     2, TMS320C55_round1,    {{ op_ACx,      0x0030           }, { opt_ACy,       0x00C0     }}}, // error manual: unused bits
  { 0x540C,     0xFE0E,     2, TMS320C55_sat1,      {{ insn_1_R,     0x0001           }, { op_ACx,        0x0030     }, { opt_ACy,    0x00C0           }}},
  { 0x5600,     0xFE02,     2, TMS320C55_mac3,      {{ insn_1_R,     0x0001           }, { op_ACx,        0x0030     }, { op_Tx,      0x000C           }, { opt_ACy,   0x00C0     }, { op_ACy,     0x00C0     }}},
  { 0x5602,     0xFE02,     2, TMS320C55_mas2,      {{ insn_1_R,     0x0001           }, { op_Tx,         0x000C     }, { op_ACx,     0x0030           }, { opt_ACy,   0x00C0     }}},
  { 0x5800,     0xFE02,     2, TMS320C55_mpy2,      {{ insn_1_R,     0x0001           }, { op_Tx,         0x000C     }, { op_ACx,     0x0030           }, { opt_ACy,   0x00C0     }}},
  { 0x5802,     0xFE02,     2, TMS320C55_mac4,      {{ insn_1_R,     0x0001           }, { op_ACy,        0x00C0     }, { op_Tx,      0x000C           }, { op_ACx,    0x0030     }, { op_ACy,     0x00C0     }}},
  { 0x5A00,     0xFE03,     2, TMS320C55_add2,      {{ op_ACx,      0x0030           }, { shl_Tx,        0x000C     }, { op_ACy,     0x00C0           }}},
  { 0x5A01,     0xFE03,     2, TMS320C55_sub2,      {{ op_ACx,      0x0030           }, { shl_Tx,        0x000C     }, { op_ACy,     0x00C0           }}},
  { 0x5A02,     0xFE02,     2, TMS320C55_sftcc,     {{ op_ACx,      0x00C0           }, { op_TCx,        0x0001     }}},
  { 0x5C00,     0xFE03,     2, TMS320C55_sftl2,     {{ op_ACx,      0x0030           }, { op_Tx,         0x000C     }, { opt_ACy,    0x00C0           }}},
  { 0x5C01,     0xFE03,     2, TMS320C55_sfts2,     {{ op_ACx,      0x0030           }, { op_Tx,         0x000C     }, { opt_ACy,    0x00C0           }}},
  { 0x5C02,     0xFE03,     2, TMS320C55_sftsc2,    {{ op_ACx,      0x0030           }, { op_Tx,         0x000C     }, { opt_ACy,    0x00C0           }}},
  { 0x5E00,     0xFEC0,     2, TMS320C55_swap,      {{ op_swap,     0x003F           }}},
  { 0x5E80,     0xFEC0,     2, TMS320C55_nop_16 },
  { 0x6000,     0xF800,     2, TMS320C55_bcc,       {{ op_l4,       0x0780           }, { op_cond,       0x007F     }}},
  { 0x6800,     0xFF00,     2, TMS320C55_bcc,       {{ op_P24,      0                }, { op_cond,       0x007F     }}}, // compiler bug
  { 0x6900,     0xFF00,     2, TMS320C55_callcc,    {{ op_P24,      0                }, { op_cond,       0x007F     }}},
  { 0x6A,       0xFF,       1, TMS320C55_b,         {{ op_P24,      0                }}},
  { 0x6C,       0xFF,       1, TMS320C55_call,      {{ op_P24,      0                }}},
  { 0x6D000000, 0xFF000000, 4, TMS320C55_bcc,       {{ op_L16,      0x0000FFFF       }, { op_cond,       0x007F0000 }}},
  { 0x6E000000, 0xFF000000, 4, TMS320C55_callcc,    {{ op_L16,      0x0000FFFF       }, { op_cond,       0x007F0000 }}},
  { 0x6F000000, 0xFF000000, 4, TMS320C55_bcc,       {{ insn_1_U,     0x00010000       }, { op_L8,         0x000000FF }, { op_src,     0x00F00000       }, { RELOP,     0x000C0000 }, { RELOP_K8,   0x0000FF00 }}},
  { 0x70000000, 0xFF000000, 4, TMS320C55_add2,      {{ op_K16,      0x00FFFF00       }, { shl_SHFT,      0x0000000F }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x71000000, 0xFF000000, 4, TMS320C55_sub2,      {{ op_K16,      0x00FFFF00       }, { shl_SHFT,      0x0000000F }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x72000000, 0xFF000000, 4, TMS320C55_and2,      {{ op_k16,      0x00FFFF00       }, { shl_SHFT,      0x0000000F }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x73000000, 0xFF000000, 4, TMS320C55_or2,       {{ op_k16,      0x00FFFF00       }, { shl_SHFT,      0x0000000F }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x74000000, 0xFF000000, 4, TMS320C55_xor2,      {{ op_k16,      0x00FFFF00       }, { shl_SHFT,      0x0000000F }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x75000000, 0xFF000000, 4, TMS320C55_mov2,      {{ op_K16,      0x00FFFF00       }, { shl_SHFT,      0x0000000F }, { op_ACx,     0x00000030       }}},
  { 0x76000000, 0xFF00000C, 4, TMS320C55_bfxtr,     {{ op_k16,      0x00FFFF00       }, { op_ACx,        0x00000003 }, { op_dst,     0x000000F0       }}},
  { 0x76000004, 0xFF00000C, 4, TMS320C55_bfxpa,     {{ op_k16,      0x00FFFF00       }, { op_ACx,        0x00000003 }, { op_dst,     0x000000F0       }}},
  { 0x76000008, 0xFF00000C, 4, TMS320C55_mov2,      {{ op_K16,      0x00FFFF00       }, { op_dst,        0x000000F0 }}},
  { 0x77000000, 0xFF000000, 4, TMS320C55_amov,      {{ op_D16,      0x00FFFF00       }, { op_TAx,        0x000000F0 }}},
  { 0x78000000, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_DP,         0          }}},
  { 0x78000002, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_SSP,        0          }}},
  { 0x78000004, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_CDP,        0          }}},
  { 0x78000006, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_BSA01,      0          }}},
  { 0x78000008, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_BSA23,      0          }}},
  { 0x7800000A, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_BSA45,      0          }}},
  { 0x7800000C, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_BSA67,      0          }}},
  { 0x7800000E, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_BSAC,       0          }}},
  { 0x78000010, 0xFF00001E, 4, TMS320C55_mov2,      {{ op_k16,      0x00FFFF00       }, { op_SP,         0          }}},
  { 0x79000000, 0xFF000002, 4, TMS320C55_mpyk2,     {{ insn_1_R,     0x00000001       }, { op_K16,        0x00FFFF00 }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x79000002, 0xFF000002, 4, TMS320C55_mack3,     {{ insn_1_R,     0x00000001       }, { op_Tx,         0x0000000C }, { op_K16,     0x00FFFF00       }, { op_ACx,    0x000000C0 }, { opt_ACy,    0x00000030 }}},
  { 0x7A000000, 0xFF00000E, 4, TMS320C55_add2,      {{ op_K16,      0x00FFFF00       }, { shl_16,        0,         }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x7A000002, 0xFF00000E, 4, TMS320C55_sub2,      {{ op_K16,      0x00FFFF00       }, { shl_16,        0,         }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x7A000004, 0xFF00000E, 4, TMS320C55_and2,      {{ op_k16,      0x00FFFF00       }, { shl_16,        0,         }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x7A000006, 0xFF00000E, 4, TMS320C55_or2,       {{ op_k16,      0x00FFFF00       }, { shl_16,        0,         }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x7A000008, 0xFF00000E, 4, TMS320C55_xor2,      {{ op_k16,      0x00FFFF00       }, { shl_16,        0,         }, { op_ACx,     0x000000C0       }, { opt_ACy,   0x00000030 }}},
  { 0x7A00000A, 0xFF00000E, 4, TMS320C55_mov2,      {{ op_K16,      0x00FFFF00       }, { shl_16,        0,         }, { op_ACx,     0x00000030       }}},
  { 0x7A00000C, 0xFF00000E, 4, TMS320C55_idle },
  { 0x7B000000, 0xFF000000, 4, TMS320C55_add2,      {{ op_K16,      0x00FFFF00       }, { op_src,        0x0000000F }, { opt_dst,    0x000000F0       }}},
  { 0x7C000000, 0xFF000000, 4, TMS320C55_sub2,      {{ op_K16,      0x00FFFF00       }, { op_src,        0x0000000F }, { opt_dst,    0x000000F0       }}},
  { 0x7D000000, 0xFF000000, 4, TMS320C55_and2,      {{ op_k16,      0x00FFFF00       }, { op_src,        0x0000000F }, { op_dst,     0x000000F0       }}},
  { 0x7E000000, 0xFF000000, 4, TMS320C55_or2,       {{ op_k16,      0x00FFFF00       }, { op_src,        0x0000000F }, { op_dst,     0x000000F0       }}},
  { 0x7F000000, 0xFF000000, 4, TMS320C55_xor2,      {{ op_k16,      0x00FFFF00       }, { op_src,        0x0000000F }, { op_dst,     0x000000F0       }}},
  { 0x800000,   0xFF000C,   3, TMS320C55_mov2,      {{ op_Xmem,     0x00FC00         }, { fn_dbl,        OP_TRUE,   }, { op_Ymem,    0x0003F0         }, { fn_dbl,    OP_TRUE    }}},
  { 0x800004,   0xFF000C,   3, TMS320C55_mov2,      {{ op_Xmem,     0x00FC00         }, { op_Ymem,       0x0003F0   }}},
  { 0x800008,   0xFF000C,   3, TMS320C55_mov3,      {{ op_ACx,      0x000003         }, { op_Xmem,       0x00FC00,  }, { op_Ymem,    0x0003F0         }}},
  { 0x810000,   0xFF000C,   3, TMS320C55_add3,      {{ op_Xmem,     0x00FC00         }, { op_Ymem,       0x0003F0,  }, { op_ACx,     0x000003         }}},
  { 0x810004,   0xFF000C,   3, TMS320C55_sub3,      {{ op_Xmem,     0x00FC00         }, { op_Ymem,       0x0003F0,  }, { op_ACx,     0x000003         }}},
  { 0x810008,   0xFF000C,   3, TMS320C55_mov3,      {{ op_Xmem,     0x00FC00         }, { op_Ymem,       0x0003F0,  }, { op_ACx,     0x000003         }}},
  { 0x82000000, 0xFF000C00, 4, TMS320C55_mpy_mpy,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x82000400, 0xFF000C00, 4, TMS320C55_mac_mpy,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x82000800, 0xFF000C00, 4, TMS320C55_mas_mpy,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x82000C00, 0xFF000C00, 4, TMS320C55_amar_mpy,  {{ insn_1_2_R,   0x00000001       }, { insn_1_2_40,    0x00000002 }, { op_Xmem,    0x00FC0000       }, { blt_prll,  0,         }, { op_Ymem,    0x0003F000 }, { fn_uns,    0x00000080 }, { op_Cmem,   0x00000300 }, { fn_uns,   0x00000040 }, { op_ACx,   0x0000000C }}},
  { 0x83000000, 0xFF000C00, 4, TMS320C55_mac_mac,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x83000400, 0xFF000C00, 4, TMS320C55_mas_mac,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x83000800, 0xFF000C00, 4, TMS320C55_mac_mac,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { shr,      OP_IMM(16) }, { blt_prll, 0          }, { op_Ymem, 0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns, 0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x83000C00, 0xFF000C00, 4, TMS320C55_amar_mac,  {{ insn_1_2_R,   0x00000001       }, { insn_1_2_40,    0x00000002 }, { op_Xmem,    0x00FC0000       }, { blt_prll,  0,         }, { op_Ymem,    0x0003F000 }, { fn_uns,    0x00000080 }, { op_Cmem,   0x00000300 }, { fn_uns,   0x00000040 }, { op_ACx,   0x0000000C }}},
  { 0x84000000, 0xFF000C00, 4, TMS320C55_mas_mac,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }, { shr,    OP_IMM(16) }}},
  { 0x84000400, 0xFF000C00, 4, TMS320C55_amar_mac,  {{ insn_1_2_R,   0x00000001       }, { insn_1_2_40,    0x00000002 }, { op_Xmem,    0x00FC0000       }, { blt_prll,  0,         }, { op_Ymem,    0x0003F000 }, { fn_uns,    0x00000080 }, { op_Cmem,   0x00000300 }, { fn_uns,   0x00000040 }, { op_ACx,   0x0000000C }, { shr,     OP_IMM(16) }}},
  { 0x84000800, 0xFF000C00, 4, TMS320C55_mpy_mac,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }, { shr,    OP_IMM(16) }}},
  { 0x84000C00, 0xFF000C00, 4, TMS320C55_mac_mac,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { shr,      OP_IMM(16) }, { blt_prll, 0          }, { op_Ymem, 0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns, 0x00000040 }, { op_ACy, 0x0000000C }, { shr, OP_IMM(16) }}},
  { 0x85000000, 0xFF000C00, 4, TMS320C55_amar_mas,  {{ insn_1_2_R,   0x00000001       }, { insn_1_2_40,    0x00000002 }, { op_Xmem,    0x00FC0000       }, { blt_prll,  0,         }, { op_Ymem,    0x0003F000 }, { fn_uns,    0x00000080 }, { op_Cmem,   0x00000300 }, { fn_uns,   0x00000040 }, { op_ACx,   0x0000000C }}},
  { 0x85000400, 0xFF000C00, 4, TMS320C55_mas_mas,   {{ insn_1_R_2_R, 0x00000001       }, { insn_1_40_2_40, 0x00000002 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000080 }, { op_Cmem,    0x00000300 }, { fn_uns,    0x00000040 }, { op_ACx,    0x00000030 }, { blt_prll, 0          }, { op_Ymem,  0x0003F000 }, { fn_uns,  0x00000080 }, { op_Cmem, 0x00000300 }, { fn_uns,  0x00000040 }, { op_ACy, 0x0000000C }}},
  { 0x85000800, 0xFF000C00, 4, TMS320C55_amar3,     {{ op_Xmem,     0x00FC0000       }, { op_Ymem,       0x0003F000 }, { op_Cmem,    0x00000300       }}},
  { 0x85000C00, 0xFF000C10, 4, TMS320C55_firsadd,   {{ op_Xmem,     0x00FC0000       }, { op_Ymem,       0x0003F000 }, { op_Cmem,    0x00000300       }, { op_ACx,    0x000000C0 }, { op_ACy,     0x0000000C }}}, // error manual: unused bits: DDx0DDU% p552
  { 0x85000C10, 0xFF000C10, 4, TMS320C55_firssub,   {{ op_Xmem,     0x00FC0000       }, { op_Ymem,       0x0003F000 }, { op_Cmem,    0x00000300       }, { op_ACx,    0x000000C0 }, { op_ACy,     0x0000000C }}}, // error manual: unused bits: DDx0DDU% p552
  { 0x86000000, 0xFF0000E0, 4, TMS320C55_mpym3,     {{ insn_1_R,     0x00000001       }, { insn_1_40,      0x00000010 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000008 }, { fn_T3,      0x00000002 }, { op_Ymem,   0x0003F000 }, { fn_uns,    0x00000004 }, { op_ACx,   0x00000300 }}},
  { 0x86000020, 0xFF0000E0, 4, TMS320C55_macm3,     {{ insn_1_R,     0x00000001       }, { insn_1_40,      0x00000010 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000008 }, { fn_T3,      0x00000002 }, { op_Ymem,   0x0003F000 }, { fn_uns,    0x00000004 }, { op_ACx,   0x00000C00 }, { opt_ACy,  0x00000300 }}},
  { 0x86000040, 0xFF0000E0, 4, TMS320C55_macm3,     {{ insn_1_R,     0x00000001       }, { insn_1_40,      0x00000010 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000008 }, { fn_T3,      0x00000002 }, { op_Ymem,   0x0003F000 }, { fn_uns,    0x00000004 }, { op_ACx,   0x00000C00 }, { shr,      OP_IMM(16) }, { opt_ACy, 0x00000300 }}},
  { 0x86000060, 0xFF0000E0, 4, TMS320C55_masm3,     {{ insn_1_R,     0x00000001       }, { insn_1_40,      0x00000010 }, { op_Xmem,    0x00FC0000       }, { fn_uns,    0x00000008 }, { fn_T3,      0x00000002 }, { op_Ymem,   0x0003F000 }, { fn_uns,    0x00000004 }, { op_ACx,   0x00000C00 }, { opt_ACy,  0x00000300 }}},
  { 0x86000080, 0xFF0000E0, 4, TMS320C55_masm_mov,  {{ insn_1_R_2,   0x00000001       }, { op_Xmem,       0x00FC0000 }, { fn_T3,      0x00000002       }, { op_Tx,     0x0000000C }, { op_ACx,     0x00000C00 }, { blt_prll,  0,         }, { op_Ymem,   0x0003F000 }, { shl_16,   0          }, { op_ACy,   0x00000300 }}},
  { 0x860000A0, 0xFF0000E0, 4, TMS320C55_macm_mov,  {{ insn_1_R_2,   0x00000001       }, { op_Xmem,       0x00FC0000 }, { fn_T3,      0x00000002       }, { op_Tx,     0x0000000C }, { op_ACx,     0x00000C00 }, { blt_prll,  0,         }, { op_Ymem,   0x0003F000 }, { shl_16,   0          }, { op_ACy,   0x00000300 }}},
  { 0x860000C0, 0xFF0000E0, 4, TMS320C55_lms,       {{ op_Xmem,     0x00FC0000       }, { op_Ymem,       0x0003F000 }, { op_ACx,     0x00000C00       }, { op_ACy,    0x00000300 }}},
  { 0x860000E0, 0xFF0000F0, 4, TMS320C55_sqdst,     {{ op_Xmem,     0x00FC0000       }, { op_Ymem,       0x0003F000 }, { op_ACx,     0x00000C00       }, { op_ACy,    0x00000300 }}},
  { 0x860000F0, 0xFF0000F0, 4, TMS320C55_abdst,     {{ op_Xmem,     0x00FC0000       }, { op_Ymem,       0x0003F000 }, { op_ACx,     0x00000C00       }, { op_ACy,    0x00000300 }}},
  { 0x87000000, 0xFF0000E0, 4, TMS320C55_mpym_mov,  {{ insn_1_R_2,   0x00000001       }, { op_Xmem,       0x00FC0000 }, { fn_T3,      0x00000002       }, { op_Tx,     0x0000000C }, { op_ACy,     0x00000300 }, { blt_prll,  0,         }, { op_ACx,    0x00000C00 }, { fn_hi,    OP_TRUE    }, { shl_T2,   0          }, { op_Ymem, 0x0003F000 }}},
  { 0x87000020, 0xFF0000E0, 4, TMS320C55_macm_mov,  {{ insn_1_R_2,   0x00000001       }, { op_Xmem,       0x00FC0000 }, { fn_T3,      0x00000002       }, { op_Tx,     0x0000000C }, { op_ACy,     0x00000300 }, { blt_prll,  0,         }, { op_ACx,    0x00000C00 }, { fn_hi,    OP_TRUE    }, { shl_T2,   0          }, { op_Ymem, 0x0003F000 }}},
  { 0x87000040, 0xFF0000E0, 4, TMS320C55_masm_mov,  {{ insn_1_R_2,   0x00000001       }, { op_Xmem,       0x00FC0000 }, { fn_T3,      0x00000002       }, { op_Tx,     0x0000000C }, { op_ACy,     0x00000300 }, { blt_prll,  0,         }, { op_ACx,    0x00000C00 }, { fn_hi,    OP_TRUE    }, { shl_T2,   0          }, { op_Ymem, 0x0003F000 }}},
  { 0x87000080, 0xFF0000E0, 4, TMS320C55_add_mov,   {{ op_Xmem,     0x00FC0000       }, { shl_16,        0,         }, { op_ACx,     0x00000C00       }, { op_ACy,    0x00000300 }, { blt_prll,   0,         }, { op_ACy,    0x00000300 }, { fn_hi,     OP_TRUE,   }, { shl_T2,   0          }, { op_Ymem,  0x0003F000 }}},
  { 0x870000A0, 0xFF0000E0, 4, TMS320C55_sub_mov,   {{ op_Xmem,     0x00FC0000       }, { shl_16,        0,         }, { op_ACx,     0x00000C00       }, { op_ACy,    0x00000300 }, { blt_prll,   0,         }, { op_ACy,    0x00000300 }, { fn_hi,     OP_TRUE,   }, { shl_T2,   0          }, { op_Ymem,  0x0003F000 }}},
  { 0x870000C0, 0xFF0000E0, 4, TMS320C55_mov_mov,   {{ op_Xmem,     0x00FC0000       }, { shl_16,        0,         }, { op_ACy,     0x00000300       }, { blt_prll,  0,         }, { op_ACx,     0x00000C00 }, { fn_hi,     OP_TRUE    }, { shl_T2,    0,         }, { op_Ymem,  0x0003F000 }}},
  { 0x8A0000A0, 0xFF0000F0, 4, TMS320C55_mov_mov,   {{ op_Xmem,     0x00FC0000       }, { op_dst,        0x00000F00 }, { blt_prll,   0,               }, { op_Ymem,   0x0003F000 }, { op_dst,     0x0000000F }}},
  { make_int64(0x00001000, 0x008A), make_int64(0x0000F700, 0x00FF), 5, TMS320C55_mov_aadd, {{ op_Smem,                0xFF000000          }, { op_dst,                 0x000F0000          }, { blt_prll,             0 }, { op_src,      0x00000000F0 }, { op_dst,    0x0000F00000 }}},
  { make_int64(0x0000D600, 0x008A), make_int64(0x0000FF00, 0x00FF), 5, TMS320C55_mov_add,  {{ op_Xmem,                0xFC000000          }, { op_dst,                 0x000F0000          }, { blt_prll,             0 }, { op_Ymem,     0x0003F00000 }, { op_dst,    0x00000000F0 }, { op_src,   0x000000000F }}},
  { make_int64(0x0000E708, 0x008A), make_int64(0x0000FF0C, 0x00FF), 5, TMS320C55_mov_mov,  {{ op_Xmem,                0xFC000000          }, { op_dst,                 0x000F0000          }, { blt_prll,             0 }, { op_ACx,      0x00000000C0 }, { shl_Tx,    0x0000000030 }, { fn_hi,       OP_TRUE_5 }, { fn_rnd,    0x0000000001 }, { op_Ymem,  0x0003F00000 }}},
  {               0x8B0004B4,                        0xFF000FFF,          4, TMS320C55_amar_amar, {{ op_Xmem,                0x00FC0000          }, { blt_prll,               0,                  }, { op_Ymem,     0x0003F000 }}},
  { make_int64(0x00001400, 0x008C), make_int64(0x0000F700, 0x00FF), 5, TMS320C55_mov_aadd, {{ op_src,                 0x000F0000          }, { op_Smem,                0xFF000000          }, { blt_prll,             0 }, { op_k8,       0x00000000FF }, { op_dst,    0x0000F00000 }}},
  { make_int64(0x000CB000, 0x008D), make_int64(0x000FFC03, 0x00FF), 5, TMS320C55_btst_mov, {{ op_k4,                  0x000000F0          }, { op_Xmem,                0xFC000000          }, { op_TCx,      0x00000001 }, { blt_prll,               0 }, { op_Ymem,   0x0003F00000 }, { shl_16,              0 }, { op_ACx,      0x00000300 }}},
  { make_int64(0x061A0000, 0x8D00), make_int64(0x0FF70000, 0xFF00), 6, TMS320C55_add_asub, {{ op_Smem,  make_int64(0x00000000, 0x00FF) }, { op_dst,   make_int64(0x0000F000, 0x0000) }, { op_src,  0x000000000F00 }, { blt_prll,               0 }, { op_src,  0x0000000000F0 }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x0B100500, 0x8E00), make_int64(0x0FF70F00, 0xFF00), 6, TMS320C55_mov_aadd, {{ op_xdst,  make_int64(0x0000F000, 0x0000) }, { op_Lmem,  make_int64(0x00000000, 0x00FF) }, { fn_dbl,       OP_TRUE_6 }, { blt_prll,               0 }, { op_src,  0x0000000000F0 }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x0B160500, 0x8E00), make_int64(0x0FF70F00, 0xFF00), 6, TMS320C55_mov_asub, {{ op_xdst,  make_int64(0x0000F000, 0x0000) }, { op_Lmem,  make_int64(0x00000000, 0x00FF) }, { fn_dbl,       OP_TRUE_6 }, { blt_prll,               0 }, { op_k8,   0x0000000000FF }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x0D100800, 0x8E00), make_int64(0x0FF70F00, 0xFF00), 6, TMS320C55_mov_aadd, {{ op_Lmem,  make_int64(0x00000000, 0x00FF) }, { fn_dbl,                          OP_TRUE_6  }, { op_ACx,  0x000000003000 }, { blt_prll,               0 }, { op_src,  0x0000000000F0 }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x0B140500, 0x8E00), make_int64(0x0FF70F00, 0xFF00), 6, TMS320C55_mov_aadd, {{ op_xdst,  make_int64(0x0000F000, 0x0000) }, { op_Lmem,  make_int64(0x00000000, 0x00FF) }, { fn_dbl,       OP_TRUE_6 }, { blt_prll,               0 }, { op_k8,   0x0000000000FF }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x0B140800, 0x8E00), make_int64(0x0FF70F00, 0xFF00), 6, TMS320C55_mov_aadd, {{ op_ACx,   make_int64(0x00003000, 0x0000) }, { op_Lmem,  make_int64(0x00000000, 0x00FF) }, { fn_dbl,       OP_TRUE_6 }, { blt_prll,               0 }, { op_k8,   0x0000000000FF }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x0B100800, 0x8E00), make_int64(0x0FF70F00, 0xFF00), 6, TMS320C55_mov_aadd, {{ op_ACx,   make_int64(0x00003000, 0x0000) }, { op_Lmem,  make_int64(0x00000000, 0x00FF) }, { fn_dbl,       OP_TRUE_6 }, { blt_prll,               0 }, { op_src,  0x0000000000F0 }, { op_dst, 0x0000F0000000 }}},
  { make_int64(0x06140000, 0x8E00), make_int64(0x0FF70000, 0xFF00), 6, TMS320C55_mov_aadd, {{ op_k8,    make_int64(0x0000FF00, 0x0000) }, { op_Lmem,  make_int64(0x00000000, 0x00FF) }, { blt_prll,             0 }, { op_k8,     0x0000000000FF }, { op_dst,  0x0000F0000000 }}},
  { make_int64(0x0DEB080D, 0x8E00), make_int64(0x0FFF0F0F, 0xFF00), 6, TMS320C55_mov_mov,  {{ op_Xmem,  make_int64(0x00000000, 0x00FC) }, { fn_dbl,                          OP_TRUE_6  }, { op_ACx,  0x000000003000 }, { blt_prll,               0 }, { op_ACx,  0x000000000030 }, { shr,       OP_IMM_6(1) }, { op_Ymem, make_int64(0xF0000000, 0x0003) }, { fn_dual,                       OP_TRUE_6 }}},
  { make_int64(0x0EEB040D, 0x8E00), make_int64(0x0FFF0F0F, 0xFF00), 6, TMS320C55_sub_mov,  {{ op_Xmem,  make_int64(0x00000000, 0x00FC) }, { fn_dual,                         OP_TRUE_6  }, { op_ACx,  0x00000000C000 }, { op_ACy,    0x000000003000 }, { blt_prll,             0 }, { op_ACx, 0x000000000030 }, { shr,                   OP_IMM_6(1        ) }, { op_Ymem, make_int64(0xF0000000, 0x03) }, { fn_dual, OP_TRUE_6 }}},
  { make_int64(0x0EEB000D, 0x8E00), make_int64(0x0FFF0F0F, 0xFF00), 6, TMS320C55_add_mov,  {{ op_Xmem,  make_int64(0x00000000, 0x00FC) }, { fn_dual,                         OP_TRUE_6  }, { op_ACx,  0x00000000C000 }, { op_ACy,    0x000000003000 }, { blt_prll,             0 }, { op_ACx, 0x000000000030 }, { shr,                   OP_IMM_6(1        ) }, { op_Ymem, make_int64(0xF0000000, 0x03) }, { fn_dual, OP_TRUE_6 }}},
  { make_int64(0x0EEB0408, 0x8E00), make_int64(0x0FFF0F0F, 0xFF00), 6, TMS320C55_sub_mov,  {{ op_Xmem,  make_int64(0x00000000, 0x00FC) }, { fn_dual,                         OP_TRUE_6  }, { op_ACx,  0x00000000C000 }, { op_ACy,    0x000000003000 }, { blt_prll,             0 }, { op_ACx, 0x000000000030 }, { op_Ymem, make_int64(0xF0000000, 0x0003) }, { fn_dbl,                        OP_TRUE_6 }}},
  { make_int64(0x0EEB0008, 0x8E00), make_int64(0x0FFF0F0F, 0xFF00), 6, TMS320C55_add_mov,  {{ op_Xmem,  make_int64(0x00000000, 0x00FC) }, { fn_dual,                         OP_TRUE_6  }, { op_ACx,  0x00000000C000 }, { op_ACy,    0x000000003000 }, { blt_prll,             0 }, { op_ACx, 0x000000000030 }, { op_Ymem, make_int64(0xF0000000, 0x0003) }, { fn_dbl,                        OP_TRUE_6 }}},

  // 10001xxx error manual
  { 0x9000,     0xFF00,     2, TMS320C55_mov2,      {{op_xsrc,     0x00F0            }, {op_xdst,        0x000F}}},
  { 0x9100,     0xFF00,     2, TMS320C55_b,         {{ op_ACx,      0x0003           }}},
  { 0x9200,     0xFF00,     2, TMS320C55_call,      {{ op_ACx,      0x0003           }}},
  { 0x9400,     0xFF00,     2, TMS320C55_reset },
  { 0x9500,     0xFF80,     2, TMS320C55_intr,      {{ op_k5,       0x001F           }}},
  { 0x9580,     0xFF80,     2, TMS320C55_trap,      {{ op_k5,       0x001F           }}},
  { 0x9600,     0xFF80,     2, TMS320C55_xcc,       {{ op_cond,     0x007F           }}},
  { 0x9680,     0xFF80,     2, TMS320C55_xccpart,   {{ op_cond,     0x007F           }}},
  // 10010111 error manual
  // mmap()
  // port()
  // <instruction>.LR
  // <instruction>.CR
  { 0x9E00,     0xFF80,     2, TMS320C55_xcc,       {{ op_cond,     0x007F           }, { insn_UP,        0          }}},
  { 0x9E80,     0xFF80,     2, TMS320C55_xccpart,   {{ op_cond,     0x007F           }}},
  { 0x9F00,     0xFF80,     2, TMS320C55_xcc,       {{ op_cond,     0x007F           }}},
  { 0x9F80,     0xFF80,     2, TMS320C55_xccpart,   {{ op_cond,     0x007F           }}},
  { 0xA000,     0xF000,     2, TMS320C55_mov2,      {{ op_Smem,     0x00FF           }, { op_dst,        0x0F00     }}},
  { 0xB000,     0xFC00,     2, TMS320C55_mov2,      {{ op_Smem,     0x00FF           }, { shl_16,        0          }, { op_ACx,     0x0300           }}},
  { 0xB400,     0xFF00,     2, TMS320C55_amar1,     {{ op_Smem,     0x00FF           }}},
  { 0xB500,     0xFF00,     2, TMS320C55_psh1,      {{ op_Smem,     0x00FF           }}},
  { 0xB600,     0xFF00,     2, TMS320C55_delay,     {{ op_Smem,     0x00FF           }}},
  { 0xB700,     0xFF00,     2, TMS320C55_psh1,      {{ op_Lmem,     0x00FF           }, { fn_dbl,        OP_TRUE    }}},
  { 0xB800,     0xFF00,     2, TMS320C55_pop1,      {{ op_Lmem,     0x00FF           }, { fn_dbl,        OP_TRUE    }}},
  { 0xBB00,     0xFF00,     2, TMS320C55_pop1,      {{ op_Smem,     0x00FF           }}},
  { 0xBC00,     0xFC00,     2, TMS320C55_mov2,      {{ op_ACx,      0x0300           }, { fn_hi,         OP_TRUE    }, { op_Smem,    0x00FF           }}},
  { 0xC000,     0xF000,     2, TMS320C55_mov2,      {{ op_src,      0x0F00           }, { op_Smem,       0x00FF     }}},
  { 0xD00000,   0xFF0040,   3, TMS320C55_macmz,     {{ op_Smem,     0x00FF00         }, { fn_T3,         0x000080   }, { op_Cmem,    0x000003         }, { op_ACx,    0x000030   }}},
  { 0xD00040,   0xFF0040,   3, TMS320C55_macmrz,    {{ op_Smem,     0x00FF00         }, { fn_T3,         0x000080   }, { op_Cmem,    0x000003         }, { op_ACx,    0x000030   }}},
  { 0xD10000,   0xFF000C,   3, TMS320C55_mpym3,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_Cmem,   0x000003   }, { op_ACx,     0x000030   }}},
  { 0xD10004,   0xFF000C,   3, TMS320C55_macm3,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_Cmem,   0x000003   }, { op_ACx,     0x000030   }}},
  { 0xD10008,   0xFF000C,   3, TMS320C55_masm3,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_Cmem,   0x000003   }, { op_ACx,     0x000030   }}},
  { 0xD20000,   0xFF000C,   3, TMS320C55_macm2,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_ACx,    0x000003   }, { opt_ACy,    0x000030   }}},
  { 0xD20004,   0xFF000C,   3, TMS320C55_masm2,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_ACx,    0x000003   }, { opt_ACy,    0x000030   }}},
  { 0xD20008,   0xFF000C,   3, TMS320C55_sqam2,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_ACx,    0x000003   }, { opt_ACy,    0x000030   }}},
  { 0xD2000C,   0xFF000C,   3, TMS320C55_sqsm2,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_ACx,    0x000003   }, { opt_ACy,    0x000030   }}},
  { 0xD30000,   0xFF000C,   3, TMS320C55_mpym2,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_ACx,    0x000003   }, { opt_ACy,    0x000030   }}},
  { 0xD30008,   0xFF000C,   3, TMS320C55_sqrm,      {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_ACx,    0x000030   }}},
  { 0xD30004,   0xFF0004,   3, TMS320C55_mpym3,     {{ insn_1_R,     0x000040         }, { insn_1_U,       0x000008   }, { op_Smem,    0x00FF00         }, { fn_T3,     0x000080   }, { op_Tx,      0x000003   }, { op_ACx,    0x000030   }}},
  { 0xD40000,   0xFF0000,   3, TMS320C55_macm3,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_Tx,     0x00000C   }, { op_ACx,     0x000003   }, { opt_ACy,   0x000030   }}},
  { 0xD50000,   0xFF0000,   3, TMS320C55_masm3,     {{ insn_1_R,     0x000040         }, { op_Smem,       0x00FF00   }, { fn_T3,      0x000080         }, { op_Tx,     0x00000C   }, { op_ACx,     0x000003   }, { opt_ACy,   0x000030   }}},
  { 0xD60000,   0xFF0000,   3, TMS320C55_add2,      {{ op_Smem,     0x00FF00         }, { op_src,        0x00000F   }, { opt_dst,    0x0000F0         }}},
  { 0xD70000,   0xFF0000,   3, TMS320C55_sub2,      {{ op_Smem,     0x00FF00         }, { op_src,        0x00000F   }, { opt_dst,    0x0000F0         }}},
  { 0xD80000,   0xFF0000,   3, TMS320C55_sub3,      {{ op_src,      0x00000F         }, { op_Smem,       0x00FF00   }, { op_dst,     0x0000F0         }}},
  { 0xD90000,   0xFF0000,   3, TMS320C55_and3,      {{ op_Smem,     0x00FF00         }, { op_src,        0x00000F   }, { op_dst,     0x0000F0         }}},
  { 0xDA0000,   0xFF0000,   3, TMS320C55_or3,       {{ op_Smem,     0x00FF00         }, { op_src,        0x00000F   }, { op_dst,     0x0000F0         }}},
  { 0xDB0000,   0xFF0000,   3, TMS320C55_xor3,      {{ op_Smem,     0x00FF00         }, { op_src,        0x00000F   }, { op_dst,     0x0000F0         }}},
  { 0xDC0000,   0xFF0002,   3, TMS320C55_btst,      {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TCx,     0x000001         }}},
  { 0xDC0002,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_DP,         0          }}},
  { 0xDC0012,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_CDP,        0          }}},
  { 0xDC0022,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BSA01,      0          }}},
  { 0xDC0032,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BSA23,      0          }}},
  { 0xDC0042,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BSA45,      0          }}},
  { 0xDC0052,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BSA67,      0          }}},
  { 0xDC0062,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BSAC,       0          }}},
  { 0xDC0072,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_SP,         0          }}},
  { 0xDC0082,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_SSP,        0          }}},
  { 0xDC0092,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BK03,       0          }}},
  { 0xDC00A2,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BK47,       0          }}},
  { 0xDC00B2,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BKC,        0          }}},
  { 0xDC00C2,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_DPH,        0          }}},
  { 0xDC00D2,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_MDP05,      0          }}},
  { 0xDC00E2,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_MDP67,      0          }}},
  { 0xDC00F2,   0xFF00F3,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_PDP,        0          }}},
  { 0xDC0003,   0xFF0073,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_CSR,        0          }}},
  { 0xDC0013,   0xFF0073,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BRC0,       0          }}},
  { 0xDC0023,   0xFF0073,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_BRC1,       0          }}},
  { 0xDC0033,   0xFF0073,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_TRN0,       0          }}},
  { 0xDC0043,   0xFF0073,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_TRN1,       0          }}},
  { 0xDD0000,   0xFF0003,   3, TMS320C55_add2,      {{ op_Smem,     0x00FF00         }, { shl_Tx,        0x00000C   }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xDD0001,   0xFF0003,   3, TMS320C55_sub2,      {{ op_Smem,     0x00FF00         }, { shl_Tx,        0x00000C   }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xDD0002,   0xFF0003,   3, TMS320C55_addsub2cc, {{ op_Smem,     0x00FF00         }, { op_ACx,        0x0000C0   }, { op_Tx,      0x00000C         }, { op_TC1,    0,         }, { op_TC2,     0,         }, { op_ACy,    0x000030   }}},
  { 0xDD0003,   0xFF0003,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { shl_Tx,        0x00000C   }, { fn_rnd,     0x000040         }, { op_ACx,    0x000030   }}},
  { 0xDE0000,   0xFF000F,   3, TMS320C55_addsubcc4, {{ op_Smem,     0x00FF00         }, { op_ACx,        0x0000C0   }, { op_TC1,     0                }, { op_ACy,    0x000030   }}},
  { 0xDE0001,   0xFF000F,   3, TMS320C55_addsubcc4, {{ op_Smem,     0x00FF00         }, { op_ACx,        0x0000C0   }, { op_TC2,     0                }, { op_ACy,    0x000030   }}},
  { 0xDE0002,   0xFF000F,   3, TMS320C55_addsubcc4, {{ op_Smem,     0x00FF00         }, { op_ACx,        0x0000C0   }, { op_TC1,     0                }, { op_TC2,    0,         }, { op_ACy,     0x000030   }}},
  { 0xDE0003,   0xFF000F,   3, TMS320C55_subc2,     {{ op_Smem,     0x00FF00         }, { op_ACx,        0x0000C0   }, { opt_ACy,    0x000030         }}},
  { 0xDE0004,   0xFF000F,   3, TMS320C55_add2,      {{ op_Smem,     0x00FF00         }, { shl_16,        0          }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xDE0005,   0xFF000F,   3, TMS320C55_sub2,      {{ op_Smem,     0x00FF00         }, { shl_16,        0          }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xDE0006,   0xFF000F,   3, TMS320C55_sub3,      {{ op_ACx,      0x0000C0         }, { op_Smem,       0x00FF00   }, { shl_16,     0                }, { op_ACy,    0x000030   }}},
  { 0xDE0008,   0xFF000F,   3, TMS320C55_addsub,    {{ op_Tx,       0x0000C0         }, { op_Smem,       0x00FF00   }, { op_ACx,     0x000030         }}},
  { 0xDE0009,   0xFF000F,   3, TMS320C55_subadd,    {{ op_Tx,       0x0000C0         }, { op_Smem,       0x00FF00   }, { op_ACx,     0x000030         }}},
  { 0xDF0000,   0xFF000E,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { fn_hb,         OP_TRUE    }, { fn_uns,     OP_NOT(0x000001) }, { op_dst,    0x0000F0   }}},
  { 0xDF0002,   0xFF000E,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { fn_lb,         OP_TRUE    }, { fn_uns,     OP_NOT(0x000001) }, { op_dst,    0x0000F0   }}},
  { 0xDF0004,   0xFF000E,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { fn_uns,        0x000001   }, { op_ACx,     0x000030         }}},
  { 0xDF0008,   0xFF000E,   3, TMS320C55_add3,      {{ op_Smem,     0x00FF00         }, { fn_uns,        0x000001   }, { op_CARRY,   0                }, { op_ACx,    0x0000C0   }, { opt_ACy,    0x000030   }}},
  { 0xDF000A,   0xFF000E,   3, TMS320C55_sub3,      {{ op_Smem,     0x00FF00         }, { fn_uns,        0x000001   }, { op_BORROW,  0                }, { op_ACx,    0x0000C0   }, { opt_ACy,    0x000030   }}},
  { 0xDF000C,   0xFF000E,   3, TMS320C55_add2,      {{ op_Smem,     0x00FF00         }, { fn_uns,        0x000001   }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xDF000E,   0xFF000E,   3, TMS320C55_sub2,      {{ op_Smem,     0x00FF00         }, { fn_uns,        0x000001   }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xE00000,   0xFF0000,   3, TMS320C55_btst,      {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TCx,     0x000001         }}},
  { 0xE10000,   0xFF0000,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { fn_lb,         OP_TRUE    }, { slo_SHIFTW, 0x00003F         }, { op_ACx,    0x0000C0   }}},
  { 0xE20000,   0xFF0000,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { fn_hb,         OP_TRUE    }, { slo_SHIFTW, 0x00003F         }, { op_ACx,    0x0000C0   }}},
  { 0xE30000,   0xFF000E,   3, TMS320C55_btstset,   {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TC1                       }}},
  { 0xE30002,   0xFF000E,   3, TMS320C55_btstset,   {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TC2                       }}},
  { 0xE30004,   0xFF000E,   3, TMS320C55_btstclr,   {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TC1                       }}},
  { 0xE30006,   0xFF000E,   3, TMS320C55_btstclr,   {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TC2                       }}},
  { 0xE30008,   0xFF000E,   3, TMS320C55_btstnot,   {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TC1                       }}},
  { 0xE3000A,   0xFF000E,   3, TMS320C55_btstnot,   {{ op_k4,       0x0000F0         }, { op_Smem,       0x00FF00   }, { op_TC2                       }}},
  { 0xE3000C,   0xFF000F,   3, TMS320C55_bset2,     {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }}},
  { 0xE3000D,   0xFF000F,   3, TMS320C55_bclr2,     {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }}},
  { 0xE3000E,   0xFF000E,   3, TMS320C55_bnot,      {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }}},
  { 0xE40000,   0xFF0004,   3, TMS320C55_psh2,      {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }}},
  { 0xE40004,   0xFF0004,   3, TMS320C55_pop2,      {{ op_dst,      0x0000F0         }, { op_Smem,       0x00FF00   }}},
  { 0xE50004,   0xFF000D,   3, TMS320C55_mov2,      {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }, { fn_hb,      OP_TRUE          }}},
  { 0xE50005,   0xFF000D,   3, TMS320C55_mov2,      {{ op_src,      0x0000F0         }, { op_Smem,       0x00FF00   }, { fn_lb,      OP_TRUE          }}},
  { 0xE50008,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_DP,       0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50018,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_CDP,      0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50028,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BSA01,    0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50038,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BSA23,    0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50048,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BSA45,    0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50058,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BSA67,    0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50068,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BSAC,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50078,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_SP,       0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50088,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_SSP,      0                }, { op_Smem,       0x00FF00   }}},
  { 0xE50098,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BK03,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE500A8,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BK47,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE500B8,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_BKC,      0                }, { op_Smem,       0x00FF00   }}},
  { 0xE500C8,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_DPH,      0                }, { op_Smem,       0x00FF00   }}},
  { 0xE500D8,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_MDP05,    0                }, { op_Smem,       0x00FF00   }}},
  { 0xE500E8,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_MDP67,    0                }, { op_Smem,       0x00FF00   }}},
  { 0xE500F8,   0xFF00FC,   3, TMS320C55_mov2,      {{ op_PDP,      0                }, { op_Smem,       0x00FF00   }}},
  { 0xE5000C,   0xFF007C,   3, TMS320C55_mov2,      {{ op_CSR,      0                }, { op_Smem,       0x00FF00   }}},
  { 0xE5001C,   0xFF007C,   3, TMS320C55_mov2,      {{ op_BRC0,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE5002C,   0xFF007C,   3, TMS320C55_mov2,      {{ op_BRC1,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE5003C,   0xFF007C,   3, TMS320C55_mov2,      {{ op_TRN0,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE5004C,   0xFF007C,   3, TMS320C55_mov2,      {{ op_TRN1,     0                }, { op_Smem,       0x00FF00   }}},
  { 0xE60000,   0xFF0000,   3, TMS320C55_mov2,      {{ op_K8,       0x0000FF         }, { op_Smem,       0x00FF00   }}},
  { 0xE70000,   0xFF000C,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { shl_Tx,        0x000030   }, { op_Smem,    0x00FF00         }}},
  { 0xE70008,   0xFF000C,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { shl_Tx,        0x000030   }, { fn_hi,      OP_TRUE,         }, { fn_rnd,    0x000001   }, { op_Smem,    0x00FF00   }}},
  { 0xE7000C,   0xFF000C,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { shl_Tx,        0x000030   }, { fn_sat,     OP_TRUE,         }, { fn_hi,     OP_TRUE    }, { fn_rnd,     0x000001   }, { fn_uns,    0x000002   }, { op_Smem,   0x00FF00   }}},
  { 0xE80000,   0xFF0004,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { fn_hi,         OP_TRUE    }, { fn_rnd,     0x000001         }, { op_Smem,   0x00FF00   }}},
  { 0xE80004,   0xFF0004,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { fn_sat,        OP_TRUE    }, { fn_hi,      OP_TRUE          }, { fn_rnd,    0x000001   }, { fn_uns,     0x000002   }, { op_Smem,   0x00FF00   }}},
  { 0xE90000,   0xFF0000,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { shl_SHIFTW,    0x00003F   }, { op_Smem,    0x00FF00         }}},
  { 0xEA0000,   0xFF0000,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000C0         }, { shl_SHIFTW,    0x00003F   }, { fn_hi,      OP_TRUE          }, { op_Smem,   0x00FF00   }}},
  { 0xEB0004,   0xFF000D,   3, TMS320C55_mov2,      {{ op_RETA,     0                }, { op_Lmem,       0x00FF00   }, { fn_dbl,     OP_TRUE          }}},
  { 0xEB0005,   0xFF000D,   3, TMS320C55_mov2,      {{ op_xsrc,     0x0000F0         }, { op_Lmem,       0x00FF00   }, { fn_dbl,     OP_TRUE          }}}, // not in documentation
  { 0xEB0008,   0xFF000D,   3, TMS320C55_mov2,      {{ op_ACx,      0x000030         }, { op_Lmem,       0x00FF00   }, { fn_dbl,     OP_TRUE          }}},
  { 0xEB0009,   0xFF000D,   3, TMS320C55_mov2,      {{ op_ACx,      0x000030         }, { fn_sat,        OP_TRUE    }, { fn_uns,     0x000002         }, { op_Lmem,   0x00FF00   }, { fn_dbl,     OP_TRUE    }}},
  { 0xEB000C,   0xFF000F,   3, TMS320C55_mov2,      {{ op_TAx,      0x0000F0         }, { fn_pair,       OP_TRUE    }, { op_Lmem,    0x00FF00         }, { fn_dbl,    OP_TRUE    }}},
  { 0xEB000D,   0xFF000F,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000F0         }, { shr,           OP_IMM(1)  }, { op_Lmem,    0x00FF00         }, { fn_dual,   OP_TRUE    }}},
  { 0xEB000E,   0xFF000F,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000F0         }, { fn_hi,         OP_TRUE    }, { fn_pair,    OP_TRUE          }, { op_Lmem,   0x00FF00   }, { fn_dbl,     OP_TRUE    }}},
  { 0xEB000F,   0xFF000F,   3, TMS320C55_mov2,      {{ op_ACx,      0x0000F0         }, { fn_lo,         OP_TRUE    }, { fn_pair,    OP_TRUE          }, { op_Lmem,   0x00FF00   }, { fn_dbl,     OP_TRUE    }}},
  { 0xEC0000,   0xFF000E,   3, TMS320C55_bset2,     {{ op_Baddr,    0x00FF00         }, { op_src,        0x0000F0   }}},
  { 0xEC0002,   0xFF000E,   3, TMS320C55_bclr2,     {{ op_Baddr,    0x00FF00         }, { op_src,        0x0000F0   }}},
  { 0xEC0004,   0xFF000E,   3, TMS320C55_btstp,     {{ op_Baddr,    0x00FF00         }, { op_src,        0x0000F0   }}},
  { 0xEC0006,   0xFF000E,   3, TMS320C55_bnot,      {{ op_Baddr,    0x00FF00         }, { op_src,        0x0000F0   }}},
  { 0xEC0008,   0xFF000E,   3, TMS320C55_btst,      {{ op_Baddr,    0x00FF00         }, { op_src,        0x0000F0   }, { op_TCx,     0x000001         }}},
  { 0xEC000E,   0xFF000F,   3, TMS320C55_amar2,     {{ op_Smem,     0x00FF00         }, { op_xdst,       0x0000F0   }}},
  { 0xED0000,   0xFF000E,   3, TMS320C55_add2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xED0002,   0xFF000E,   3, TMS320C55_sub2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xED0004,   0xFF000E,   3, TMS320C55_sub3,      {{ op_ACx,      0x0000C0         }, { op_Lmem,       0x00FF00   }, { fn_dbl,     OP_TRUE          }, { op_ACy,    0x000030   }}},
  { 0xED0006,   0xFF000E,   3, TMS320C55_mov2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_RETA,    0                }}},
  { 0xED0008,   0xFF000E,   3, TMS320C55_mov2,      {{ insn_1_40,    0x000001         }, { op_Lmem,       0x00FF00   }, { fn_dbl,     OP_TRUE          }, { op_ACx,    0x000030   }}},
  { 0xED000A,   0xFF000E,   3, TMS320C55_mov2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_ACx,     0x000030         }, { fn_hi,     OP_TRUE,   }, { fn_pair,    OP_TRUE    }}},
  { 0xED000C,   0xFF000E,   3, TMS320C55_mov2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_ACx,     0x000030         }, { fn_lo,     OP_TRUE,   }, { fn_pair,    OP_TRUE    }}},
  { 0xED000E,   0xFF000F,   3, TMS320C55_mov2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_TAx,     0x0000F0         }, { fn_pair,   OP_TRUE    }}},
  { 0xED000F,   0xFF000F,   3, TMS320C55_mov2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_xdst,    0x0000F0         }}},
  { 0xEE0000,   0xFF000E,   3, TMS320C55_add2,      {{ op_Lmem,     0x00FF00         }, { fn_dual,       OP_TRUE    }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xEE0002,   0xFF000E,   3, TMS320C55_sub2,      {{ op_Lmem,     0x00FF00         }, { fn_dual,       OP_TRUE    }, { op_ACx,     0x0000C0         }, { opt_ACy,   0x000030   }}},
  { 0xEE0004,   0xFF000E,   3, TMS320C55_sub3,      {{ op_Lmem,     0x00FF00         }, { fn_dual,       OP_TRUE    }, { op_ACx,     0x0000C0         }, { op_ACy,    0x000030   }}},
  { 0xEE0006,   0xFF000E,   3, TMS320C55_sub3,      {{ op_Lmem,     0x00FF00         }, { fn_dual,       OP_TRUE    }, { op_Tx,      0x0000C0         }, { op_ACx,    0x000030   }}},
  { 0xEE0008,   0xFF000E,   3, TMS320C55_add3,      {{ op_Lmem,     0x00FF00         }, { fn_dual,       OP_TRUE    }, { op_Tx,      0x0000C0         }, { op_ACx,    0x000030   }}},
  { 0xEE000A,   0xFF000E,   3, TMS320C55_sub3,      {{ op_Tx,       0x0000C0         }, { op_Lmem,       0x00FF00   }, { fn_dual,    OP_TRUE          }, { op_ACx,    0x000030   }}},
  { 0xEE000C,   0xFF000E,   3, TMS320C55_addsub,    {{ op_Tx,       0x0000C0         }, { op_Lmem,       0x00FF00   }, { fn_dual,    OP_TRUE          }, { op_ACx,    0x000030   }}},
  { 0xEE000E,   0xFF000E,   3, TMS320C55_subadd,    {{ op_Tx,       0x0000C0         }, { op_Lmem,       0x00FF00   }, { fn_dual,    OP_TRUE          }, { op_ACx,    0x000030   }}},
  { 0xEF0000,   0xFF000C,   3, TMS320C55_mov2,      {{ op_Cmem,     0x000003         }, { op_Smem,       0x00FF00   }}},
  { 0xEF0004,   0xFF000C,   3, TMS320C55_mov2,      {{ op_Smem,     0x00FF00         }, { op_Cmem,       0x000003   }}},
  { 0xEF0008,   0xFF000C,   3, TMS320C55_mov2,      {{ op_Cmem,     0x000003         }, { op_Lmem,       0x00FF00   }, { fn_dbl,     OP_TRUE          }}},
  { 0xEF000C,   0xFF000C,   3, TMS320C55_mov2,      {{ op_Lmem,     0x00FF00         }, { fn_dbl,        OP_TRUE    }, { op_Cmem,    0x000003         }}},
  { 0xF0000000, 0xFF000000, 4, TMS320C55_cmp,       {{ op_Smem,     0x00FF0000       }, { eq_K16,        0x0000FFFF }, { op_TC1,     0                }}},
  { 0xF1000000, 0xFF000000, 4, TMS320C55_cmp,       {{ op_Smem,     0x00FF0000       }, { eq_K16,        0x0000FFFF }, { op_TC2,     0                }}},
  { 0xF2000000, 0xFF000000, 4, TMS320C55_band,      {{ op_Smem,     0x00FF0000       }, { op_k16,        0x0000FFFF }, { op_TC1,     0                }}},
  { 0xF3000000, 0xFF000000, 4, TMS320C55_band,      {{ op_Smem,     0x00FF0000       }, { op_k16,        0x0000FFFF }, { op_TC2,     0                }}},
  { 0xF4000000, 0xFF000000, 4, TMS320C55_and2,      {{ op_k16,      0x0000FFFF       }, { op_Smem,       0x00FF0000 }}},
  { 0xF5000000, 0xFF000000, 4, TMS320C55_or2,       {{ op_k16,      0x0000FFFF       }, { op_Smem,       0x00FF0000 }}},
  { 0xF6000000, 0xFF000000, 4, TMS320C55_xor2,      {{ op_k16,      0x0000FFFF       }, { op_Smem,       0x00FF0000 }}},
  { 0xF7000000, 0xFF000000, 4, TMS320C55_add2,      {{ op_K16,      0x0000FFFF       }, { op_Smem,       0x00FF0000 }}},
  { 0xF8000000, 0xFF000004, 4, TMS320C55_mpymk,     {{ insn_1_R,     0x00000001       }, { op_Smem,       0x00FF0000 }, { fn_T3,      0x00000002       }, { op_K8,     0x0000FF00 }, { op_ACx,     0x00000030 }}},
  { 0xF8000004, 0xFF000004, 4, TMS320C55_macmk3,    {{ insn_1_R,     0x00000001       }, { op_Smem,       0x00FF0000 }, { fn_T3,      0x00000002       }, { op_K8,     0x0000FF00 }, { op_ACx,     0x000000C0 }, { opt_ACy,   0x00000030 }}},
  { 0xF9000000, 0xFF00000C, 4, TMS320C55_add2,      {{ op_Smem,     0x00FF0000       }, { fn_uns,        0x00008000 }, { slo_SHIFTW, 0x00003F00       }, { op_ACx,    0x000000C0 }, { opt_ACy,    0x00000030 }}},
  { 0xF9000004, 0xFF00000C, 4, TMS320C55_sub2,      {{ op_Smem,     0x00FF0000       }, { fn_uns,        0x00008000 }, { slo_SHIFTW, 0x00003F00       }, { op_ACx,    0x000000C0 }, { opt_ACy,    0x00000030 }}},
  { 0xF9000008, 0xFF00000C, 4, TMS320C55_mov2,      {{ op_Smem,     0x00FF0000       }, { fn_uns,        0x00008000 }, { slo_SHIFTW, 0x00003F00       }, { op_ACx,    0x00000030 }}},
  { 0xFA000000, 0xFF000004, 4, TMS320C55_mov2,      {{ op_ACx,      0x000000C0       }, { shl_SHIFTW,    0x00003F00 }, { fn_hi,      OP_TRUE          }, { fn_rnd,    0x00000001 }, { op_Smem,    0x00FF0000 }}},
  { 0xFA000004, 0xFF000004, 4, TMS320C55_mov2,      {{ op_ACx,      0x000000C0       }, { shl_SHIFTW,    0x00003F00 }, { fn_sat,     OP_TRUE          }, { fn_hi,     OP_TRUE    }, { fn_rnd,     0x00000001 }, { fn_uns,    0x00008000 }, { op_Smem,   0x00FF0000 }}},
  { 0xFB000000, 0xFF000000, 4, TMS320C55_mov2,      {{ op_K16,      0x0000FFFF       }, { op_Smem,       0x00FF0000 }}},
  { 0xFC000000, 0xFF000000, 4, TMS320C55_bcc,       {{ op_L16,      0x0000FFFF       }, { op_ARn_mod,    0x00FF0000 }, { neq_0,      OP_TRUE          }}},
  { 0, 0, 0, TMS320C55_null  }
};

//--------------------------------------------------------------------------
// unpack an "sdual" instruction operand ( 6->8 bits )
static uchar unpack_opsdual(uchar packed)
{
  static const uchar lowpart[8] = { 0, 1, 2, 3, 9, 4, 10, 5 };
  return ((lowpart[packed&7] | ((packed<<1) & 0x70)) << 1) | 1;
}

//--------------------------------------------------------------------------
// unpack an "sdual" instruction
// these are probably instructions from C55x+ processor
static bool unpack_sdual(ea_t ea, bytevec_t *insn1, bytevec_t *insn2)
{
  // sdual instruction packs two parallel instructions
  uint32 word = 0;
  for ( int i=0; i < 4; i++ )
    word = (word << 8) | get_byte(ea + i);
  uchar opc1 = ((word >> 20) & 0xF0) | ((word >> 8) & 0x0F);
  uchar opc2 = (word & 0xFF);
  if ( opc2 & 0x80 )
  {
    //  3       |   2     |       1 |
    // 1098 7654|321098 76|5432 1098|76543210
    //          |         |         |
    // 1000 1011|100010 10|1001 1100|11000001
    //      o1h | opd1   opd2    o1l|   opc2
    //
    //  opcode1 = o1h:o1l
    //  opcode2 = opc2
    //  opd1 and opd2 are packed operand parts

    uchar ops1 = (word >> 18) & 0x3F;
    uchar ops2 = (word >> 12) & 0x3F;
    int insn1_len = get_insn_size(masks, opc1<<24);
    if ( insn1_len < 2 )
      return false;
    int insn2_len = get_insn_size(masks, opc2<<24);
    if ( insn2_len < 2 )
    {
      // try to add extra bytes (skip operand byte)
      uint32 w2 = (opc2<<24) | (get_byte(ea + insn1_len+2) << 8);
      insn2_len = get_insn_size(masks, w2);
      if ( insn2_len < 2 )
      {
        w2 |= get_byte(ea + insn1_len+3);
        insn2_len = get_insn_size(masks, w2);
      }
    }
    if ( insn2_len < 2 )
      return false;
    if ( insn1 )
    {
      insn1->clear();
      // add real opcode and operands
      insn1->push_back(opc1);
      insn1->push_back(unpack_opsdual(ops1));
      // add extra bytes
      for ( int i=4; i < insn1_len+2; i++ )
        insn1->push_back(get_byte(ea + i));
    }
    if ( insn2 )
    {
      insn2->clear();
      insn2->push_back(opc2);
      insn2->push_back(unpack_opsdual(ops2));
      for ( int i=insn1_len+2; i < (insn1_len+insn2_len); i++ )
        insn2->push_back(get_byte(ea + i));
    }
  }
  else
  {
    // unpacked insn1 can be 2, 3, or 4 bytes
    // insn2 is always 3 bytes
    //
    // source bytes: ab cd ef gh  ij kl mn op
    // case 2+3:
    //  insn1 = bf cd
    //  insn2 = g4 ij eh
    // case 3+3:
    //  insn1 = bf cd ij
    //  insn2 = g4 kl eh
    // case 4+3:
    //  insn1 = bf cd ij kl
    //  insn2 = g4 mn eh
    uint32 w1 = (opc1<<24) | (word & 0x00FF0000); // bfcd0000
    uint32 w2 = (((word&0xF0)|4)<<24) | (word&0xF000) | ((word&0x0F)<<8); // g400eh00
    int insn1_len = get_insn_size(masks, w1);
    if ( insn1_len == 0 )
    {
      // try to add one byte
      w1 |= (get_byte(ea + 4) << 8);
      insn1_len = get_insn_size(masks, w1);
      if ( insn1_len == 0 || insn1_len < 3 )
      {
        w1 |= get_byte(ea + 5);
        insn1_len = get_insn_size(masks, w1);
        if ( insn1_len != 4 )
          return false;
      }
    }
    int insn2_len = get_insn_size(masks, w2);
    if ( insn1_len < 2 || insn2_len != 3 )
      return false;
    if ( insn1 )
    {
      insn1->clear();
      insn1->push_back((w1>>24)&0xFF);
      insn1->push_back((w1>>16)&0xFF);
      // add extra bytes
      for ( int i=4; i < insn1_len + 2; i++ )
        insn1->push_back(get_byte(ea + i));
    }
    if ( insn2 )
    {
      insn2->clear();
      insn2->push_back((w2>>24)&0xFF);
      insn2->push_back(get_byte(ea + insn1_len + 2));
      insn2->push_back((w2>>8)&0xFF);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
void ana_status_bits(insn_t &insn)
{
  if ( (insn.itype == TMS320C55_bclr2 || insn.itype == TMS320C55_bset2)
    && insn.Op2.type == o_reg
    && insn.Op1.type == o_imm )
  {
    int reg = -1;
    switch ( insn.Op2.reg )
    {
      case ST0_55:
        {
          static const int regs[] =
          {
            -1, -1,    -1,    -1,    -1,  -1,  -1,    -1,
            -1, ACOV1, ACOV0, CARRY, TC2, TC1, ACOV3, ACOV2
          };
          reg = regs[int(insn.Op1.value)];
          break;
        }
      case ST1_55:
        {
          static const int regs[] =
          {
            -1,   -1,    -1,   -1,   -1,   C54CM, FRCT, C16,
            SXMD, SATD,  M40,  INTM, HM,   XF,    CPL,  BRAF
          };
          reg = regs[int(insn.Op1.value)];
          break;
        }
      case ST2_55:
        {
          static const int regs[] =
          {
            AR0LC, AR1LC, AR2LC, AR3LC,  AR4LC, AR5LC, AR6LC, AR7LC,
            CDPLC, -1,    RDM,   EALLOW, DBGM,  -1,    -1,    ARMS
          };
          reg = regs[int(insn.Op1.value)];
          break;
        }
      case ST3_55:
        {
          static const int regs[] =
          {
            SST, SMUL, CLKOFF, -1, -1,   SATA,  MPNMC, CBERR,
            -1,  -1,   -1,     -1, HINT, CACLR, CAEN,  CAFRZ
          };
          reg = regs[int(insn.Op1.value)];
          break;
        }
    }
    if ( reg != -1 )
    {
      insn.itype = (insn.itype == TMS320C55_bclr2) ? TMS320C55_bclr1 : TMS320C55_bset1;
      insn.Op1.type = o_reg;
      insn.Op1.reg = uint16(reg);
      insn.Op2.type = o_void;
    }
  }
}

//--------------------------------------------------------------------------
int tms320c55_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  optional_op = -1;
  bytes_c bytes(insn);
  uchar firstbyte = bytes.get_next();

  int sdual_len = helper.altval_ea(insn.ea, TAG_SDUAL);
  if ( sdual_len != 0 )
  {
    // this is a second part of sdual instruction
    bytevec_t insn_bytes;
    if ( !unpack_sdual(insn.ea - sdual_len, nullptr, &insn_bytes) )
      return 0;
    bytes.set_cache(insn_bytes);
    process_masks(insn, masks, TMS320C55_null, bytes, 8); // analyze opcode
    if ( insn.itype == TMS320C55_null || insn.size != insn_bytes.size() )
      return 0;
    ana_status_bits(insn);
    insn.SpecialModes |= TMS_MODE_USER_PARALLEL;
    return insn.size;
  }
  else
  {
    // a normal instruction ?
    process_masks(insn, masks, TMS320C55_null, bytes, 8); // analyze opcode
    if ( insn.size != 0 && insn.itype != TMS320C55_null )
    {
      helper.altdel_ea(insn.ea + insn.size, TAG_SDUAL);
    }
    else if ( (firstbyte & 0xF8) == 0x88 )
    {
      // "sdual" instruction; unpack it
      bytevec_t insn_bytes;
      if ( !unpack_sdual(insn.ea, &insn_bytes, nullptr) )
        return 0;
      bytes.set_cache(insn_bytes);
      process_masks(insn, masks, TMS320C55_null, bytes, 8); // analyze opcode
      if ( insn.itype != TMS320C55_null && insn.size == insn_bytes.size() )
      {
        ana_status_bits(insn);
        // remember that next address is the second part
        helper.altset_ea(insn.ea + insn.size, insn.size, TAG_SDUAL);
        return insn.size;
      }
    }
  }

  // analyze special bits access
  ana_status_bits(insn);

  // analyze user-parallelized instructions
  if ( firstbyte <= MAX_BYTE_USER_PARALLELIZED && (firstbyte & 1) ) // instruction has E bit set
    insn.SpecialModes |= TMS_MODE_USER_PARALLEL;

  // analyze postfixes
  uchar nextbyte = get_byte(insn.ea+insn.size); // is_mapped() not necessary here
  switch ( nextbyte )
  {
    case BYTE_MMAP: // mmap()
      if ( insn.OpMem != 0 )
      {
        int n = insn.OpMem - 1;
        if ( insn.ops[n].type == o_mem
          && insn.ops[n].tms_regH == DPH
          && insn.ops[n].tms_regP == DP
          && insn.ops[n].tms_modifier == TMS_MODIFIER_DMA )
        { // @dma using DP
          insn.ops[n].tms_regH     = 0;
          insn.ops[n].tms_regP     = 0;
          insn.ops[n].tms_modifier = TMS_MODIFIER_MMAP;
          insn.size++;
        }
        else if ( insn.ops[n].type == o_reg
               && insn.ops[n].reg == SP
               && insn.ops[n].tms_modifier == TMS_MODIFIER_REG_OFFSET )
        { // @dma using SP
          insn.ops[n].addr         = insn.ops[n].value;
          insn.ops[n].type         = o_mem;
          insn.ops[n].tms_regH     = 0;
          insn.ops[n].tms_regP     = 0;
          insn.ops[n].tms_modifier = TMS_MODIFIER_MMAP;
          insn.size++;
        }
      }
      break;
    case BYTE_PORT1:
    case BYTE_PORT2: // port()
      if ( insn.OpMem != 0 )
      {
        int n = insn.OpMem - 1;
        switch ( insn.ops[n].type )
        {
          case o_mem:
            insn.ops[n].type         = o_io;
            insn.ops[n].tms_regH     = 0;
            insn.ops[n].tms_regP     = PDP;
            insn.ops[n].addr         = insn.ops[n].addr >> 1;
            insn.ops[n].tms_modifier = TMS_MODIFIER_PORT_AT;
            insn.size++;
            break;
          case o_reg:
            insn.ops[n].tms_operator1 |= TMS_OPERATOR_PORT & 0xFF;
            insn.ops[n].tms_operator2 |= (TMS_OPERATOR_PORT >> 8);
            insn.size++;
            break;
        }
      }
      break;
    case BYTE_LR:
    case BYTE_CR: // .lr & .cr
      insn.SpecialModes |= nextbyte == BYTE_LR ? TMS_MODE_LR : TMS_MODE_CR;
      insn.size++;
      break;
  }
  if ( insn.itype == TMS320C55_null )
    return 0;
  return insn.size;
}
