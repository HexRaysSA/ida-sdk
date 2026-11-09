/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Fujitsu's F2MC
 *
 */

#include "f2mc.hpp"
#include <segregs.hpp>

//--------------------------------------------------------------------------
// function to generate an operand
typedef void (*func_op_t)(const struct map_t *, int offset, op_t &op, insn_t &insn);

struct map_t
{
  const map_t *next; // map for next opcode byte
  int code;       // first opcode of instruction range
  ushort itype;   // itype of instruction
  func_op_t op1;  //lint !e958 padding is required to align members
                  // function to set Op1
  func_op_t op2;  // function to set Op2
  func_op_t op3;  // function to set Op3
  char priority1; // first operand to inc (1..3)
  char size1;     // maximum size of the first operand
  char priority2;
  char size2;
  char priority3;
  char size3;
};
// operands increments priority (OP_first_second_...)
#define OP_NULL 0, 0, 0, 0, 0, 0
#define OP_1_2(SIZE1) 1, SIZE1, 2, 0, 0, 0
#define OP_2_1(SIZE2) 2, SIZE2, 1, 0, 0, 0
#define OP_3_1(SIZE3) 3, SIZE3, 1, 0, 0, 0
#define OP_3_2(SIZE3) 3, SIZE3, 2, 0, 0, 0


//--------------------------------------------------------------------------
// analyze code by processing map

static const map_t *process_map(insn_t &insn, int code, const map_t *map, int itype_null)
{
  // search for the good opcode range
  const map_t *p = map;
  while ( ((p+1)->code != 0 || (p+1)->itype != 0)
       && code >= (p+1)->code )
  {
    p++; // loop until p->code <= code < (p+1)->code
  }
  if ( insn.itype == itype_null )
    insn.itype = p->itype; // define itype if not already defined

  // compute operand offsets
  int offset = code - p->code, offsets[3];
  for ( int i=0; i < 3; i++ )
    offsets[i] = offset;
  if ( p->priority1 )
  {
    if ( p->size1 )
      offsets[p->priority1 - 1] = offset % p->size1;
    if ( p->priority2 )
    {
      offset /= p->size1;
      offsets[p->priority2 - 1] = offset;
      if ( p->size2 )
        offsets[p->priority2 - 1] = offset % p->size2;
      if ( p->priority3 )
      {
        offset /= p->size2;
        offsets[p->priority3 - 1] = offset;
        if ( p->size3 )
          offsets[p->priority3 - 1] = offset % p->size3;
      }
    }
  }

  // process operands
  if ( p->op1 != nullptr )
    p->op1(p, offsets[0], insn.Op1, insn);
  if ( p->op2 != nullptr )
    p->op2(p, offsets[1], insn.Op2, insn);
  if ( p->op3 != nullptr )
    p->op3(p, offsets[2], insn.Op3, insn);
  return p->next;
}

//--------------------------------------------------------------------------
// analyze code by processing all necessary maps
static void process_maps(insn_t &insn, const map_t *map, uint16 itype_null)
{
  insn.itype = itype_null;
  insn.size  = 0;
  while ( map ) // while we must analyze a new map
  {
    int code = insn.get_next_byte();
    map = process_map(insn, code, map, itype_null); // analyze this byte
  }
}

//--------------------------------------------------------------------------
// class to store an instructions cache
#define CMDS_SIZE 3 // maximum cache size (maximum number of instructions)
class cmds_t
{
private:
  insn_t insns[CMDS_SIZE];
  int size;
  int i;
public:
  void reset(void) { i = 0; }
  //lint -sem(cmds_t::reload,initializer)
  void reload(const insn_t &insn) { insns[0] = insn; size = 1; reset(); }
  cmds_t(const insn_t &insn) { reload(insn); }    //lint !e1566 'cmds_t::i' may have been initialized in a separate method
  const insn_t *get_next(void);
  const insn_t *get(int j) const;
};

// get the next instruction
const insn_t *cmds_t::get_next(void)
{
  if ( i == size )
  {
    // if ( size >= CACHE_SIZE ) return nullptr;
    // load a new instruction into the cache
    if ( size <= 0 )
      return nullptr;
    ea_t ea = insns[size-1].ea + insns[size-1].size;
    if ( decode_insn(&insns[size], ea) < 1 )
      return nullptr;
    size++;
  }
  return &insns[i++];
}

//--------------------------------------------------------------------------
// get an instruction already in the cache
const insn_t *cmds_t::get(int j) const
{
  // if ( j >= size ) return nullptr;
  return &insns[j];
}

// function to check the validity of an operand
typedef bool (*func_is_op_t)(const insn_t *insn, const op_t &op);

struct macro_insn_t
{
  func_is_op_t op1; // function to check Op1
  func_is_op_t op2; // function to check Op2
  func_is_op_t op3; // function to check Op3
  ushort itype;     // itype of instruction
};

struct macro_t
{
  const macro_insn_t *insns; // array of instructions
  ushort itype;        // itype of macro
  char cmd;            // indice (1..n) of the "base" cmd
  char op1_cmd;        // indice (1..n) of the cmd containing the 1st operand
  char op1_cmd_op;     // indice of the operand from the cmd containing the 1st operand
  char op2_cmd;
  char op2_cmd_op;
  char op3_cmd;
  char op3_cmd_op;
};
#define OP_VOID 0, 0
#define OP_CMD(CMD,OP) CMD, OP


//--------------------------------------------------------------------------
// build a macro and return true, or return cmd and return false
static bool build_macro(const macro_t *macros, int itype_null, insn_t &build, const insn_t &insn)
{
  build = insn;
  cmds_t cmds(insn);
  const macro_t *macro = macros;
  while ( macro->itype != itype_null ) // loop into macros array
  {
    const macro_insn_t *mdef = macro->insns;
    cmds.reset();
    int size = 0;
    while ( mdef->itype != itype_null ) // loop into instructions of the macro
    {
      const insn_t *pcmds = cmds.get_next(); // get the instruction
      if ( pcmds == nullptr )
        break;
      size += pcmds->size;
      // check if instructions and operands correspond
      if ( pcmds->itype != mdef->itype )
        break;
      if ( mdef->op1 && !mdef->op1(pcmds, pcmds->Op1) )
        break;
      if ( mdef->op2 && !mdef->op2(pcmds, pcmds->Op2) )
        break;
      if ( mdef->op3 && !mdef->op2(pcmds, pcmds->Op3) )
        break;
      if ( (mdef+1)->itype == itype_null ) // macro founded
      {
        ea_t ea = cmds.get(0)->ea;
        // check if an external Xrefs exists
        xrefblk_t xb;
        for ( ea_t i = ea; i < ea+size; i++ )
          for ( int ok = xb.first_to(i,XREF_FAR); ok; ok=xb.next_to() )
            if ( xb.from < ea || xb.from >= ea+size )
              return false; // external Xref founded

        // fill resulting insn_t
        build = *cmds.get(macro->cmd-1);
        build.ea    = ea;
        build.size  = (uint16)size;
        build.itype = macro->itype;
        if ( macro->op1_cmd )
          build.Op1 = cmds.get(macro->op1_cmd-1)->ops[macro->op1_cmd_op-1];
        else
          build.Op1.type = o_void;
        build.Op1.n = 1;
        if ( macro->op2_cmd )
          build.Op2 = cmds.get(macro->op2_cmd-1)->ops[macro->op2_cmd_op-1];
        else
          build.Op2.type = o_void;
        build.Op2.n = 2;
        if ( macro->op3_cmd )
          build.Op3 = cmds.get(macro->op3_cmd-1)->ops[macro->op3_cmd_op-1];
        else
          build.Op3.type = o_void;
        build.Op3.n = 3;
        return true;
      }
      mdef++;
    }
    macro++;
  }
  return false;
}

//--------------------------------------------------------------------------
// analyze cmd and next instructions to eventually detect a macro and update database
static void process_macros(insn_t &insn, const macro_t *macros, int itype_null, bool macro_on)
{
  if ( macro_on ) // try to build a macro
  {
    insn_t macro;
    if ( build_macro(macros, itype_null, macro, insn) )
      insn = macro; // a macro can be built
  }
  if ( is_head(get_flags(insn.ea))   // if not the first analyze
    && insn.size != get_item_size(insn.ea) ) // and the size of the instruction just changed
  {
    // reanalyze
    del_items(insn.ea, DELIT_SIMPLE, insn.size); // undefine preceding instructions
    auto_make_code(insn.ea);
  }
}

//--------------------------------------------------------------------------
// get the value of a bank
static sel_t get_bank_value(const insn_t &insn, int bank)
{
  sel_t sel;
  if ( bank != PCB )
  {
    if ( bank == SPB )
    {
      sel_t ccr = get_sreg(insn.ea, CCR);
      if ( ccr == BADSEL )
        ccr = 0;
      if ( ccr & 0x20 )
        bank = SSB;
      else
        bank = USB;
    }

    sel = get_sreg(insn.ea, bank);
    if ( sel == BADSEL )
      sel = 0;
  }
  else
  {
    sel = insn.cs;
  }
  return sel & 0xFF;
}

//--------------------------------------------------------------------------
// get the value of the bank used by the instruction (eventually with a prefix)
static sel_t get_insn_bank_value(const insn_t &insn)
{
  int bank = 0;
  if ( insn.prefix_bank )
    bank = insn.prefix_bank;
  else if ( insn.default_bank )
    bank = insn.default_bank;
  else
    error("interr: emu: get_insn_bank_value()");
  return get_bank_value(insn, bank);
}

//--------------------------------------------------------------------------
#define op_reg(REG,DTYP) \
  static void op_##REG(const map_t *, int, op_t &op, insn_t &) \
  {                                                  \
    op.type = o_reg;                                 \
    op.reg  = REG;                                   \
    op.dtype = dt_##DTYP;                             \
  }
op_reg(A,dword)  // op_A
op_reg(AH,word)  // op_AH
op_reg(AL,word)  // op_AL
op_reg(SP,word)  // op_SP
op_reg(PC,word)  // op_PC
op_reg(PCB,byte) // op_PCB
op_reg(DTB,byte) // op_DTB
op_reg(ADB,byte) // op_ADB
op_reg(SPB,byte) // op_SPB
op_reg(SSB,byte) // op_SSB
op_reg(USB,byte) // op_USB
op_reg(DPR,byte) // op_DPR
op_reg(PS,word)  // op_PS
op_reg(ILM,byte) // op_ILM
op_reg(RP,byte)  // op_RP
op_reg(CCR,byte) // op_CCR

#define op_regi(NAME,REG,DTYP)                                         \
  static void op_##NAME(const map_t *, int offset, op_t &op, insn_t &) \
  {                                                                    \
    op.type  = o_reg;                                                  \
    op.reg   = uint16(REG + offset);                                   \
    op.dtype = dt_##DTYP;                                              \
  }
op_regi(Ri,R0,byte)    // op_Ri
op_regi(RWi,RW0,word)  // op_RWi
op_regi(RLi,RL0,dword) // op_RLi
// special for EA RLi adressing mode

static void op_RLi2(const map_t *, int offset, op_t &op, insn_t &)
{
  op.type = o_reg;
  op.reg  = uint16(RL0 + (offset>>1));
  op.dtype = dt_dword;
}

#define op_at(OP,DEFAULT_BANK,DTYP) \
   static void op_##DTYP##_at_##OP(const map_t *map, int offset, op_t &op, insn_t &insn) \
   {                                                                     \
     op_##OP(map,offset,op,insn);                                        \
     insn.default_bank = DEFAULT_BANK;                                   \
     insn.op_bank = op.n;                                                \
     op.type = o_phrase;                                                 \
     op.at_qty++;                                                        \
     op.dtype = dt_##DTYP;                                               \
   }
op_at(A,DTB,byte)   // op_byte_at_A
op_at(A,DTB,word)   // op_word_at_A
op_at(A,DTB,code)   // op_code_at_A
op_at(AL,DTB,byte)  // op_byte_at_AL
op_at(AL,DTB,word)  // op_word_at_AL
// op_DTYP_at_RWi
op_at(RLi,0,byte)   // op_byte_at_RLi
op_at(RLi,0,word)   // op_word_at_RLi
// op_at(RLi,0,dword)  // op_dword_at_RLi
op_at(PC,PCB,byte)  // op_byte_at_PC
op_at(PC,PCB,word)  // op_word_at_PC
op_at(PC,PCB,dword) // op_dword_at_PC

#define op_at_RWi(DTYP) \
  static void op_##DTYP##_at_RWi(const map_t *map, int offset, op_t &op, insn_t &insn) \
  {                                                                      \
    op_RWi(map,offset,op,insn);                                          \
    op.type = o_phrase;                                                  \
    op.at_qty++;                                                         \
    op.dtype = dt_##DTYP;                                                \
    switch ( offset )                                                    \
    {                                                                    \
      case 0:                                                            \
      case 1:                                                            \
      case 4:                                                            \
      case 5:                                                            \
        insn.default_bank = DTB;                                         \
        break;                                                           \
      case 3:                                                            \
      case 7:                                                            \
        insn.default_bank = SPB;                                         \
        break;                                                           \
      case 2:                                                            \
      case 6:                                                            \
        insn.default_bank = ADB;                                         \
        break;                                                           \
    }                                                                    \
    insn.op_bank = op.n;                                                 \
  }
op_at_RWi(byte)
op_at_RWi(word)
op_at_RWi(dword)

#define op_imm(NAME,VALUE,DTYP,IN) \
  static void op_##NAME(const map_t *, int offset, op_t &op, insn_t &IN) \
  {                                                          \
    op.type  = o_imm;                                        \
    op.value = VALUE;                                        \
    op.dtype = dt_##DTYP;                                    \
  }
op_imm(imm4,offset,byte, /*insn*/) // op_imm4
#define offset
op_imm(imm8,insn.get_next_byte(),byte,insn)   // op_imm8
op_imm(imm16,insn.get_next_word(),word,insn)  // op_imm16
op_imm(imm32,insn.get_next_dword(),dword,insn) // op_imm32
#undef offset

#define op_dir(DTYP)                                                    \
  static void op_dir_##DTYP(const map_t *, int, op_t &op, insn_t &insn) \
  {                                                                     \
    insn.default_bank = DTB;                                            \
    insn.op_bank = op.n;                                                \
    op.type = o_mem;                                                    \
    op.dtype = dt_##DTYP;                                               \
    sel_t dpr = get_sreg(insn.ea, DPR);                                 \
    if ( dpr == BADSEL )                                                \
      dpr = 0;                                                          \
    op.addr = (get_insn_bank_value(insn) << 16) | ((dpr&0xFF) << 8) | insn.get_next_byte(); \
    op.addr_dtyp = 's'; \
  }
op_dir(byte)  // op_dir_byte
op_dir(word)  // op_dir_word
// op_dir(dword) // op_dir_dword

#define op_io(DTYP) \
  static void op_io_##DTYP(const map_t *, int, op_t &op, insn_t &insn) \
  {                                                      \
    op.type      = o_mem;                                \
    op.dtype     = dt_##DTYP;                            \
    op.addr      = insn.get_next_byte();                 \
    op.addr_dtyp = 'i';                                  \
  }
op_io(byte)  // op_io_byte
op_io(word)  // op_io_word
// op_io(dword) // op_io_dword

#define op_addr16(DEFAULT_BANK,TYPE,DTYP) \
  static void op_addr16_##DTYP(const map_t *, int, op_t &op, insn_t &insn) \
  {                                                                 \
    insn.default_bank = DEFAULT_BANK;                               \
    insn.op_bank = op.n;                                            \
    op.type = o_##TYPE;                                             \
    op.addr = (get_insn_bank_value(insn) << 16) | insn.get_next_word(); \
    op.dtype = dt_##DTYP;                                            \
  }
op_addr16(PCB, near, code) // op_addr16_code
op_addr16(DTB, mem, byte)  // op_addr16_byte
op_addr16(DTB, mem, word)  // op_addr16_word
op_addr16(DTB, mem, dword) // op_addr16_dword

#define op_bp(NAME,OP) \
  static void op_bp_##NAME(const map_t *map, int offset, op_t &op, insn_t &insn) \
  {                                                                \
    op_##OP(map,offset,op,insn);                                   \
    op.special_mode = MODE_BIT;                                    \
    op.byte_bit     = uchar(offset);                               \
  }
op_bp(io,io_byte)         // op_bp_io
op_bp(dir,dir_byte)       // op_bp_dir
op_bp(addr16,addr16_byte) // op_bp_addr16

#define op_at_RWi_inc(DTYP) \
  static void op_##DTYP##_at_RWi_inc(const map_t *map, int offset, op_t &op, insn_t &insn) \
  {                                            \
    op_##DTYP##_at_RWi(map, offset, op, insn); \
    op.special_mode = MODE_INC;                \
  }
op_at_RWi_inc(byte)  // op_byte_at_RWi_inc
op_at_RWi_inc(word)  // op_word_at_RWi_inc
op_at_RWi_inc(dword) // op_dword_at_RWi_inc

#define op_at_reg_displ(NAME,REG,VALUE,VALUE_DTYP,DTYP) \
  static void op_##DTYP##_at_##REG##_##NAME(const map_t *map, int offset, op_t &op, insn_t &insn) \
  {                                                                                 \
    op_##DTYP##_at_##REG(map,offset,op,insn);                                       \
    op.type       = o_displ;                                                        \
    op.addr       = VALUE;                                                          \
    op.addr_dtyp  = dt_##VALUE_DTYP;                                                \
  }
op_at_reg_displ(disp8,RWi,get_signed(insn.get_next_byte(),0xFF),byte,byte)     // op_byte_at_RWi_disp8
op_at_reg_displ(disp8,RWi,get_signed(insn.get_next_byte(),0xFF),byte,word)     // op_word_at_RWi_disp8
op_at_reg_displ(disp8,RWi,get_signed(insn.get_next_byte(),0xFF),byte,dword)    // op_dword_at_RWi_disp8
op_at_reg_displ(disp16,RWi,get_signed(insn.get_next_word(),0xFFFF),word,byte)  // op_byte_at_RWi_disp16
op_at_reg_displ(disp16,RWi,get_signed(insn.get_next_word(),0xFFFF),word,word)  // op_word_at_RWi_disp16
op_at_reg_displ(disp16,RWi,get_signed(insn.get_next_word(),0xFFFF),word,dword) // op_dword_at_RWi_disp16
op_at_reg_displ(disp8,RLi,get_signed(insn.get_next_byte(),0xFF),byte,byte)     // op_byte_at_RLi_disp8
op_at_reg_displ(disp8,RLi,get_signed(insn.get_next_byte(),0xFF),byte,word)     // op_word_at_RLi_disp8
// op_at_reg_displ(disp8,RLi,get_signed(insn.get_next_byte(),0xFF),byte,dword)    // op_dword_at_RLi_disp8
op_at_reg_displ(disp16,PC,get_signed(insn.get_next_word(),0xFFFF),word,byte)   // op_byte_at_PC_disp16
op_at_reg_displ(disp16,PC,get_signed(insn.get_next_word(),0xFFFF),word,word)   // op_word_at_PC_disp16
op_at_reg_displ(disp16,PC,get_signed(insn.get_next_word(),0xFFFF),word,dword)  // op_dword_at_PC_disp16

#define op_ea(REG,DTYP) \
static void op_ea_##DTYP(const map_t *map, int offset, op_t &op, insn_t &insn) \
{                                                                \
  if ( offset < 8 )                                              \
    op_##REG(map, offset, op, insn);                             \
  else if ( offset < 0x0C )                                      \
    op_##DTYP##_at_RWi(map, offset-0x08, op, insn);              \
  else if ( offset < 0x10 )                                      \
    op_##DTYP##_at_RWi_inc(map, offset-0x0C, op, insn);          \
  else if ( offset < 0x18 )                                      \
    op_##DTYP##_at_RWi_disp8(map, offset-0x10, op, insn);        \
  else if ( offset < 0x1C )                                      \
    op_##DTYP##_at_RWi_disp16(map, offset-0x18, op, insn);       \
  else if ( offset < 0x1E )                                      \
  {                                                              \
    op_##DTYP##_at_RWi(map, offset-0x1C, op, insn);              \
    op.special_mode = MODE_INDEX;                                \
    op.f2mc_index   = RW7;                                       \
  }                                                              \
  else if ( offset == 0x1E )                                     \
    op_##DTYP##_at_PC_disp16(map, offset-0x18, op, insn);        \
  else                                                           \
    op_addr16_##DTYP(map, offset-0x1F, op, insn);                \
}

op_ea(Ri,byte)    // op_ea_byte
op_ea(RWi,word)   // op_ea_word
op_ea(RLi2,dword) // op_ea_dword

#define op_code_at_ea(DEFAULT_BANK,DTYP) \
  static void op_code_at_ea_##DTYP(const map_t *map, int offset, op_t &op, insn_t &insn) \
  {                                                                        \
    op_ea_##DTYP(map,offset,op, insn);                                     \
    insn.default_bank = DEFAULT_BANK;                                      \
    insn.op_bank = op.n;                                                   \
    op.at_qty++;                                                           \
    op.dtype = dt_code;                                                    \
  }
op_code_at_ea(PCB,word) // op_code_at_ea_word
op_code_at_ea(0,dword)  // op_code_at_ea_dword


//--------------------------------------------------------------------------
static void op_addr24(const map_t *, int, op_t &op, insn_t &insn)
{
  op.type = o_far;
  op.addr = insn.get_next_word();
  op.addr |= insn.get_next_byte() << 16;
  op.dtype = dt_code;
}

//--------------------------------------------------------------------------
static void op_rel(const map_t *, int, op_t &op, insn_t &insn)
{
  int offset = get_signed(insn.get_next_byte(), 0xFF);
  op.type  = o_near;
  op.addr  = (insn.ip & ~0xFFFF) | ((insn.ip + insn.size + offset) & 0xFFFF);
  op.dtype = dt_code;
}

//-------------------------------------------------------------------------
static void op_rlst(const map_t *, int, op_t &op, insn_t &insn)
{
  op.type  = o_reglist;
  op.reg   = insn.get_next_byte();
  op.dtype = dt_byte;
}

//--------------------------------------------------------------------------
// used for string instructions
static void op_PCB_DTB_ADB_SPB(const map_t *map, int offset, op_t &op, insn_t &insn)
{
  static const func_op_t banks[4] = { op_PCB, op_DTB, op_ADB, op_SPB };
  banks[offset&3](map, offset, op, insn);
}

//--------------------------------------------------------------------------
// used for writing/reading values to/from bank registers
static void op_DTB_ADB_SSB_USB_DPR(const map_t *map, int offset, op_t &op, insn_t &insn)
{
  static const func_op_t banks[5] = { op_DTB, op_ADB, op_SSB, op_USB, op_DPR };
  banks[offset%5](map, offset, op, insn);
}

//--------------------------------------------------------------------------
static const map_t bitop_map[] = // bit operations
{
  { nullptr, 0x00, F2MC_movb, op_A,         op_bp_io,     0, OP_NULL },
  { nullptr, 0x08, F2MC_movb, op_A,         op_bp_dir,    0, OP_NULL },
  { nullptr, 0x10, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0x18, F2MC_movb, op_A,         op_bp_addr16, 0, OP_NULL },
  { nullptr, 0x20, F2MC_movb, op_bp_io,     op_A,         0, OP_NULL },
  { nullptr, 0x28, F2MC_movb, op_bp_dir,    op_A,         0, OP_NULL },
  { nullptr, 0x30, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0x38, F2MC_movb, op_bp_addr16, op_A,         0, OP_NULL },
  { nullptr, 0x40, F2MC_clrb, op_bp_io,     0,            0, OP_NULL },
  { nullptr, 0x48, F2MC_clrb, op_bp_dir,    0,            0, OP_NULL },
  { nullptr, 0x50, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0x58, F2MC_clrb, op_bp_addr16, 0,            0, OP_NULL },
  { nullptr, 0x60, F2MC_setb, op_bp_io,     0,            0, OP_NULL },
  { nullptr, 0x68, F2MC_setb, op_bp_dir,    0,            0, OP_NULL },
  { nullptr, 0x70, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0x78, F2MC_setb, op_bp_addr16, 0,            0, OP_NULL },
  { nullptr, 0x80, F2MC_bbc,  op_bp_io,     op_rel,       0, OP_NULL },
  { nullptr, 0x88, F2MC_bbc,  op_bp_dir,    op_rel,       0, OP_NULL },
  { nullptr, 0x90, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0x98, F2MC_bbc,  op_bp_addr16, op_rel,       0, OP_NULL },
  { nullptr, 0xA0, F2MC_bbs,  op_bp_io,     op_rel,       0, OP_NULL },
  { nullptr, 0xA8, F2MC_bbs,  op_bp_dir,    op_rel,       0, OP_NULL },
  { nullptr, 0xB0, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0xB8, F2MC_bbs,  op_bp_addr16, op_rel,       0, OP_NULL },
  { nullptr, 0xC0, F2MC_wbts, op_bp_io,     0,            0, OP_NULL },
  { nullptr, 0xC8, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0xE0, F2MC_wbtc, op_bp_io,     0,            0, OP_NULL },
  { nullptr, 0xE8, F2MC_null, 0,            0,            0, OP_NULL },
  { nullptr, 0xF8, F2MC_sbbs, op_bp_addr16, op_rel,       0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t strop_map[] = // string operations
{
  { nullptr, 0x00, F2MC_movsi,  op_PCB_DTB_ADB_SPB, op_PCB_DTB_ADB_SPB, 0, OP_2_1(4) },
  { nullptr, 0x10, F2MC_movsd,  op_PCB_DTB_ADB_SPB, op_PCB_DTB_ADB_SPB, 0, OP_2_1(4) },
  { nullptr, 0x20, F2MC_movswi, op_PCB_DTB_ADB_SPB, op_PCB_DTB_ADB_SPB, 0, OP_2_1(4) },
  { nullptr, 0x30, F2MC_movswd, op_PCB_DTB_ADB_SPB, op_PCB_DTB_ADB_SPB, 0, OP_2_1(4) },
  { nullptr, 0x40, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0x80, F2MC_sceqi,  op_PCB_DTB_ADB_SPB, 0,                  0, OP_NULL   },
  { nullptr, 0x84, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0x90, F2MC_sceqd,  op_PCB_DTB_ADB_SPB, 0,                  0, OP_NULL   },
  { nullptr, 0x94, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0xA0, F2MC_scweqi, op_PCB_DTB_ADB_SPB, 0,                  0, OP_NULL   },
  { nullptr, 0xA4, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0xB0, F2MC_scweqd, op_PCB_DTB_ADB_SPB, 0,                  0, OP_NULL   },
  { nullptr, 0xB4, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0xC0, F2MC_filsi,  op_PCB_DTB_ADB_SPB, 0,                  0, OP_NULL   },
  { nullptr, 0xC4, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0xE0, F2MC_filswi, op_PCB_DTB_ADB_SPB, 0,                  0, OP_NULL   },
  { nullptr, 0xE4, F2MC_null,   0,                  0,                  0, OP_NULL   },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t twobyte_map[] =
{
  { nullptr, 0x00, F2MC_mov,   op_A,                   op_DTB_ADB_SSB_USB_DPR, 0, OP_NULL   },
  { nullptr, 0x05, F2MC_mov,   op_A,                   op_byte_at_A,           0, OP_NULL   },
  { nullptr, 0x06, F2MC_mov,   op_A,                   op_PCB,                 0, OP_NULL   },
  { nullptr, 0x07, F2MC_rolc,  op_A,                   0,                      0, OP_NULL   },
  { nullptr, 0x08, F2MC_null,  0,                      0,                      0, OP_NULL   },
  { nullptr, 0x0C, F2MC_lslw2, op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x0D, F2MC_movw,  op_A,                   op_word_at_A,           0, OP_NULL   },
  { nullptr, 0x0E, F2MC_asrw2, op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x0F, F2MC_lsrw2, op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x10, F2MC_mov,   op_DTB_ADB_SSB_USB_DPR, op_A,                   0, OP_NULL   },
  { nullptr, 0x15, F2MC_mov,   op_byte_at_AL,          op_AH,                  0, OP_NULL   },
  { nullptr, 0x16, F2MC_movx,  op_A,                   op_byte_at_A,           0, OP_NULL   },
  { nullptr, 0x17, F2MC_rorc,  op_A,                   0,                      0, OP_NULL   },
  { nullptr, 0x18, F2MC_null,  0,                      0,                      0, OP_NULL   },
  { nullptr, 0x1C, F2MC_lsll,  op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x1D, F2MC_movw,  op_word_at_AL,          op_AH,                  0, OP_NULL   },
  { nullptr, 0x1E, F2MC_asrl,  op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x1F, F2MC_lsrl,  op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x20, F2MC_movx,  op_A,                   op_byte_at_RLi_disp8,   0, OP_3_2(2) },
  { nullptr, 0x27, F2MC_null,  0,                      0,                      0, OP_NULL   },
  { nullptr, 0x2C, F2MC_lsl,   op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x2D, F2MC_nrml,  op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x2E, F2MC_asr,   op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x2F, F2MC_lsr,   op_A,                   op_Ri,                  0, OP_NULL   },
  { nullptr, 0x30, F2MC_mov,   op_byte_at_RLi_disp8,   op_A,                   0, OP_3_1(2) },
  { nullptr, 0x38, F2MC_movw,  op_word_at_RLi_disp8,   op_A,                   0, OP_3_1(2) },
  { nullptr, 0x40, F2MC_mov,   op_A,                   op_byte_at_RLi_disp8,   0, OP_3_2(2) },
  { nullptr, 0x48, F2MC_movw,  op_A,                   op_word_at_RLi_disp8,   0, OP_3_2(2) },
  { nullptr, 0x50, F2MC_null,  0,                      0,                      0, OP_NULL   },
  { nullptr, 0x78, F2MC_mul1,  op_A,                   0,                      0, OP_NULL   },
  { nullptr, 0x79, F2MC_mulw1, op_A,                   0,                      0, OP_NULL   },
  { nullptr, 0x7A, F2MC_div1,  op_A,                   0,                      0, OP_NULL   },
  { nullptr, 0x7B, F2MC_null,  0,                      0,                      0, OP_NULL   },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_1_map[] =
{
  { nullptr, 0x00, F2MC_addl,  op_A,       op_ea_dword, 0,      OP_NULL },
  { nullptr, 0x20, F2MC_subl,  op_A,       op_ea_dword, 0,      OP_NULL },
  { nullptr, 0x40, F2MC_cwbne, op_ea_word, op_imm16,    op_rel, OP_NULL },
  { nullptr, 0x60, F2MC_cmpl,  op_A,       op_ea_dword, 0,      OP_NULL },
  { nullptr, 0x80, F2MC_andl,  op_A,       op_ea_dword, 0,      OP_NULL },
  { nullptr, 0xA0, F2MC_orl,   op_A,       op_ea_dword, 0,      OP_NULL },
  { nullptr, 0xC0, F2MC_xorl,  op_A,       op_ea_dword, 0,      OP_NULL },
  { nullptr, 0xE0, F2MC_cbne,  op_ea_byte, op_imm8,     op_rel, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_2_map[] =
{
  { nullptr, 0x00, F2MC_jmpp,   op_code_at_ea_dword, 0,            0, OP_NULL },
  { nullptr, 0x20, F2MC_callp,  op_code_at_ea_dword, 0,            0, OP_NULL },
  { nullptr, 0x40, F2MC_incl,   op_ea_dword,         0,            0, OP_NULL },
  { nullptr, 0x60, F2MC_decl,   op_ea_dword,         0,            0, OP_NULL },
  { nullptr, 0x80, F2MC_movl,   op_A,                op_ea_dword,  0, OP_NULL },
  { nullptr, 0xA0, F2MC_movl,   op_ea_dword,         op_A,         0, OP_NULL },
  { nullptr, 0xC0, F2MC_mov,    op_ea_byte,          op_imm8,      0, OP_NULL },
  { nullptr, 0xE0, F2MC_movea,  op_A,                op_ea_word,   0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_3_map[] =
{
  { nullptr, 0x00, F2MC_rolc, op_ea_byte, 0,          0, OP_NULL },
  { nullptr, 0x20, F2MC_rorc, op_ea_byte, 0,          0, OP_NULL },
  { nullptr, 0x40, F2MC_inc,  op_ea_byte, 0,          0, OP_NULL },
  { nullptr, 0x60, F2MC_dec,  op_ea_byte, 0,          0, OP_NULL },
  { nullptr, 0x80, F2MC_mov,  op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0xA0, F2MC_mov,  op_ea_byte, op_A,       0, OP_NULL },
  { nullptr, 0xC0, F2MC_movx, op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0xE0, F2MC_xch,  op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_4_map[] =
{
  { nullptr, 0x00, F2MC_jmp,  op_code_at_ea_word, 0,          0, OP_NULL },
  { nullptr, 0x20, F2MC_call, op_code_at_ea_word, 0,          0, OP_NULL },
  { nullptr, 0x40, F2MC_incw, op_ea_word,         0,          0, OP_NULL },
  { nullptr, 0x60, F2MC_decw, op_ea_word,         0,          0, OP_NULL },
  { nullptr, 0x80, F2MC_movw, op_A,               op_ea_word, 0, OP_NULL },
  { nullptr, 0xA0, F2MC_movw, op_ea_word,         op_A,       0, OP_NULL },
  { nullptr, 0xC0, F2MC_movw, op_ea_word,         op_imm16,   0, OP_NULL },
  { nullptr, 0xE0, F2MC_xchw, op_A,               op_ea_word, 0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_5_map[] =
{
  { nullptr, 0x00, F2MC_add,   op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0x20, F2MC_sub,   op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0x40, F2MC_addc2, op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0x60, F2MC_cmp2,  op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0x80, F2MC_and,   op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0xA0, F2MC_or,    op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0xC0, F2MC_xor,   op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0xE0, F2MC_dbnz,  op_ea_byte, op_rel,     0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_6_map[] =
{
  { nullptr, 0x00, F2MC_add,   op_ea_byte, op_A,       0, OP_NULL },
  { nullptr, 0x20, F2MC_sub,   op_ea_byte, op_A,       0, OP_NULL },
  { nullptr, 0x40, F2MC_subc2, op_A,       op_ea_byte, 0, OP_NULL },
  { nullptr, 0x60, F2MC_neg,   op_ea_byte, 0,          0, OP_NULL },
  { nullptr, 0x80, F2MC_and,   op_ea_byte, op_A,       0, OP_NULL },
  { nullptr, 0xA0, F2MC_or,    op_ea_byte, op_A,       0, OP_NULL },
  { nullptr, 0xC0, F2MC_xor,   op_ea_byte, op_A,       0, OP_NULL },
  { nullptr, 0xE0, F2MC_not,   op_ea_byte, 0,          0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_7_map[] =
{
  { nullptr, 0x00, F2MC_addw2, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0x20, F2MC_subw2, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0x40, F2MC_addcw, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0x60, F2MC_cmpw2, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0x80, F2MC_andw2, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0xA0, F2MC_orw2,  op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0xC0, F2MC_xorw2, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0xE0, F2MC_dwbnz, op_ea_word, op_rel,     0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_8_map[] =
{
  { nullptr, 0x00, F2MC_addw2, op_ea_word, op_A,       0, OP_NULL },
  { nullptr, 0x20, F2MC_subw2, op_ea_word, op_A,       0, OP_NULL },
  { nullptr, 0x40, F2MC_subcw, op_A,       op_ea_word, 0, OP_NULL },
  { nullptr, 0x60, F2MC_negw,  op_ea_word, 0,          0, OP_NULL },
  { nullptr, 0x80, F2MC_andw2, op_ea_word, op_A,       0, OP_NULL },
  { nullptr, 0xA0, F2MC_orw2,  op_ea_word, op_A,       0, OP_NULL },
  { nullptr, 0xC0, F2MC_xorw2, op_ea_word, op_A,       0, OP_NULL },
  { nullptr, 0xE0, F2MC_notw,  op_ea_word, 0,          0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_9_map[] =
{
  { nullptr, 0x00, F2MC_mulu2,  op_A, op_ea_byte, 0, OP_NULL },
  { nullptr, 0x20, F2MC_muluw2, op_A, op_ea_word, 0, OP_NULL },
  { nullptr, 0x40, F2MC_mul2,   op_A, op_ea_byte, 0, OP_NULL },
  { nullptr, 0x60, F2MC_mulw2,  op_A, op_ea_word, 0, OP_NULL },
  { nullptr, 0x80, F2MC_divu2,  op_A, op_ea_byte, 0, OP_NULL },
  { nullptr, 0xA0, F2MC_divuw,  op_A, op_ea_word, 0, OP_NULL },
  { nullptr, 0xC0, F2MC_div2,   op_A, op_ea_byte, 0, OP_NULL },
  { nullptr, 0xE0, F2MC_divw,   op_A, op_ea_word, 0, OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t RWi_ea_map[] =
{
  { nullptr, 0x00, F2MC_null, op_RWi, op_ea_word, 0, OP_2_1(32) },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t Ri_ea_map[] =
{
  { nullptr, 0x00, F2MC_null, op_Ri, op_ea_byte, 0, OP_2_1(32) },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_Ri_map[] =
{
  { nullptr, 0x00, F2MC_null, op_ea_byte, op_Ri, 0, OP_1_2(32) },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t ea_RWi_map[] =
{
  { nullptr, 0x00, F2MC_null, op_ea_word, op_RWi, 0, OP_1_2(32) },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

static const map_t basic_map[] =
{
  { nullptr, 0x00, F2MC_nop,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x01, F2MC_int9,   0,                    0,                    0,      OP_NULL },
  { nullptr, 0x02, F2MC_adddc,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x03, F2MC_neg,    op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x04, F2MC_pcb,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x05, F2MC_dtb,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x06, F2MC_adb,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x07, F2MC_spb,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x08, F2MC_link,   op_imm8,              0,                    0,      OP_NULL },
  { nullptr, 0x09, F2MC_unlink, 0,                    0,                    0,      OP_NULL },
  { nullptr, 0x0A, F2MC_mov,    op_RP,                op_imm8,              0,      OP_NULL },
  { nullptr, 0x0B, F2MC_negw,   op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x0C, F2MC_lslw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x0D, F2MC_null,   0,                    0,                    0,      OP_NULL },
  { nullptr, 0x0E, F2MC_asrw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x0F, F2MC_lsrw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x10, F2MC_cmr,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x11, F2MC_ncc,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x12, F2MC_subdc,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x13, F2MC_jctx,   op_byte_at_A,         0,                    0,      OP_NULL },
  { nullptr, 0x14, F2MC_ext,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x15, F2MC_zext,   0,                    0,                    0,      OP_NULL },
  { nullptr, 0x16, F2MC_swap,   0,                    0,                    0,      OP_NULL },
  { nullptr, 0x17, F2MC_addsp,  op_imm8,              0,                    0,      OP_NULL },
  { nullptr, 0x18, F2MC_addl,   op_A,                 op_imm32,             0,      OP_NULL },
  { nullptr, 0x19, F2MC_subl,   op_A,                 op_imm32,             0,      OP_NULL },
  { nullptr, 0x1A, F2MC_mov,    op_ILM,               op_imm8,              0,      OP_NULL },
  { nullptr, 0x1B, F2MC_cmpl,   op_A,                 op_imm32,             0,      OP_NULL },
  { nullptr, 0x1C, F2MC_extw,   0,                    0,                    0,      OP_NULL },
  { nullptr, 0x1D, F2MC_zextw,  0,                    0,                    0,      OP_NULL },
  { nullptr, 0x1E, F2MC_swapw,  0,                    0,                    0,      OP_NULL },
  { nullptr, 0x1F, F2MC_addsp,  op_imm16,             0,                    0,      OP_NULL },
  { nullptr, 0x20, F2MC_add,    op_A,                 op_dir_byte,          0,      OP_NULL },
  { nullptr, 0x21, F2MC_sub,    op_A,                 op_dir_byte,          0,      OP_NULL },
  { nullptr, 0x22, F2MC_addc1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x23, F2MC_cmp1,   op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x24, F2MC_and,    op_CCR,               op_imm8,              0,      OP_NULL },
  { nullptr, 0x25, F2MC_or,     op_CCR,               op_imm8,              0,      OP_NULL },
  { nullptr, 0x26, F2MC_divu1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x27, F2MC_mulu1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x28, F2MC_addw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x29, F2MC_subw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x29, F2MC_subw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x2A, F2MC_cbne,   op_A,                 op_imm8,              op_rel, OP_NULL },
  { nullptr, 0x2B, F2MC_cmpw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x2C, F2MC_andw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x2D, F2MC_orw1,   op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x2E, F2MC_xorw1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x2F, F2MC_muluw1, op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x30, F2MC_add,    op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x31, F2MC_sub,    op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x32, F2MC_subc1,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x33, F2MC_cmp2,   op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x34, F2MC_and,    op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x35, F2MC_or,     op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x36, F2MC_xor,    op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x37, F2MC_not,    op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x38, F2MC_addw2,  op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x39, F2MC_subw2,  op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x3A, F2MC_cwbne,  op_A,                 op_imm16,             op_rel, OP_NULL },
  { nullptr, 0x3B, F2MC_cmpw2,  op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x3C, F2MC_andw2,  op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x3D, F2MC_orw2,   op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x3E, F2MC_xorw2,  op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x3F, F2MC_notw,   op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x40, F2MC_mov,    op_A,                 op_dir_byte,          0,      OP_NULL },
  { nullptr, 0x41, F2MC_mov,    op_dir_byte,          op_A,                 0,      OP_NULL },
  { nullptr, 0x42, F2MC_mov,    op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x43, F2MC_movx,   op_A,                 op_imm8,              0,      OP_NULL },
  { nullptr, 0x44, F2MC_mov,    op_dir_byte,          op_imm8,              0,      OP_NULL },
  { nullptr, 0x45, F2MC_movx,   op_A,                 op_dir_byte,          0,      OP_NULL },
  { nullptr, 0x46, F2MC_movw,   op_A,                 op_SP,                0,      OP_NULL },
  { nullptr, 0x47, F2MC_movw,   op_SP,                op_A,                 0,      OP_NULL },
  { nullptr, 0x48, F2MC_movw,   op_A,                 op_dir_word,          0,      OP_NULL },
  { nullptr, 0x49, F2MC_movw,   op_dir_word,          op_A,                 0,      OP_NULL },
  { nullptr, 0x4A, F2MC_movw,   op_A,                 op_imm16,             0,      OP_NULL },
  { nullptr, 0x4B, F2MC_movl,   op_A,                 op_imm32,             0,      OP_NULL },
  { nullptr, 0x4C, F2MC_pushw,  op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x4D, F2MC_pushw,  op_AH,                0,                    0,      OP_NULL },
  { nullptr, 0x4E, F2MC_pushw,  op_PS,                0,                    0,      OP_NULL },
  { nullptr, 0x4F, F2MC_pushw,  op_rlst,              0,                    0,      OP_NULL },
  { nullptr, 0x50, F2MC_mov,    op_A,                 op_io_byte,           0,      OP_NULL },
  { nullptr, 0x51, F2MC_mov,    op_io_byte,           op_A,                 0,      OP_NULL },
  { nullptr, 0x52, F2MC_mov,    op_A,                 op_addr16_byte,       0,      OP_NULL },
  { nullptr, 0x53, F2MC_mov,    op_addr16_byte,       op_A,                 0,      OP_NULL },
  { nullptr, 0x54, F2MC_mov,    op_io_byte,           op_imm8,              0,      OP_NULL },
  { nullptr, 0x55, F2MC_movx,   op_A,                 op_io_byte,           0,      OP_NULL },
  { nullptr, 0x56, F2MC_movw,   op_io_word,           op_imm16,             0,      OP_NULL },
  { nullptr, 0x57, F2MC_movx,   op_A,                 op_addr16_byte,       0,      OP_NULL },
  { nullptr, 0x58, F2MC_movw,   op_A,                 op_io_word,           0,      OP_NULL },
  { nullptr, 0x59, F2MC_movw,   op_io_word,           op_A,                 0,      OP_NULL },
  { nullptr, 0x5A, F2MC_movw,   op_A,                 op_addr16_word,       0,      OP_NULL },
  { nullptr, 0x5B, F2MC_movw,   op_addr16_word,       op_A,                 0,      OP_NULL },
  { nullptr, 0x5C, F2MC_popw,   op_A,                 0,                    0,      OP_NULL },
  { nullptr, 0x5D, F2MC_popw,   op_AH,                0,                    0,      OP_NULL },
  { nullptr, 0x5E, F2MC_popw,   op_PS,                0,                    0,      OP_NULL },
  { nullptr, 0x5F, F2MC_popw,   op_rlst,              0,                    0,      OP_NULL },
  { nullptr, 0x60, F2MC_bra,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0x61, F2MC_jmp,    op_code_at_A,         0,                    0,      OP_NULL },
  { nullptr, 0x62, F2MC_jmp,    op_addr16_code,       0,                    0,      OP_NULL },
  { nullptr, 0x63, F2MC_jmpp,   op_addr24,            0,                    0,      OP_NULL },
  { nullptr, 0x64, F2MC_call,   op_addr16_code,       0,                    0,      OP_NULL },
  { nullptr, 0x65, F2MC_callp,  op_addr24,            0,                    0,      OP_NULL },
  { nullptr, 0x66, F2MC_retp,   0,                    0,                    0,      OP_NULL },
  { nullptr, 0x67, F2MC_ret,    0,                    0,                    0,      OP_NULL },
  { nullptr, 0x68, F2MC_int,    op_imm8,              0,                    0,      OP_NULL },
  { nullptr, 0x69, F2MC_int,    op_addr16_code,       0,                    0,      OP_NULL },
  { nullptr, 0x6A, F2MC_intp,   op_addr24,            0,                    0,      OP_NULL },
  { nullptr, 0x6B, F2MC_reti,   0,                    0,                    0,      OP_NULL },
  { bitop_map,  0x6C, F2MC_null,   0,              0,                    0,      OP_NULL },
  { nullptr,       0x6D, F2MC_null,   0,              0,                    0,      OP_NULL },
  { strop_map,  0x6E, F2MC_null,   0,              0,                    0,      OP_NULL },
  { twobyte_map,0x6F, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_1_map,   0x70, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_2_map,   0x71, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_3_map,   0x72, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_4_map,   0x73, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_5_map,   0x74, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_6_map,   0x75, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_7_map,   0x76, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_8_map,   0x77, F2MC_null,   0,              0,                    0,      OP_NULL },
  { ea_9_map,   0x78, F2MC_null,   0,              0,                    0,      OP_NULL },
  { RWi_ea_map, 0x79, F2MC_movea,  0,              0,                    0,      OP_NULL },
  { Ri_ea_map,  0x7A, F2MC_mov,    0,              0,                    0,      OP_NULL },
  { RWi_ea_map, 0x7B, F2MC_movw,   0,              0,                    0,      OP_NULL },
  { ea_Ri_map,  0x7C, F2MC_mov,    0,              0,                    0,      OP_NULL },
  { ea_RWi_map, 0x7D, F2MC_movw,   0,              0,                    0,      OP_NULL },
  { Ri_ea_map,  0x7E, F2MC_xch,    0,              0,                    0,      OP_NULL },
  { RWi_ea_map, 0x7F, F2MC_xchw,   0,              0,                    0,      OP_NULL },
  { nullptr, 0x80, F2MC_mov,    op_A,                 op_Ri,                0,      OP_NULL },
  { nullptr, 0x88, F2MC_movw,   op_A,                 op_RWi,               0,      OP_NULL },
  { nullptr, 0x90, F2MC_mov,    op_Ri,                op_A,                 0,      OP_NULL },
  { nullptr, 0x98, F2MC_movw,   op_RWi,               op_A,                 0,      OP_NULL },
  { nullptr, 0xA0, F2MC_mov,    op_Ri,                op_imm8,              0,      OP_NULL },
  { nullptr, 0xA8, F2MC_movw,   op_RWi,               op_imm16,             0,      OP_NULL },
  { nullptr, 0xB0, F2MC_movx,   op_A,                 op_Ri,                0,      OP_NULL },
  { nullptr, 0xB8, F2MC_movw,   op_A,                 op_word_at_RWi_disp8, 0,      OP_NULL },
  { nullptr, 0xC0, F2MC_movx,   op_A,                 op_byte_at_RWi_disp8, 0,      OP_NULL },
  { nullptr, 0xC8, F2MC_movw,   op_word_at_RWi_disp8, op_A,                 0,      OP_NULL },
  { nullptr, 0xD0, F2MC_movn,   op_A,                 op_imm4,              0,      OP_NULL },
  { nullptr, 0xE0, F2MC_callv,  op_imm4,              0,                    0,      OP_NULL },
  { nullptr, 0xF0, F2MC_bz,     op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF1, F2MC_bnz,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF2, F2MC_bc,     op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF3, F2MC_bnc,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF4, F2MC_bn,     op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF5, F2MC_bp,     op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF6, F2MC_bv,     op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF7, F2MC_bnv,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF8, F2MC_bt,     op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xF9, F2MC_bnt,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xFA, F2MC_blt,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xFB, F2MC_bge,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xFC, F2MC_ble,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xFD, F2MC_bgt,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xFE, F2MC_bls,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0xFF, F2MC_bhi,    op_rel,               0,                    0,      OP_NULL },
  { nullptr, 0, 0, 0, 0, 0, OP_NULL }
};

//--------------------------------------------------------------------------
static bool is_A(const insn_t *, const op_t &op)
{
  return op.type == o_reg && op.reg == A;
}

//--------------------------------------------------------------------------
static bool is_1(const insn_t *, const op_t &op)
{
  return op.type == o_imm && op.value == 1;
}

//--------------------------------------------------------------------------
#define is_rel(REL)                                         \
static bool is_rel##REL(const insn_t *insn, const op_t &op) \
{                                                           \
  return op.type == o_near && op.addr == insn->ea + REL;    \
}
is_rel(5) // is_rel5
is_rel(7) // is_rel7

//--------------------------------------------------------------------------
static bool is_imm(const insn_t *, const op_t &op)
{
  return op.type == o_imm;
}

//--------------------------------------------------------------------------
// can't be A (if A then this is a dec/decw MACRO)
static bool is_ea_and_not_A(const insn_t *, const op_t &op)
{
  return op.type != o_reg || op.reg != A;
}

//--------------------------------------------------------------------------
static bool is_bp(const insn_t *, const op_t &op)
{
  return op.special_mode == MODE_BIT;
}

//--------------------------------------------------------------------------
static bool is_bp_addr16(const insn_t *insn, const op_t &op)
{
  return op.type == o_mem && op.dtype == dt_byte && is_bp(insn, op);
}

//--------------------------------------------------------------------------
#define macro_incdec(ITYPE)             \
  static const macro_insn_t macro_##ITYPE[] = \
  {                                     \
    { is_A, is_1, 0, F2MC_##ITYPE },    \
    { 0,    0,    0, F2MC_null    }     \
  }
macro_incdec(add);   // macro_add
macro_incdec(addw2); // macro_addw2
macro_incdec(addl);  // macro_addl
macro_incdec(sub);   // macro_sub
macro_incdec(subw2); // macro_subw2
macro_incdec(subl);  // macro_subl

#define macro_bXX16(ITYPE)                    \
  static const macro_insn_t macro_##ITYPE##_jmp[] = \
  {                                           \
    { is_rel5, 0, 0, F2MC_##ITYPE },          \
    { 0,       0, 0, F2MC_jmp     },          \
    { 0,       0, 0, F2MC_null    }           \
  }
macro_bXX16(bnz); // macro_bnz_jmp
macro_bXX16(bz);  // macro_bz_jmp
macro_bXX16(bnc); // macro_bnc_jmp
macro_bXX16(bc);  // macro_bc_jmp
macro_bXX16(bp);  // macro_bp_jmp
macro_bXX16(bn);  // macro_bn_jmp
macro_bXX16(bnv); // macro_bnv_jmp
macro_bXX16(bv);  // macro_bv_jmp
macro_bXX16(bnt); // macro_bnt_jmp
macro_bXX16(bt);  // macro_bt_jmp
macro_bXX16(bge); // macro_bge_jmp
macro_bXX16(blt); // macro_blt_jmp
macro_bXX16(bgt); // macro_bgt_jmp
macro_bXX16(ble); // macro_ble_jmp
macro_bXX16(bhi); // macro_bhi_jmp
macro_bXX16(bls); // macro_bls_jmp

#define macro_cXbne16(ITYPE)                    \
  static const macro_insn_t macro_##ITYPE##_bnz16[] = \
  {                                             \
    { is_A, is_imm, 0, F2MC_##ITYPE },          \
    { 0,    0,      0, F2MC_bnz16   },          \
    { 0,    0,      0, F2MC_null    }           \
  }
macro_cXbne16(cmp2);  // macro_cmp2_bnz16
macro_cXbne16(cmpw2); // macro_cmpw2_bnz16

#define macro_dXbnz16(ITYPE)                    \
  static const macro_insn_t macro_##ITYPE##_bnz16[] = \
  {                                             \
    { is_ea_and_not_A, 0, 0, F2MC_##ITYPE },    \
    { 0,               0, 0, F2MC_bnz16   },    \
    { 0,               0, 0, F2MC_null    }     \
  }
macro_dXbnz16(dec);  // macro_dec_bnz16
macro_dXbnz16(decw); // macro_decw_bnz16

#define macro_bbX16(ITYPE)                    \
  static const macro_insn_t macro_##ITYPE##_jmp[] = \
  {                                           \
    { is_bp, is_rel7, 0, F2MC_##ITYPE },      \
    { 0,     0,       0, F2MC_jmp     },      \
    { 0,     0,       0, F2MC_null    }       \
  }
macro_bbX16(bbc); // macro_bbc_jmp
macro_bbX16(bbs); // macro_bbs_jmp

static const macro_insn_t macro_sbbs_bra_jmp[] =
{
  { is_bp_addr16, is_rel7, 0, F2MC_sbbs },
  { is_rel5,      0,       0, F2MC_bra  },
  { 0,            0,       0, F2MC_jmp  },
  { 0,            0,       0, F2MC_null }
};


static const macro_t macros[] =
{
  { macro_add,          F2MC_inc,     1, OP_CMD(1,1), OP_VOID,     OP_VOID     },
  { macro_addw2,        F2MC_incw,    1, OP_CMD(1,1), OP_VOID,     OP_VOID     },
  { macro_addl,         F2MC_incl,    1, OP_CMD(1,1), OP_VOID,     OP_VOID     },
  { macro_sub,          F2MC_dec,     1, OP_CMD(1,1), OP_VOID,     OP_VOID     },
  { macro_subw2,        F2MC_decw,    1, OP_CMD(1,1), OP_VOID,     OP_VOID     },
  { macro_subl,         F2MC_decl,    1, OP_CMD(1,1), OP_VOID,     OP_VOID     },
  { macro_bnz_jmp,      F2MC_bz16,    1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bz_jmp,       F2MC_bnz16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bnc_jmp,      F2MC_bc16,    1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bc_jmp,       F2MC_bnc16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bp_jmp,       F2MC_bn16,    1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bn_jmp,       F2MC_bp16,    1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bnv_jmp,      F2MC_bv16,    1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bv_jmp,       F2MC_bnv16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bnt_jmp,      F2MC_bt16,    1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bt_jmp,       F2MC_bnt16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bge_jmp,      F2MC_blt16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_blt_jmp,      F2MC_bge16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bgt_jmp,      F2MC_ble16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_ble_jmp,      F2MC_bgt16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bhi_jmp,      F2MC_bls16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_bls_jmp,      F2MC_bhi16,   1, OP_CMD(2,1), OP_VOID,     OP_VOID     },
  { macro_cmp2_bnz16,   F2MC_cbne16,  1, OP_CMD(1,1), OP_CMD(1,2), OP_CMD(2,1) },
  { macro_cmpw2_bnz16,  F2MC_cwbne16, 1, OP_CMD(1,1), OP_CMD(1,2), OP_CMD(2,1) },
  { macro_dec_bnz16,    F2MC_dbnz16,  1, OP_CMD(1,1), OP_CMD(2,1), OP_VOID     },
  { macro_decw_bnz16,   F2MC_dwbnz16, 1, OP_CMD(1,1), OP_CMD(2,1), OP_VOID     },
  { macro_bbs_jmp,      F2MC_bbc16,   1, OP_CMD(1,1), OP_CMD(2,1), OP_VOID     },
  { macro_bbc_jmp,      F2MC_bbs16,   1, OP_CMD(1,1), OP_CMD(2,1), OP_VOID     },
  { macro_sbbs_bra_jmp, F2MC_sbbs16,  1, OP_CMD(1,1), OP_CMD(3,1), OP_VOID     },
  { nullptr,               F2MC_null,    OP_VOID, OP_VOID, OP_VOID, 0 }
};

//--------------------------------------------------------------------------
void f2mc_t::ana_F2MC16LX(insn_t &insn)
{
  process_maps(insn, basic_map, F2MC_null); // analyze opcode

  // analyze prefix
  char prefix;
  switch ( insn.itype )
  {
    case F2MC_pcb: prefix = PCB; break;
    case F2MC_dtb: prefix = DTB; break;
    case F2MC_adb: prefix = ADB; break;
    case F2MC_spb: prefix = SPB; break;
    default:       prefix = 0;   break;
  }
  if ( prefix )
  {
    insn_t next;
    if ( decode_insn(&next, insn.ea + insn.size) > 0 && next.default_bank
      && (prefix != next.default_bank) ) // if next instruction need prefix
    {
      next.ea = insn.ea;
      next.size += insn.size;
      next.prefix_bank = prefix;
      insn = next;
    }
  }

  process_macros(insn, macros, F2MC_null, (idpflags & F2MC_MACRO) != 0);
}

//--------------------------------------------------------------------------
int f2mc_t::ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;

  switch ( ptype )
  {
    case F2MC16L:
      ana_F2MC16LX(insn);
      switch ( insn.itype )
      {
        case F2MC_div1:
        case F2MC_div2:
        case F2MC_divw:
        case F2MC_mul1:
        case F2MC_mul2:
        case F2MC_mulw1:
        case F2MC_mulw2:
          insn.itype = F2MC_null;
          break;
      }
      break;
    case F2MC16LX:
      ana_F2MC16LX(insn);
      break;
    default:
      error("interr: ana: ana()");
  }
  if ( insn.itype == F2MC_null )
    return 0;
  return insn.size;
}

//--------------------------------------------------------------------------
int get_signed(int byte, int mask)
{
  int bits = mask >> 1;
  int sign = bits + 1;
  if ( byte & sign ) // offset < 0
  {
    byte = ( byte & bits ) - sign;
  }
  else // offset >= 0
  {
    byte = byte & mask;
  }
  return byte;
}
