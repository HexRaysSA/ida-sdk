
#include "kr1878.hpp"

#define FUNCS_COUNT 3

struct funcdesc_t
{
  bool (kr1878_t:: *func)(const insn_t &insn, int);
  int mask;
  int shift;
};

struct opcode
{
  ushort itype;
  const char *recog; //lint !e958 padding is required to align members
  funcdesc_t funcs[FUNCS_COUNT];
  uint32 mask;
  uint32 value;
};

//----------------------------------------------------------------------
inline uint32 ua_16bits(const insn_t &insn)
{
  return get_wide_byte(insn.ea);
}


//----------------------------------------------------------------------
void kr1878_t::opreg(uint16 reg)
{
  op->type  = o_reg;
  op->dtype = dt_word;
  op->reg   = reg;
}

//----------------------------------------------------------------------
void kr1878_t::make_o_mem(const insn_t &insn)
{

  switch ( insn.itype )
  {
    case KR1878_jmp:
    case KR1878_jsr:
    case KR1878_jnz:
    case KR1878_jz:
    case KR1878_jns:
    case KR1878_js:
    case KR1878_jnc:
    case KR1878_jc:
      op->type   = o_near;
      op->dtype  = dt_code;
      return;
  }
  op->type   = o_mem;
  op->dtype  = dt_byte;
}


//----------------------------------------------------------------------
bool kr1878_t::D_ddddd(const insn_t &, int value)
{
  op->type   = o_phrase;
  op->dtype  = dt_byte;
  op->reg    = (value >> 3) & 0x03;
  op->value  = value & 7;

  return true;
}

//----------------------------------------------------------------------
bool kr1878_t::S_ddddd(const insn_t &insn, int value)
{
  if ( D_ddddd(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool kr1878_t::D_SR(const insn_t &, int value)
{
  op->type  = o_reg;
  op->dtype = dt_word;
  op->reg   = uint16(SR0 + value);

  return true;
}

//----------------------------------------------------------------------
bool kr1878_t::S_SR(const insn_t &insn, int value)
{
  if ( D_SR(insn, value) )
  {
    op++;
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
bool kr1878_t::D_Imm(const insn_t &, int value)
{
  op->type = o_imm;
  op->dtype = dt_word;
  op->value = value & 0xffff;
  return true;
}

//----------------------------------------------------------------------
bool kr1878_t::D_pImm(const insn_t &insn, int value)
{

  if ( value & 0x10 )
    D_Imm(insn, (value & 0x0f) << 4);
  else
    D_Imm(insn, value & 0x0f);

  return true;
}

//----------------------------------------------------------------------
bool kr1878_t::D_EA(const insn_t &insn, int value)
{
  op->addr = value;
  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
// singleton to init table thread-aware
struct table_t
{
  static int count() { return qnumber(table); }
  static const opcode &get(int opcode)
  {
    static const table_t instance;    //lint !e1788 only by its constructor/destructor
    return instance.table[opcode];    //lint !e727 static local symbol 'instance' of type 'const struct table_t' not explicitly initialized
  }

private:
  opcode table[52] =
  {
    { KR1878_mov,   "000001sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_cmp,   "000010sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_add,   "000100sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_sub,   "000011sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_and,   "000101sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_or,    "000110sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_xor,   "000111sssssddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_ddddd, 0x3e0}}  },
    { KR1878_movl,  "010ccccccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_Imm,   0x1fe0}} },
    { KR1878_cmpl,  "011ccccccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_Imm,   0x1fe0}} },
    { KR1878_addl,  "001100cccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_Imm,   0x3e0}}  },
    { KR1878_subl,  "001011cccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_Imm,   0x3e0}}  },
    { KR1878_bic,   "001010pccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_pImm,  0x3e0}}  },
    { KR1878_bis,   "001110pccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_pImm,  0x3e0}}  },
    { KR1878_btg,   "001111pccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_pImm,  0x3e0}}  },
    { KR1878_btt,   "001101pccccddddd", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_pImm,  0x3e0}}  },
    { KR1878_swap,  "00000000001ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_neg,   "00000000010ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_not,   "00000000011ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_shl,   "00000000100ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_shr,   "00000000101ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_shra,  "00000000110ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_rlc,   "00000000111ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_rrc,   "00000001000ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_adc,   "00000001001ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_sbc,   "00000001010ddddd", {{&kr1878_t::D_ddddd, 0x1f}} },
    { KR1878_ldr,   "00100ccccccccnnn", {{&kr1878_t::S_SR,    0x07}, {&kr1878_t::D_Imm,   0x07f8}} },
    { KR1878_mtpr,  "00000010nnnsssss", {{&kr1878_t::S_ddddd, 0x1f}, {&kr1878_t::D_SR,    0xe0  }} },
    { KR1878_mfpr,  "00000011nnnddddd", {{&kr1878_t::S_SR,    0xe0}, {&kr1878_t::D_ddddd, 0x1f  }} },
    { KR1878_push,  "0000000000010nnn", {{&kr1878_t::D_SR,    0x07}} },
    { KR1878_pop,   "0000000000011nnn", {{&kr1878_t::D_SR,    0x07}} },
    { KR1878_sst,   "000000011000bbbb", {{&kr1878_t::D_Imm,   0x0f}} },
    { KR1878_cst,   "000000011100bbbb", {{&kr1878_t::D_Imm,   0x0f}} },
    { KR1878_tof,   "0000000000000100" },
    { KR1878_tdc,   "0000000000000101" },
    { KR1878_jmp,   "100000aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_jsr,   "100100aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_jnz,   "101100aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_jz,    "101000aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_jns,   "110000aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_js,    "110100aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_jnc,   "111000aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_jc,    "111100aaaaaaaaaa", {{&kr1878_t::D_EA,    0x3ff}} },
    { KR1878_ijmp,  "0000000000000011" },
    { KR1878_ijsr,  "0000000000000111" },
    { KR1878_rts,   "0000000000001100" },
    { KR1878_rtsc,  "000000000000111c", {{&kr1878_t::D_Imm,   0x01}}  },
    { KR1878_rti,   "0000000000001101" },
    { KR1878_nop,   "0000000000000000" },
    { KR1878_wait,  "0000000000000001" },
    { KR1878_stop,  "0000000000001000" },
    { KR1878_reset, "0000000000000010" },
    { KR1878_sksp,  "0000000000000110" },
  };

  table_t()
  {
    make_masks();
  }
  ~table_t() = default;
  table_t(const table_t&) = delete;
  table_t &operator=(const table_t&) = delete;

  void make_masks(void)
  {
    for ( int i = 0; i < qnumber(table); i++ )
    {
      int bmax = strlen(table[i].recog);
      for ( int b = 0; b < bmax; b++ )
      {
        table[i].value <<= 1;
        table[i].mask <<= 1;

        if ( table[i].recog[b] == '1' || table[i].recog[b] == '0' )
          table[i].mask++;

        if ( table[i].recog[b] == '1' )
          table[i].value++;
      }

      for ( int j = 0; j < FUNCS_COUNT; j++ )
      {
        if ( table[i].funcs[j].func != nullptr )
        {
          for ( int b = 0; b < 16; b++ )
          {
            if ( table[i].funcs[j].mask & (1 << b) )
              break;
            else
              table[i].funcs[j].shift++;
          }
        }
      }
    }
  }
};


//----------------------------------------------------------------------
void init_analyzer(void)
{
  // TODO make_masks();
}

//----------------------------------------------------------------------
bool kr1878_t::use_table(const insn_t &insn, uint32 code, int entry, int start, int end)  //lint !e1762 could be made const
{
  const opcode &ptr = table_t::get(entry);
  for ( int j = start; j <= end; j++ )
  {
    if ( ptr.funcs[j].func == nullptr )
      break;
    int value = (code & ptr.funcs[j].mask) >> ptr.funcs[j].shift;
    if ( !(this->*ptr.funcs[j].func)(insn, value) )
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
int kr1878_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  uint code = ua_16bits(insn);
  op = &insn.Op1;

  int cnt = table_t::count();
  for ( int i = 0; i < cnt; i++ )
  {
    const auto &te = table_t::get(i);
    if ( (code & te.mask) == te.value )
    {
      insn.itype = te.itype;
      insn.size = 1;

      if ( !use_table(insn, code, i, 0, FUNCS_COUNT - 1) )
        continue;

      return insn.size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
void interr(const insn_t &insn, const char *module)
{
  const char *name = nullptr;
  if ( insn.itype < KR1878_last )
    name = Instructions[insn.itype].name;
  warning("%a(%s): internal error in %s", insn.ea, name, module);
}
