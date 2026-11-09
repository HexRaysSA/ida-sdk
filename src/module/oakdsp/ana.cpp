#include "oakdsp.hpp"

#define FUNCS_COUNT 5

struct funcdesc_t
{
  bool (oakdsp_t:: *func)(insn_t &, int, int);
  uint32 mask;
  uint32 param;
  uint32 shift;
};

struct opcode_t
{
  const char *recog;
  ushort itype;
  funcdesc_t funcs[FUNCS_COUNT]; //lint !e958 padding is required to align members
  uchar  cycles;     // Number of cycles
  uint32 mask;                   //lint !e958 padding is required to align members
  uint32 value;
};

//----------------------------------------------------------------------
static uint32 ua_32bits(const insn_t &insn)
{
  return ((get_wide_byte(insn.ea)   <<  0) & 0x0000FFFF)
       | ((get_wide_byte(insn.ea+1) << 16) & 0xFFFF0000);

}

//lint -e1762 member function could be made const

//----------------------------------------------------------------------
inline void oakdsp_t::opreg(int reg)
{
  op->type = o_reg;
  op->reg  = uint16(reg);
}

//----------------------------------------------------------------------
void oakdsp_t::make_o_mem(const insn_t &insn)
{
  if ( !(op->amode & amode_x) )
  {
    switch ( insn.itype )
    {

      case OAK_Dsp_callr:
      case OAK_Dsp_call:
      case OAK_Dsp_br_u:
      case OAK_Dsp_br:
      case OAK_Dsp_brr_u:
      case OAK_Dsp_brr:
      case OAK_Dsp_bkrep:
        op->type = o_near;
        op->dtype = dt_code;
        return;
    }
  }
  op->type = o_mem;
}

//----------------------------------------------------------------------
bool oakdsp_t::rrrrr(insn_t &, int value, int param)
{
  uint idx;
  if ( param & mix_mode )
    param = (param & 0xff) + value;
  idx = param ? param : value;

  if ( idx >= PAGE )
    return false;
  opreg(idx);
  if ( op->reg == uchar(-1) )
    return false;

  op++;
  return true;
}

//----------------------------------------------------------------------
//lint -e{1764} 'insn' could be declared const ref
bool oakdsp_t::sdirect(insn_t &insn, int value, int)
{
  op->amode = amode_short;
  op->addr = value & 0x00ff;
  op->amode |= amode_x;

  make_o_mem(insn);
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::ldirect(insn_t &insn, int value, int)
{
  op->amode = amode_long;
  op->addr = value & 0xffff;
  insn.size++;
  op->amode |= amode_x;

  make_o_mem(insn);
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::A(insn_t &insn, int value, int)
{
  return rrrrr(insn, value & 0x01, A0 + mix_mode);
}

//----------------------------------------------------------------------
bool oakdsp_t::B(insn_t &insn, int value, int)
{
  return rrrrr(insn, value & 0x01, B0 + mix_mode);
}

//----------------------------------------------------------------------
bool oakdsp_t::mmnnn(insn_t &, int value, int)
{
  if ( (value & 0x07) > 0x05 )
    return false;

  op->type = o_phrase;
  op->reg = value & 0x07;
  op->phtype = (value & 0x0018) >> 3;
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::nnn(insn_t &insn, int value, int)
{
  return rrrrr(insn, value & 0x07, R0 + mix_mode);
}
//----------------------------------------------------------------------
bool oakdsp_t::ALU_ALM(insn_t &insn, int value, int param)
{
  if ( param && (value == 0x04 || value == 0x05) )
    return false;

  insn.itype = OAK_Dsp_or + (value & (param ? 0x07 : 0x0f));
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::ALB(insn_t &insn, int value, int)
{
  insn.itype = OAK_Dsp_set + (value & 0x07);
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::MUL(insn_t &insn, int value, int param)
{
  if ( param && (value > 0x03) )
    return false;

  insn.itype = OAK_Dsp_mpy + ((value & (param ? 0x03 : 0x07)) << (param ? 0x01 : 0x00));
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::MODA_B(insn_t &insn, int value, int param)
{
  if ( value == 0x07 )
    return false;

  insn.itype = OAK_Dsp_shr + (value & (param ? 0x07 : 0x0f));
  return true;
}

//----------------------------------------------------------------------
//lint -e{1764} 'insn' could be declared const ref
bool oakdsp_t::s_Imm(insn_t &insn, int value, int)
{
  op->type  = o_imm;
  op->value = value;

  switch ( insn.itype )
  {
    case OAK_Dsp_mpyi:
      op->amode |= amode_signed;
      break;
  }

  op++;
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::s_ImmS(insn_t &, int value, int param)
{
  uint mask1 = 1 << (param - 1);
  uint mask2 = 0;
  for ( int i = 0; i < param; i++ )
    mask2 |= (1 << i);

  op->type  = o_imm;
  op->value = (value & mask2);
  op->amode |= amode_signed;

  if ( value & mask1 )
    op->value = 0 - ((value^mask2) + 1);

  op++;
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::l_Imm(insn_t &insn, int value, int)
{
  op->type  = o_imm;
  op->value = value & 0xffff;
  insn.size++;

  switch ( insn.itype )
  {
    case OAK_Dsp_maa:
    case OAK_Dsp_mac:
    case OAK_Dsp_macus:
    case OAK_Dsp_mpy:
    case OAK_Dsp_msu:
      op->amode |= amode_signed;
      break;
  }

  op++;
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::rb_rel_short(insn_t &, int value, int)
{
  op->type   = o_local;
  op->phtype = 0; // "rb + #displ"
  op->amode |= amode_signed;

  value &= 0x7f;

  if ( value & 0x40 )
    value = - ((value^0x7f) + 1);

  op->addr = value;
  op->amode |= amode_x;

  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::rb_rel_long(insn_t &insn, int value, int)
{
  int16 tmp;

  insn.size++;
  op->type   = o_local;
  op->phtype = 0; // "rb + #displ"
  op->amode |= amode_signed;
  tmp = (value & 0xffff);
  op->addr = tmp;
  op->amode |= amode_x;

  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::Cond(insn_t &insn, int value, int param)
{
  insn.auxpref |= value & 0x0f;

  if ( (!param) && ((value & 0x0f) > 0x00) )
    insn.auxpref |= aux_comma_cc;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::xe_xt(insn_t &insn, int value, int param)
{
  static const uchar regs[] = { cc_ge, cc_gt, cc_le, cc_lt };

  insn.auxpref |= regs[(value & 0x01) + (param ? 2 : 0)];
  insn.auxpref |= aux_comma_cc;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::lim_xx(insn_t &, int value, int)
{
  static const uchar regs1[] = { A0, A0, A1, A1 };
  static const uchar regs2[] = { uchar(-1), A1, A0, uchar(-1) };

  opreg(regs1[value & 0x03]);

  if ( regs2[value & 0x03] != uchar(-1) )
  {
    op++;
    opreg(regs2[value & 0x03]);
  }

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::rJ_rI(insn_t &, int value, int param)
{
  // jjiiwqq

  op->type   = o_phrase;
  op->reg    = param ? (value & 0x03)        : ((value & 0x04) >> 2) + 4;
  op->phtype = param ? (value & 0x0018) >> 3 : (value & 0x0060) >> 5;
  op++;

  op->type   = o_phrase;
  op->reg    = param ? ((value & 0x04) >> 2) + 4 : (value & 0x03);
  op->phtype = param ? (value & 0x0060) >> 5     : (value & 0x0018) >> 3;
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::rI(insn_t &, int value, int)
{
  // iiqq

  op->type = o_phrase;
  op->reg = (value & 0x03);
  op->phtype = (value & 0x0c) >> 2;
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::AB(insn_t &, int value, int)
{
  static const uchar regs[] = { B0, B1, A0, A1 };

  opreg(regs[value & 0x03]);
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::ABLH(insn_t &, int value, int)
{
  static const uchar regs[] = { B0L, B0H, B1L, B1H, A0L, A0H, A1L, A1H };

  opreg(regs[value & 0x07]);
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::indir_reg(insn_t &, int value, int param)
{
  op->type = o_phrase;
  op->reg = uint16(param + value);
  op->phtype = 4;
  op++;

  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::laddr_pgm(insn_t &insn, int value, int)
{
  op->amode |= amode_p;
  op->addr = value & 0xffff;
  insn.size++;

  make_o_mem(insn);
  op++;

  return true;
}

//----------------------------------------------------------------------
//lint -e{1764} 'insn' could be declared const ref
bool oakdsp_t::addr_rel_pgm(insn_t &insn, int value, int)
{
  value = (value & 0x7f);
  op->amode |= amode_p;

  if ( value & 0x40 )
  {
    value = (value^0x7f) + 1;
    op->addr = insn.ea + 1 - value;
  }
  else
  {
    op->addr = insn.ea + 1 + value;
  }

  make_o_mem(insn);
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::ext_XX(insn_t &insn, int value, int)
{
  return rrrrr(insn, (value & 0x01) + ((value & 0x04) >> 1), EXT0 + mix_mode);
}

//----------------------------------------------------------------------
bool oakdsp_t::context(insn_t &insn, int value, int)
{
  if ( value )
    insn.auxpref |= aux_iret_context;
  return true;
}
//----------------------------------------------------------------------
bool oakdsp_t::swap(insn_t &, int value, int)
{
  op->type   = o_textphrase;
  op->phrase = value & 0x0f;
  op->phtype = text_swap;
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::banke(insn_t &, int value, int)
{
  op->type   = o_textphrase;
  op->phrase = value & 0x0f;
  op->phtype = text_banke;
  return true;
}
//----------------------------------------------------------------------
bool oakdsp_t::cntx(insn_t &, int value, int)
{
  op->type   = o_textphrase;
  op->phrase = (uint16)value;
  op->phtype = text_cntx;
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::dmod(insn_t &, int value, int)
{
  op->type   = o_textphrase;
  op->phrase = (uint16)value;
  op->phtype = text_dmod;
  return true;
}

//----------------------------------------------------------------------
bool oakdsp_t::eu(insn_t &, int, int)
{
  op->type   = o_textphrase;
  op->phtype = text_eu;
  return true;
}

//----------------------------------------------------------------------
// singleton to init table thread-aware
struct table_t
{
  static int count() { return qnumber(table); }
  static const opcode_t &get(int opcode)
  {
    static const table_t instance;    //lint !e1788 only by its constructor/destructor
    return instance.table[opcode];    //lint !e727 static local symbol 'instance' of type 'const struct table_t' not explicitly initialized
  }

private:
  opcode_t table[124] =
  {
    { "0000000000000000", OAK_Dsp_nop,    {{0}},                                                                                                                                               1 },
    { "0000000000100000", OAK_Dsp_trap,   {{0}},                                                                                                                                               1 },
    { "0000000010fmmnnn", OAK_Dsp_modr,   {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::dmod, 0x0020}},                                                                               1 },
    { "0000000001arrrrr", OAK_Dsp_movp,   {{&oakdsp_t::indir_reg, 0x20, A0},         {&oakdsp_t::rrrrr, 0x001f}},                                                                              3 },
    { "000000010abrrrrr", OAK_Dsp_movs,   {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "000000011abmmnnn", OAK_Dsp_movs,   {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "00000100vvvvvvvv", OAK_Dsp_lpg,    {{&oakdsp_t::s_Imm, 0x00ff}},                                                                                                                        1 },
    { "00001000vvvvvvvv", OAK_Dsp_mpyi,   {{&oakdsp_t::rrrrr, 0, Y},                 {&oakdsp_t::s_Imm, 0x00ff}},                                                                              1 },
    { "00000101vvvvvvvv", OAK_Dsp_mov,    {{&oakdsp_t::s_Imm, 0x00ff},               {&oakdsp_t::rrrrr, 0, SV}},                                                                               1 },
    { "00001001vvvvvvvv", OAK_Dsp_rets,   {{&oakdsp_t::s_Imm, 0x00ff}},                                                                                                                        3 },
    { "00001101---rrrrr", OAK_Dsp_rep,    {{&oakdsp_t::rrrrr, 0x001f}},                                                                                                                        1 },
    { "00001100vvvvvvvv", OAK_Dsp_rep,    {{&oakdsp_t::s_Imm, 0x00ff}},                                                                                                                        1 },
    { "0000011iiqqmmnnn", OAK_Dsp_movp,   {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::rI, 0x01e0}},                                                                                 3 },
    { "0000111adddddddd", OAK_Dsp_divs,   {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "0000x01vvvvvvvvv", OAK_Dsp_load,   {{&oakdsp_t::s_Imm, 0x01ff},               {&oakdsp_t::rrrrr, 0x0800, MODI|mix_mode}},                                                               1 },
    { "000110rrrrrmmnnn", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x03e0},               {&oakdsp_t::mmnnn, 0x001f}},                                                                              1 },
    { "000111rrrrrmmnnn", OAK_Dsp_mov,    {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::rrrrr, 0x03e0}},                                                                              1 },
    { "00010ooooooocccc", OAK_Dsp_callr,  {{&oakdsp_t::addr_rel_pgm, 0x07f0},        {&oakdsp_t::Cond, 0x000f}},                                                                               2 },
    { "0010nnn0dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::nnn, 0x0e00},                 {&oakdsp_t::sdirect, 0x00ff}},                                                                            1 },
    { "001a0001vvvvvvvv", OAK_Dsp_mov,    {{&oakdsp_t::s_Imm, 0x00ff},               {&oakdsp_t::rrrrr, 0x1000, A0L|mix_mode}},                                                                1 },
    { "001a0101vvvvvvvv", OAK_Dsp_mov,    {{&oakdsp_t::s_Imm, 0x00ff},               {&oakdsp_t::rrrrr, 0x1000, A0H|mix_mode}},                                                                1 },
    { "001nnn11vvvvvvvv", OAK_Dsp_mov,    {{&oakdsp_t::s_Imm, 0x00ff},               {&oakdsp_t::nnn, 0x1c00}},                                                                                1 },
    { "001x1x01vvvvvvvv", OAK_Dsp_mov,    {{&oakdsp_t::s_Imm, 0x00ff},               {&oakdsp_t::ext_XX, 0x1400}},                                                                             1 },
    { "0011ABL0dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::ABLH, 0x0e00},                {&oakdsp_t::sdirect, 0x00ff}},                                                                            1 },
    { "0100001110000000", OAK_Dsp_eint,   {{0}},                                                                                                                                               1 },
    { "0100001111000000", OAK_Dsp_dint,   {{0}},                                                                                                                                               1 },
    { "0100000110000000", OAK_Dsp_br_u,   {{&oakdsp_t::laddr_pgm, 0xffff0000}},                                                                                                                2 },
    { "0100010110000000", OAK_Dsp_ret_u,  {{0}},                                                                                                                                               2 },
    { "01001101100000vv", OAK_Dsp_load,   {{&oakdsp_t::s_Imm, 0x0003},               {&oakdsp_t::rrrrr, 0, PS}},                                                                               1 },
    { "01000101110f0000", OAK_Dsp_reti_u, {{&oakdsp_t::context, 0x0010}},                                                                                                                      2 },
    { "010001011000cccc", OAK_Dsp_ret,    {{&oakdsp_t::Cond, 0x000f, 1}},                                                                                                                      2 },
    { "010000011000cccc", OAK_Dsp_br,     {{&oakdsp_t::laddr_pgm, 0xffff0000},       {&oakdsp_t::Cond, 0x000f}},                                                                               2 },
    { "010000011100cccc", OAK_Dsp_call,   {{&oakdsp_t::laddr_pgm, 0xffff0000},       {&oakdsp_t::Cond, 0x000f}},                                                                               2 },
    { "01000111110rrrrr", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0, MIXP},              {&oakdsp_t::rrrrr, 0x001f}},                                                                              1 },
    { "01000111111rrrrr", OAK_Dsp_mov,    {{&oakdsp_t::indir_reg, 0, SP},            {&oakdsp_t::rrrrr, 0x001f}},                                                                              1 },
    { "01000101110fcccc", OAK_Dsp_reti,   {{&oakdsp_t::Cond, 0x000f, 1},             {&oakdsp_t::context, 0x0010}},                                                                            1 },
    { "0100100110--swap", OAK_Dsp_swap,   {{&oakdsp_t::swap,  0x000f}},                                                                                                                        1 },
    { "0100111111-rrrrr", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::rrrrr, 0, ICR}},                                                                              1 },
    { "0100111110-vvvvv", OAK_Dsp_mov,    {{&oakdsp_t::s_Imm, 0x001f},               {&oakdsp_t::rrrrr, 0, ICR}},                                                                              1 },
    { "0100100111xx----", OAK_Dsp_lim,    {{&oakdsp_t::lim_xx, 0x0030}},                                                                                                                       1 },
    { "010010111---bank", OAK_Dsp_banke,  {{&oakdsp_t::banke, 0x000f}},                                                                                                                        1 },
    { "0100nnn01abvvvvv", OAK_Dsp_movsi,  {{&oakdsp_t::nnn, 0x0e00},                 {&oakdsp_t::AB, 0x0060},                     {&oakdsp_t::s_ImmS, 0x001f, 5}},                             1 },
    { "0100xxxa0ooooooo", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x0e00, 1},          {&oakdsp_t::rb_rel_short, 0x007f},           {&oakdsp_t::A, 0x0100}},                                     1 },
    { "0101111101000000", OAK_Dsp_push,   {{&oakdsp_t::l_Imm, 0xffff0000}},                                                                                                                    2 },
    { "01011110010rrrrr", OAK_Dsp_push,   {{&oakdsp_t::rrrrr, 0x001f}},                                                                                                                        1 },
    { "01011110011rrrrr", OAK_Dsp_pop,    {{&oakdsp_t::rrrrr, 0x001f}},                                                                                                                        1 },
    { "01011110100rrrrr", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::rrrrr, 0, MIXP}},                                                                             1 },
    { "0101111011brrrrr", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::B, 0x0020}},                                                                                  1 },
    { "01011101000rrrrr", OAK_Dsp_bkrep,  {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::laddr_pgm, 0xffff0000}},                                                                      2 },
    { "0101111-000rrrrr", OAK_Dsp_mov,    {{&oakdsp_t::l_Imm, 0xffff0000},           {&oakdsp_t::rrrrr, 0x001f}},                                                                              2 },
    { "0101111b001-----", OAK_Dsp_mov,    {{&oakdsp_t::l_Imm, 0xffff0000},           {&oakdsp_t::B, 0x0100}},                                                                                  2 },
    { "010111111jjiiwqq", OAK_Dsp_movd,   {{&oakdsp_t::rJ_rI, 0x007f, 1}},                                                                                                                     4 },
    { "01011100vvvvvvvv", OAK_Dsp_bkrep,  {{&oakdsp_t::s_Imm, 0x00ff},               {&oakdsp_t::laddr_pgm, 0xffff0000}},                                                                      2 },
    { "010110RRRRRrrrrr", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::rrrrr, 0x03e0}},                                                                              1 },
    { "01010ooooooo0000", OAK_Dsp_brr_u,  {{&oakdsp_t::addr_rel_pgm, 0x07f0}},                                                                                                                 2 },
    { "01010ooooooocccc", OAK_Dsp_brr,    {{&oakdsp_t::addr_rel_pgm, 0x07f0},        {&oakdsp_t::Cond, 0x000f}},                                                                               2 },
    { "01101101dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::rrrrr, 0, SV}},                                                                               1 },
    { "011nnn00dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::nnn, 0x1c00}},                                                                                1 },
    { "011AB001dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::AB, 0x1800}},                                                                                 1 },
    { "011ABL10dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::ABLH, 0x1c00}},                                                                               1 },
    { "011A0101dddddddd", OAK_Dsp_mov_eu, {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::A, 0x1000},                      {&oakdsp_t::eu, 0x0}},                                       1 },
    { "011ab011dddddddd", OAK_Dsp_movs,   {{&oakdsp_t::sdirect, 0x00ff},             {&oakdsp_t::AB, 0x1800}},                                                                                 1 },
    { "011b11110fffcccc", OAK_Dsp_proc,   {{&oakdsp_t::MODA_B, 0x0070, 1},           {&oakdsp_t::B, 0x1000},                      {&oakdsp_t::Cond, 0x000f}},                                  1 },
    { "011a0111ffffcccc", OAK_Dsp_proc,   {{&oakdsp_t::MODA_B, 0x00f0},              {&oakdsp_t::A, 0x1000},                      {&oakdsp_t::Cond, 0x000f}},                                  1 },
    { "01111101dddddddd", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0, SV},                {&oakdsp_t::sdirect, 0x00ff}},                                                                            1 },
    { "100000fa011mm000", OAK_Dsp_maxd,   {{&oakdsp_t::A, 0x0100},                   {&oakdsp_t::mmnnn, 0x001f},                  {&oakdsp_t::xe_xt, 0x0200, 0}},                              1 },
    { "100001fa011mm000", OAK_Dsp_max,    {{&oakdsp_t::A, 0x0100},                   {&oakdsp_t::mmnnn, 0x001f},                  {&oakdsp_t::xe_xt, 0x0200, 0}},                              1 },
    { "10001-fa011mm000", OAK_Dsp_min,    {{&oakdsp_t::A, 0x0100},                   {&oakdsp_t::mmnnn, 0x001f},                  {&oakdsp_t::xe_xt, 0x0200, 1}},                              1 },
    { "1000xxxa11000000", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x0e00, 1},          {&oakdsp_t::l_Imm, 0xffff0000},              {&oakdsp_t::A, 0x0100}},                                     2 },
    { "1000xxx0111mmnnn", OAK_Dsp_proc,   {{&oakdsp_t::ALB, 0x0e00},                 {&oakdsp_t::l_Imm, 0xffff0000},              {&oakdsp_t::mmnnn, 0x001f}},                                 2 },
    { "1000xxx1111rrrrr", OAK_Dsp_proc,   {{&oakdsp_t::ALB, 0x0e00},                 {&oakdsp_t::l_Imm, 0xffff0000},              {&oakdsp_t::rrrrr, 0x001f}},                                 2 },
    { "1000-00x001mmnnn", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::rrrrr, 0, Y},                    {&oakdsp_t::mmnnn, 0x001f}},                                 1 },
    { "1000axxx001mmnnn", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::rrrrr, 0, Y},                    {&oakdsp_t::mmnnn, 0x001f},        {&oakdsp_t::A, 0x0800}},  1 },
    { "1000-00x010rrrrr", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::rrrrr, 0, Y},                    {&oakdsp_t::rrrrr, 0x001f}},                                 1 },
    { "1000axxx010rrrrr", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::rrrrr, 0, Y},                    {&oakdsp_t::rrrrr, 0x001f},        {&oakdsp_t::A, 0x0800}},  1 },
    { "1000-00x000mmnnn", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::mmnnn, 0x001f},                  {&oakdsp_t::l_Imm, 0xffff0000}},                             2 },
    { "1000axxx000mmnnn", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::mmnnn, 0x001f},                  {&oakdsp_t::l_Imm, 0xffff0000},    {&oakdsp_t::A, 0x0800}},  2 },
    { "100xxxxa100mmnnn", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x1e00},             {&oakdsp_t::mmnnn, 0x001f},                  {&oakdsp_t::A, 0x0100}},                                     1 },
    { "100xxxxa101rrrrr", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x1e00},             {&oakdsp_t::rrrrr, 0x001f},                  {&oakdsp_t::A, 0x0100}},                                     1 },
    { "1001000a110mmnnn", OAK_Dsp_msu,    {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::l_Imm, 0xffff0000},              {&oakdsp_t::A, 0x0100}},                                     2 },
    { "1001010a110mmnnn", OAK_Dsp_norm,   {{&oakdsp_t::A, 0x0100},                   {&oakdsp_t::mmnnn, 0x001f}},                                                                              2 },
    { "1001bbbb001mmnnn", OAK_Dsp_tstb,   {{&oakdsp_t::s_Imm, 0x0f00},               {&oakdsp_t::mmnnn, 0x001f}},                                                                              1 },
    { "1001bbbb000rrrrr", OAK_Dsp_tstb,   {{&oakdsp_t::s_Imm, 0x0f00},               {&oakdsp_t::rrrrr, 0x001f}},                                                                              1 },
    { "1001ab1AB1vvvvvv", OAK_Dsp_shfi,   {{&oakdsp_t::AB, 0x0c00},                  {&oakdsp_t::AB, 0x0180},                     {&oakdsp_t::s_ImmS, 0x003f, 6}},                             1 },
    { "1001100a010mmnnn", OAK_Dsp_exp,    {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "1001000a010rrrrr", OAK_Dsp_exp,    {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "1001000a0110000b", OAK_Dsp_exp,    {{&oakdsp_t::B, 0x0001},                   {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "10011100010mmnnn", OAK_Dsp_exp,    {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::rrrrr, 0, SV}},                                                                               1 },
    { "10010100010rrrrr", OAK_Dsp_exp,    {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::rrrrr, 0, SV}},                                                                               1 },
    { "100101000110000b", OAK_Dsp_exp,    {{&oakdsp_t::B, 0x0001},                   {&oakdsp_t::rrrrr, 0, SV}},                                                                               1 },
    { "1001100b110mmnnn", OAK_Dsp_mov,    {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::B, 0x0100}},                                                                                  1 },
    { "1001110a110rrrrr", OAK_Dsp_movr,   {{&oakdsp_t::rrrrr, 0x001f},               {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "1001110a111mmnnn", OAK_Dsp_movr,   {{&oakdsp_t::mmnnn, 0x001f},               {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "101xxxxadddddddd", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x1e00},             {&oakdsp_t::sdirect, 0x00ff},                {&oakdsp_t::A, 0x0100}},                                     1 },
    { "1100xxxavvvvvvvv", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x0e00, 1},          {&oakdsp_t::s_Imm, 0x00ff},                  {&oakdsp_t::A, 0x0100}},                                     1 },
    { "1101001111000000", OAK_Dsp_break,  {{0}},                                                                                                                                               1 },
    { "1101011110000000", OAK_Dsp_retd,   {{0}},                                                                                                                                               1 },
    { "1101011111000000", OAK_Dsp_retid,  {{0}},                                                                                                                                               1 },
    { "1101010a10000000", OAK_Dsp_calla,  {{&oakdsp_t::A, 0x0100}},                                                                                                                            3 },
    { "11010011100f0000", OAK_Dsp_cntx,   {{&oakdsp_t::cntx, 0x0010}},                                                                                                                         1 },
    { "110101001ab10000", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0,REPC},               {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "110101001ab10001", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0,DVM},                {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "110101001ab10010", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0,ICR},                {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "110101001ab10011", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0,X},                  {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "1101010a101110--", OAK_Dsp_mov,    {{&oakdsp_t::ldirect, 0xffff0000},         {&oakdsp_t::A, 0x0100}},                                                                                  2 },
    { "1101010a101111--", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x0100, A0L|mix_mode}, {&oakdsp_t::ldirect, 0xffff0000}},                                                                        2 },
    { "1101010a100110--", OAK_Dsp_mov,    {{&oakdsp_t::rb_rel_long,0xffff0000},      {&oakdsp_t::A, 0x0100}},                                                                                  2 },
    { "1101010a100111--", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x0100, A0L|mix_mode}, {&oakdsp_t::rb_rel_long,0xffff0000}},                                                                     2 },
    { "1101010a11011xxx", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x0007, 1},          {&oakdsp_t::rb_rel_long, 0xffff0000},        {&oakdsp_t::A, 0x0100}},                                     2 },
    { "1101010a11111xxx", OAK_Dsp_proc,   {{&oakdsp_t::ALU_ALM, 0x0007, 1},          {&oakdsp_t::ldirect, 0xffff0000},            {&oakdsp_t::A, 0x0100}},                                     2 },
    { "1101AB1011011000", OAK_Dsp_mov,    {{&oakdsp_t::AB, 0x0c00},                  {&oakdsp_t::rrrrr, 0x0000, X}},                                                                           1 },
    { "1101AB1010011000", OAK_Dsp_mov,    {{&oakdsp_t::AB, 0x0c00},                  {&oakdsp_t::rrrrr, 0x0000, DVM}},                                                                         1 },
    { "1101ab101AB10000", OAK_Dsp_mov,    {{&oakdsp_t::AB, 0x0c00},                  {&oakdsp_t::AB, 0x0060}},                                                                                 1 },
    { "1101000a1jjiiwqq", OAK_Dsp_msu,    {{&oakdsp_t::rJ_rI, 0x007f},               {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "1101ab101AB0cccc", OAK_Dsp_shfc,   {{&oakdsp_t::AB, 0x0c00},                  {&oakdsp_t::AB, 0x0060},                     {&oakdsp_t::Cond, 0x000f}},                                  1 },
    { "1101100a1ooooooo", OAK_Dsp_mov,    {{&oakdsp_t::rb_rel_short, 0x007f},        {&oakdsp_t::A, 0x0100}},                                                                                  1 },
    { "1101110a1ooooooo", OAK_Dsp_mov,    {{&oakdsp_t::rrrrr, 0x0100, A0L|mix_mode}, {&oakdsp_t::rb_rel_short, 0x007f}},                                                                       1 },
    { "11011x111vvvvvvv", OAK_Dsp_load,   {{&oakdsp_t::s_Imm, 0x007f},               {&oakdsp_t::rrrrr, 0x0400, STEPI|mix_mode}},                                                              1 },
    { "1101-00x0jjiiwqq", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::rJ_rI, 0x007f}},                                                                              1 },
    { "1101axxx0jjiiwqq", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0700},                 {&oakdsp_t::rJ_rI, 0x007f},                  {&oakdsp_t::A, 0x0800}},                                     1 },
    { "1110xxx1dddddddd", OAK_Dsp_proc,   {{&oakdsp_t::ALB, 0x0e00},                 {&oakdsp_t::l_Imm, 0xffff0000},              {&oakdsp_t::sdirect, 0x00ff}},                               2 },
    { "1110-000dddddddd", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0600, 1},              {&oakdsp_t::rrrrr, 0, Y},                    {&oakdsp_t::sdirect, 0x00ff}},                               1 },
    { "1110axx0dddddddd", OAK_Dsp_proc,   {{&oakdsp_t::MUL, 0x0600, 1},              {&oakdsp_t::rrrrr, 0, Y},                    {&oakdsp_t::sdirect, 0x00ff},      {&oakdsp_t::A, 0x0800}},  1 },
    { "1111bbbbdddddddd", OAK_Dsp_tstb,   {{&oakdsp_t::s_Imm, 0x0f00},               {&oakdsp_t::sdirect, 0x00ff}},                                                                            1 },
  };

  table_t()
  {
    gen_masks();
  }
  ~table_t() = default;
  table_t(const table_t&) = delete;
  table_t &operator=(const table_t&) = delete;

  void gen_masks()
  {
    for ( auto &te : table )
    {
      int len = strlen(te.recog);
      for ( int b = 0; b < len; b++ )
      {
        te.value <<= 1;
        te.mask <<= 1;

        if ( te.recog[b] == '1' || te.recog[b] == '0' )
          te.mask++;

        if ( te.recog[b] == '1' )
          te.value++;
      }

      for ( int j = 0; j < FUNCS_COUNT; j++ )
      {
        if ( te.funcs[j].func )
        {
          for ( int b = 0; b < 32; b++ )
          {
            if ( te.funcs[j].mask & (1 << b) )
              break;
            else
              te.funcs[j].shift++;
          }
        }
      }
    }
  }
};

//----------------------------------------------------------------------
bool oakdsp_t::use_table(insn_t &insn, const opcode_t &ptr, uint code, int start, int end)
{
  for ( int j = start; j <= end; j++ )
  {
    if ( !ptr.funcs[j].func )
      break;
    int value = (code & ptr.funcs[j].mask) >> ptr.funcs[j].shift;
    if ( !(this->*ptr.funcs[j].func)(insn, value, ptr.funcs[j].param) )
      return false;
  }
  return true;
}

//----------------------------------------------------------------------
void oakdsp_t::reset_ops(insn_t &insn)
{
  op = &insn.Op1;
  for ( int i=0; i < UA_MAXOP; i++ )
    insn.ops[i].type = o_void;
}

//----------------------------------------------------------------------
int oakdsp_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  uint code = ua_32bits(insn);
  uint prev_inst_code;
  op = &insn.Op1;
  int move_rb_to_reg = 0;

  int cnt = table_t::count();
  for ( int i = 0; i < cnt; i++ )
  {
    const auto &te = table_t::get(i);
    if ( (code & te.mask) == te.value )
    {
      insn.itype = te.itype;
      insn.cmd_cycles = te.cycles;
      insn.size = 1;

      if ( !use_table(insn, te, code, 0, FUNCS_COUNT - 1) )
      {
        reset_ops(insn);
        continue;
      }



      // mov #imm, pc --> near jump
      if ( insn.itype == OAK_Dsp_mov
        && insn.Op1.type == o_imm
        && insn.Op2.type == o_reg
        && insn.Op2.reg == PC )
      {
        insn.Op1.type = o_near;
        insn.Op1.dtype = dt_code;
        insn.Op1.addr = insn.Op1.value;
        insn.Op1.amode = amode_p;
      }


      // add(sub) #imm, reg  after  mov rb, reg instruction
      // #imm --> local var

      if ( insn.ea > 0 )
      {
        prev_inst_code = get_wide_byte(insn.ea - 1);

        if ( ((prev_inst_code & 0xfc1f) == 0x5806)
          || ((prev_inst_code & 0xffdf) == 0x5ec6) )
        {
          if ( (prev_inst_code & 0xfc1f) == 0x5806 ) // mov reg, reg
            move_rb_to_reg = (prev_inst_code >> 5) & 0x1f;
          else if ( (prev_inst_code & 0xffdf) == 0x5ec6 )       // mov reg, bx
            move_rb_to_reg = B0 + ((prev_inst_code >> 5) & 0x01);

          if ( insn.Op1.type == o_imm
            && (insn.Op2.reg == move_rb_to_reg
             || (insn.Op2.reg == A0L && move_rb_to_reg == A0)
             || (insn.Op2.reg == A1L && move_rb_to_reg == A1)
             || (insn.Op2.reg == B0L && move_rb_to_reg == B0)
             || (insn.Op2.reg == B1L && move_rb_to_reg == B1)) )
          {
            int16 tmp = insn.Op1.value;

            switch ( insn.itype )
            {
              case OAK_Dsp_sub:
              case OAK_Dsp_subv:
                tmp = - tmp;
                //no break
              case OAK_Dsp_add:
              case OAK_Dsp_addv:
                insn.Op1.addr   = tmp;
                insn.Op1.type   = o_local;
                insn.Op1.phtype = 1; // "#"
                insn.Op1.amode |= amode_signed;
                insn.Op1.amode |= amode_x;
                break;
            }
          }
        }
      }


      // add(sub) #imm, SP
      // #imm --> signed imm

      if ( insn.Op1.type == o_imm && insn.Op2.type == o_reg && insn.Op2.reg == SP )
      {
        switch ( insn.itype )
        {
          case OAK_Dsp_add:
          case OAK_Dsp_addv:
          case OAK_Dsp_sub:
          case OAK_Dsp_subv:
            insn.Op1.amode |= amode_signed;
            break;
        }
      }
      return insn.size;
    }
  }
  return 0;
}

//--------------------------------------------------------------------------
void interr(const insn_t &insn, const char *module)
{
  const char *name = nullptr;
  if ( insn.itype < OAK_Dsp_last )
    name = Instructions[insn.itype].name;
  warning("%a(%s): internal error in %s", insn.ea, name, module);
}
