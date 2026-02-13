#include "necv850.hpp"
#include <name.hpp>

//-------------------------------------------------------------------------
constexpr uint32 GHS         = 0x01;
constexpr uint32 GHS_LOCALS  = 0x02;
constexpr uint32 GHS_LP_ONLY = 0x04;
constexpr uint32 GHS_CALLT   = 0x08;
constexpr uint32 GCC_RESTORE = 0x02;
inline bool is_gcc_restore(uint32 spf_feature)
{
  return (spf_feature & (GHS|GCC_RESTORE)) == GCC_RESTORE;
}
inline bool is_ghs_ld4_sv5(uint32 spf_feature)
{
  constexpr uint32 ghs_ld4_sv5 = GHS|GHS_CALLT|GHS_LOCALS;
  return (spf_feature & ghs_ld4_sv5) == ghs_ld4_sv5;
}

//-------------------------------------------------------------------------
static special_func_t check_name(
        reglist_t *regs,
        uint32 *spf_feature,
        const char *name)
{
  while ( *name == '_' )
    ++name;
  special_func_t res = SPF_NONE;
  if ( strneq(name, "save_", 5) ) // GCC
    res = SPF_SAVE;
  else if ( strneq(name, "return_", 7) ) // GCC
    res = SPF_RETURN;
  if ( res != SPF_NONE )
  {
    *spf_feature = 0;
    const char *p = qstrchr(name, '_') + 1;
    if ( streq(p, "r2_r29") )
    {
      if ( regs != nullptr )
      {
        regs->add(rR2);
        regs->add_range(rR20, 10);
      }
      *spf_feature |= GCC_RESTORE;
      return res;
    }
    if ( streq(p, "r2_r31") )
    {
      if ( regs != nullptr )
      {
        regs->add(rR2);
        regs->add_range(rR20, 10);
        regs->add(rLP);
      }
      return res;
    }
    if ( streq(p, "r29") )
    {
      if ( regs != nullptr )
        regs->add(rR29);
      *spf_feature |= GCC_RESTORE;
      return res;
    }
    if ( streq(p, "r31") )
    {
      if ( regs != nullptr )
        regs->add(rLP);
      return res;
    }
    int reglo;
    int reghi;
    int len;
    if ( qsscanf(p, "r%u_r%u%n", &reglo, &reghi, &len) != 2 || p[len] != 0 )
      return SPF_NONE;
    if ( reghi == 29 )
    {
      if ( reglo < 20 || reglo > 28 )
        return SPF_NONE;
      if ( regs != nullptr )
        regs->add_range(reglo, 29 - reglo + 1);
      *spf_feature |= GCC_RESTORE;
      return res;
    }
    if ( reghi == 31 )
    {
      if ( reglo < 20 || reglo > 29 )
        return SPF_NONE;
      if ( regs != nullptr )
      {
        regs->add_range(reglo, 29 - reglo + 1);
        regs->add(rLP);
      }
      return res;
    }
    return SPF_NONE;
  }
  if ( strneq(name, "ghssave", 7) ) // GHS
    res = SPF_SAVE;
  else if ( strneq(name, "ghsload", 7) ) // GHS
    res = SPF_RETURN;
  if ( res != SPF_NONE )
  {
    *spf_feature = GHS;
    const char *p = name + 7;
    if ( strneq(p, "lp", 2) )
    {
      if ( regs != nullptr )
        regs->add(rLP);
      *spf_feature |= GHS_LP_ONLY;
      p += 2;
    }
    else
    {
      int reglo;
      int len;
      if ( qsscanf(p, "%u%n", &reglo, &len) != 1 )
        return SPF_NONE;
      if ( reglo < 20 || reglo > 29 )
        return SPF_NONE;

      if ( regs != nullptr )
      {
        regs->add_range(reglo, 29 - reglo + 1);
        regs->add(rLP);
      }
      p += len;
    }
    if ( p[0] == '\0' )
      *spf_feature |= GHS_LOCALS;
    else if ( streq(p, "a") )
      ;
    else
      return SPF_NONE;
    return res;
  }
  if ( strneq(name, "ghssv", 5) ) // GHS-callt
    res = SPF_SAVE;
  else if ( strneq(name, "ghsld", 5) ) // GHS-callt
    res = SPF_RETURN;
  if ( res != SPF_NONE )
  {
    *spf_feature = GHS | GHS_CALLT;
    const char *p = name + 5;
    if ( res == SPF_SAVE && *p == '5' || res == SPF_RETURN && *p == '4' )
      *spf_feature |= GHS_LOCALS;
    else if ( res == SPF_SAVE && *p == '4' || res == SPF_RETURN && *p == '2' )
      ;
    else
      return SPF_NONE;
    ++p;
    if ( streq(p, "lp") )
    {
      if ( regs != nullptr )
        regs->add(rLP);
      *spf_feature |= GHS_LP_ONLY;
    }
    else
    {
      int reglo;
      int len;
      if ( qsscanf(p, "r%u%n", &reglo, &len) != 1 || p[len] != 0 )
        return SPF_NONE;
      if ( reglo < 20 || reglo > 29 )
        return SPF_NONE;

      if ( regs != nullptr )
      {
        regs->add_range(reglo, 29 - reglo + 1);
        regs->add(rLP);
      }
    }
    return res;
  }
  return SPF_NONE;
}

//-------------------------------------------------------------------------
struct check_bytes_t
{
  qstring *name;
  func_t *fn;

  insn_t start_insn;
  bool start_insn_valid() const { return start_insn.size != 0; }

  ea_t start;
  ea_t end;

  check_bytes_t(qstring *_name, func_t *_fn, ea_t _start)
    : name(_name), fn(_fn), start(_start)
  {
    const segment_t *seg = getseg(start);
    end = seg == nullptr ? start : seg->end_ea;
    decode_insn(&start_insn, start);
  }

  bool check_gcc_save();
  bool check_gcc_return();
  bool check_ghs_save();
  bool check_ghs_load();
  bool check_ghs_callt_save();
  bool check_ghs_callt_load();

  bool get_word(uint16 *x, ea_t ea) const
  {
    if ( ea >= end || end - ea < 2 )
      return false;
    *x = ::get_word(ea);
    return true;
  }
  bool get_dword(uint32 *x, ea_t ea) const
  {
    if ( ea >= end || end - ea < 4 )
      return false;
    *x = ::get_dword(ea);
    return true;
  }

  bool check_word(ea_t ea, uint16 x) const
  {
    uint16 xx;
    return get_word(&xx, ea) && xx == x;
  }
  bool check_dword(ea_t ea, uint32 x) const
  {
    uint32 xx;
    return get_dword(&xx, ea) && xx == x;
  }
  size_t check_ghs_alloc_code(ea_t ea) const;
  size_t check_ghs_release_code(ea_t ea) const;

  static bool is_save_reg(uint32 x, int reg, uval_t off)
  {
    // st.w lp, off[sp]
    // rrrrr111|011RRRRR ddddddddddddddd1
    // FF63              off|1
    const uint32 insn = ((off & 0xFFFE) << 16)
                      | ((reg & 0x1F) << 11)
                      | 0x10763;
    return x == insn;
  }
  static bool is_load_reg(uint32 x, int reg, uval_t off)
  {
    // ld.w off[sp], lp
    // rrrrr111|001RRRRR ddddddddddddddd1
    // FF23              off|1
    const uint32 insn = ((off & 0xFFFE) << 16)
                      | ((reg & 0x1F) << 11)
                      | 0x10723;
    return x == insn;
  }
  static int get_save_load_reg(uint32 x)
  {
    // rrrrr111|011RRRRR ddddddddddddddd1
    return (x >> 11) & 0x1F;
  }
  // jmp [r10]
  static constexpr uint16 JMP_R10 = 0x006A;
  // jmp [lp]
  static constexpr uint16 JMP_LP  = 0x007F;
  // st.w lp, -4[r12]
  static constexpr uint32 SAVE_LP_R12  = 0xFFFDFF6C;
  // ld.w arg_4[sp], lp
  static constexpr uint32 LOAD_LP      = 0x0005FF23;
  // ld.h -6[r10], r12
  static constexpr uint32 GHS_LOAD_R12_6 = 0xFFFA672A;
  // and  0xFFFF, r12
  static constexpr uint32 GHS_AND_R12    = 0xFFFF66CC;
  // shl  2, r12
  static constexpr uint16 GHS_SHL_R12    = 0x62C2;
  // sub  r12, sp
  static constexpr uint16 GHS_SUB_R12    = 0x19AC;
  // ld.h -6[r10], r11
  static constexpr uint32 GHS_LOAD_R11_6 = 0xFFFA5F2A;
  // and  0xFFFF, r11
  static constexpr uint32 GHS_AND_R11    = 0xFFFF5ECB;
  // shl  2, r11
  static constexpr uint16 GHS_SHL_R11    = 0x5AC2;
  // sub  r11, sp
  static constexpr uint16 GHS_SUB_R11    = 0x19AB;
  // add  r12, sp
  static constexpr uint16 GHS_ADD_R12    = 0x19CC;
  // add  r29, sp
  static constexpr uint16 GHS_ADD_R29    = 0x19DD;
  // stdr ctpc, r10
  static constexpr uint32 STSR_CTPC_R10  = 0x004057F0;
  // stdr ctpc, lp
  static constexpr uint32 STSR_CTPC_LP   = 0x0040FFF0;
  // ld.hu -4[r10], r11
  static constexpr uint32 GHS_LOAD_R11_4 = 0xFFFD5FEA;
  // ld.hu [lp], r12
  static constexpr uint32 GHS_LOAD_R12_AT_LP = 0x000167FF;
  // ld.hu [lp], r29
  static constexpr uint32 GHS_LOAD_R29_AT_LP = 0x0001EFFF;
  // dispose 0, {lp}, [lp]
  static constexpr uint32 DISPOSE_0_LP_LP = 0x003F0640;

  static bool is_add_imm_sp(const insn_t &insn, int imm)
  {
    return insn.itype == NEC850_ADD
        && insn.Op1.type == o_imm
        && insn.Op1.value == uval_t(imm) //lint !e571 cast from 'int' to 'uval_t' results in sign extension
        && insn.Op2.is_reg(rSP)
        && insn.Op3.type == o_void;
  }

  // check that X is '{<reglo>-r29}'
  static int check_reglist_range(const op_t &x)
  {
    // assert: x.type == o_reglist
    reglist_t insn_regs(x);
    int reglo = insn_regs.first_reg();
    if ( reglo < 20 || reglo > 29 )
      return -1;
    reglist_t req_regs;
    req_regs.add_range(reglo, 29 - reglo + 1);
    if ( insn_regs != req_regs )
      return -1;
    return reglo;
  }
};

//-------------------------------------------------------------------------
//   ld.h -6[r10], r12
//   and  0xFFFF, r12
//   shl  2, r12
//   sub  r12, sp
// or
//   ld.h -6[r10], r11
//   and  0xFFFF, r11
//   shl  2, r11
//   sub  r11, sp
size_t check_bytes_t::check_ghs_alloc_code(ea_t ea) const
{
  uint32 x;
  if ( !get_dword(&x, ea) )
    return 0;
  if ( x == GHS_LOAD_R12_6 )
  {
    if ( !check_dword(ea +  4, GHS_AND_R12)
      || !check_word (ea +  8, GHS_SHL_R12)
      || !check_word (ea + 10, GHS_SUB_R12) )
    {
      return 0;
    }
    return 4 + 4 + 2 + 2;
  }
  if ( x == GHS_LOAD_R11_6 )
  {
    if ( !check_dword(ea +  4, GHS_AND_R11)
      || !check_word (ea +  8, GHS_SHL_R11)
      || !check_word (ea + 10, GHS_SUB_R11) )
    {
      return 0;
    }
    return 4 + 4 + 2 + 2;
  }
  return 0;
}

//-------------------------------------------------------------------------
//   stsr  ctpc, lp
//   ld.hu [lp], r12
//   add   r12, sp
// or
//   stsr  ctpc, lp
//   ld.hu [lp], r29
//   add   r29, sp
size_t check_bytes_t::check_ghs_release_code(ea_t ea) const
{
  if ( !check_dword(ea, STSR_CTPC_LP) )
    return false;
  uint32 x;
  if ( !get_dword(&x, ea + 4) )
    return 0;
  if ( x == GHS_LOAD_R12_AT_LP )
  {
    if ( !check_word(ea + 8, GHS_ADD_R12) )
      return 0;
    return 4 + 4 + 2;
  }
  if ( x == GHS_LOAD_R29_AT_LP )
  {
    if ( !check_word(ea + 8, GHS_ADD_R29) )
      return 0;
    return 4 + 4 + 2;
  }
  return 0;
}

//-------------------------------------------------------------------------
bool check_bytes_t::check_gcc_save()
{
  if ( start_insn.itype != NEC850_ADD
    || start_insn.Op1.type != o_imm
    || (start_insn.Op1.value & 3) != 0
    || start_insn.Op1.value < uval_t(-0x30)
    || start_insn.Op1.value > uval_t(-4)
    || !start_insn.Op2.is_reg(rSP)
    || start_insn.Op3.type != o_void )
  {
    return false;
  }

  uint nregs = (0 - start_insn.Op1.value) / 4;
  // assert: nregs <= 12
  uint reghi = nregs == 12 ? 31 : 29;
  ea_t ea = start + start_insn.size;
  for ( int i = 0; i < nregs; ++i, ea += 4 )
  {
    uint32 x;
    if ( !get_dword(&x, ea) )
      return false;
    uval_t off = i * 4;
    uint reglo = i == 10 ? 2 : 29 - i;
    if ( i == 11 || !is_save_reg(x, reglo, off) )
    {
      // the last register in *_r31 functions is rLP
      if ( i == nregs - 1 && is_save_reg(x, 31, off) )
      {
        reghi = 31;
        continue;
      }
      return false;
    }
  }
  if ( !check_word(ea, JMP_R10) )
    return false;

  if ( nregs == 1 )
  {
    if ( reghi == 31 )
      *name = "__ghssavelpa"; // GHS is more popular compiler than GCC
    else
      name->sprnt("__save_r%u", reghi);
  }
  else
  {
    if ( reghi == 31 )
      --nregs;
    // assert: nregs <= 11
    uint reglo = nregs == 11 ? 2 : 30 - nregs;
    name->sprnt("__save_r%u_r%u", reglo, reghi);
  }
  fn->start_ea = start;
  fn->end_ea = ea + 2;
  return true;
}

//-------------------------------------------------------------------------
bool check_bytes_t::check_gcc_return()
{
  if ( start_insn.itype != NEC850_LD_W
    || start_insn.Op1.type != o_displ
    || start_insn.Op1.addr != 0
    || start_insn.Op1.phrase != rSP
    || start_insn.Op2.type != o_reg )
  {
    return false;
  }
  uint reghi;
  if ( start_insn.Op2.reg == rR29 )
    reghi = 29;
  else if ( start_insn.Op2.reg == rLP )
    reghi = 31;
  else
    return false;

  uint nregs = 1;
  ea_t ea = start + start_insn.size;
  for ( ; reghi != 31 && nregs <= 12; ++nregs, ea += 4 )
  {
    uint32 x;
    if ( !get_dword(&x, ea) )
      return false;
    uval_t off = nregs * 4;
    uint reglo = nregs == 10 ? 2 : 29 - nregs;
    if ( nregs == 11 || !is_load_reg(x, reglo, off) )
    {
      // the last register in *_r31 functions is rLP
      if ( is_load_reg(x, 31, off) )
      {
        reghi = 31;
        continue;
      }
      break;
    }
  }
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  if ( !is_add_imm_sp(insn, nregs * 4) )
    return false;
  ea += insn.size;
  if ( !check_word(ea, JMP_LP) )
    return false;

  if ( nregs == 1 )
  {
    if ( reghi == 31 )
      *name = "__ghsloadlp"; // GHS is more popular compiler than GCC
    else
      name->sprnt("__return_r%u", reghi);
  }
  else
  {
    if ( reghi == 31 )
      --nregs;
    // assert: nregs <= 11
    uint reglo = nregs == 11 ? 2 : 30 - nregs;
    name->sprnt("__return_r%u_r%u", reglo, reghi);
  }
  fn->start_ea = start;
  fn->end_ea = ea + 2;
  return true;
}

//-------------------------------------------------------------------------
bool check_bytes_t::check_ghs_save()
{
  // mov sp, r12
  if ( start_insn.itype != NEC850_MOV
    || !start_insn.Op1.is_reg(rSP)
    || !start_insn.Op2.is_reg(rR12) )
  {
    return false;
  }

  ea_t ea = start + start_insn.size;
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  // add -8, sp
  if ( insn.itype != NEC850_ADD
    || insn.Op1.type != o_imm
    || (insn.Op1.value & 3) != 0
    || insn.Op1.value < uval_t(-0x14)
    || insn.Op1.value > uval_t(-4)
    || !insn.Op2.is_reg(rSP)
    || insn.Op3.type != o_void )
  {
    return false;
  }
  uint nregs = (0 - insn.Op1.value) / 4;

  ea += insn.size;
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  ea_t fn_end = BADADDR;
  if ( insn.itype == NEC850_BR ) // br  save29
  {
    fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
  }
  // else flow to _save27a

  uint32 x;
  if ( !get_dword(&x, ea) )
    return false;
  int reglo = get_save_load_reg(x);
  if ( reglo < 20 || reglo == 30 )
    return false;
  constexpr int splits[3] = { 22, 26, 29 };
  if ( reglo == 31 )
  {
    if ( nregs != 1 )
      return false;
  }
  else
  {
    for ( int split : splits )
    {
      if ( reglo <= split )
      {
        if ( nregs + reglo - split != 2 )
          return false;
        break;
      }
    }
  }

  int reg = reglo;
  for ( int split : splits )
  {
    if ( reg > split )
      continue;
    for ( ; reg <= split; ++reg )
    {
      uval_t off = (split - reg) * 4;
      if ( !get_dword(&x, ea) || !is_save_reg(x, reg, off) )
        return false;
      ea += 4;
    }
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
    if ( split == 29 )
      break;
    int imm = split == 22 ? -16 : -12;
    if ( !is_add_imm_sp(insn, imm) )
      return false;
    ea += insn.size;
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
    // jr _save27a
    if ( insn.itype != NEC850_JR )
      return false;
    if ( fn_end == BADADDR )
      fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
  }
  if ( reglo != 31 )
  {
    // mov r10, r29
    if ( insn.itype != NEC850_MOV
      || !insn.Op1.is_reg(rR10)
      || !insn.Op2.is_reg(rR29) )
    {
      return false;
    }
    ea += insn.size;
  }
  // st.w lp, -4[r12]
  if ( !check_dword(ea, SAVE_LP_R12) )
    return false;
  ea += 4;

  // check locals allocation
  size_t alloc_code_size = check_ghs_alloc_code(ea);
  ea += alloc_code_size;

  if ( !check_word(ea, JMP_R10) )
    return false;
  if ( fn_end == BADADDR )
    fn_end = ea + 2;

  if ( reglo == 31 )
    name->sprnt("__ghssavelp%s", alloc_code_size > 0 ? "" : "a");
  else
    name->sprnt("__ghssave%u%s", reglo, alloc_code_size > 0 ? "" : "a");
  // assert: fn_end != BADADDR
  fn->start_ea = start;
  fn->end_ea = fn_end;
  return true;
}

//-------------------------------------------------------------------------
bool check_bytes_t::check_ghs_load()
{
  // mov imm, r12
  if ( start_insn.itype != NEC850_MOV
    || start_insn.Op1.type != o_imm
    || start_insn.Op1.value > 9
    || !start_insn.Op2.is_reg(rR12) )
  {
    return false;
  }
  int nregs = start_insn.Op1.value;

  ea_t ea = start + start_insn.size;
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  ea_t fn_end = BADADDR;
  if ( insn.itype == NEC850_BR ) // br  load29
  {
    fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
  }
  // else flow to _load27

  int reglo = 29 - nregs;
  // assert: reglo >= 20 && reglo <= 29
  constexpr int splits[3] = { 22, 26, 29 };
  int reg = reglo;
  for ( int split : splits )
  {
    if ( reg > split )
      continue;
    for ( ; reg <= split; ++reg )
    {
      uval_t off = (29 - reg) * 4;
      uint32 x;
      if ( !get_dword(&x, ea) || !is_load_reg(x, reg, off) )
        return false;
      ea += 4;
    }
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
    if ( split == 29 )
      break;
    // jr _load27
    if ( insn.itype != NEC850_JR )
      return false;
    if ( fn_end == BADADDR )
      fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
  }
  // shl  2, r12
  if ( !check_word(ea, GHS_SHL_R12) )
    return false;
  ea += 2;
  // add  r12, sp
  if ( !check_word(ea, GHS_ADD_R12) )
    return false;
  ea += 2;
  // ld.w arg_4[sp], lp
  if ( !check_dword(ea, LOAD_LP) )
    return false;
  ea += 4;
  // add  8, sp
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  if ( !is_add_imm_sp(insn, 8) )
    return false;
  ea += insn.size;
  // jmp  [lp]
  if ( !check_word(ea, JMP_LP) )
    return false;
  if ( fn_end == BADADDR )
    fn_end = ea + 2;

  name->sprnt("__ghsload%u", reglo);
  QASSERT(10533, fn_end != BADADDR);
  fn->start_ea = start;
  fn->end_ea = fn_end;
  return true;
}

//-------------------------------------------------------------------------
bool check_bytes_t::check_ghs_callt_save()
{
  // prepare {lp}, 0
  if ( start_insn.itype != NEC850_PREPARE_i
    || start_insn.Op1.type != o_reglist
    || reglist_t(start_insn.Op1) != reglist_t(rLP)
    || start_insn.Op2.type != o_imm
    || start_insn.Op2.value != 0 )
  {
    return false;
  }

  ea_t ea = start + start_insn.size;
  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  int reglo = -1;
  // prepare {r24-r29}, 0 -- optional
  if ( insn.itype == NEC850_PREPARE_i )
  {
    if ( insn.Op1.type != o_reglist
      || insn.Op2.type != o_imm
      || insn.Op2.value != 0 )
    {
      return false;
    }
    reglo = check_reglist_range(insn.Op1);
    if ( reglo == -1 )
      return false;
    ea += insn.size;
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
  }

  ea_t fn_end = BADADDR;
  // br ghssv4r22return/ghssv5return -- optional
  if ( insn.itype == NEC850_BR )
  {
    fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
  }

  // jr ghssv5return -- an optional far jump to another obj-file
  if ( insn.itype == NEC850_JR && insn.Op1.type == o_near )
  {
    if ( fn_end == BADADDR )
      fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
  }

  // except ghssv4lp and ghssv5lp
  if ( reglo != -1 )
  {
    if ( insn.itype != NEC850_STSR
      || !insn.Op1.is_reg(rCTPC)
      || !insn.Op2.is_reg(rR29) )
    {
      return false;
    }
    ea += insn.size;
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
  }

  char alloc_flag;
  if ( insn.itype == NEC850_CTRET )
  {
    alloc_flag = '4';
    ea += insn.size;
  }
  else
  {
    // br ghssvlp -- optional
    if ( insn.itype == NEC850_BR )
    {
      if ( fn_end == BADADDR )
        fn_end = ea + insn.size;
      ea = to_ea(insn.cs, insn.Op1.addr);
    }
    // stsr  ctpc, r10
    // ld.hu -4[r10], r11
    // sub   r11, sp
    // jmp   [r10]
    if ( !check_dword(ea +  0, STSR_CTPC_R10)
      || !check_dword(ea +  4, GHS_LOAD_R11_4)
      || !check_word (ea +  8, GHS_SUB_R11)
      || !check_word (ea + 10, JMP_R10) )
    {
      return false;
    }
    alloc_flag = '5';
    ea += 4 + 4 + 2 + 2;
  }
  if ( fn_end == BADADDR )
    fn_end = ea;

  if ( reglo == -1 )
    name->sprnt("___ghssv%clp", alloc_flag);
  else
    name->sprnt("___ghssv%cr%u", alloc_flag, uint(reglo));
  // assert: fn_end != BADADDR
  fn->start_ea = start;
  fn->end_ea = fn_end;
  return true;
}

//-------------------------------------------------------------------------
bool check_bytes_t::check_ghs_callt_load()
{
  // check locals release
  ea_t ea = start;
  size_t release_code_size = check_ghs_release_code(ea);
  ea += release_code_size;

  insn_t insn;
  if ( decode_insn(&insn, ea) <= 0 )
    return false;
  ea_t fn_end = BADADDR;
  // br ___ghsld2r20 -- optional after the release code
  if ( release_code_size > 0 && insn.itype == NEC850_BR )
  {
    fn_end = ea + insn.size;
    ea = to_ea(insn.cs, insn.Op1.addr);
    if ( decode_insn(&insn, ea) <= 0 )
      return false;
  }

  int reglo = -1;
  // dispose 0, {r20-r29} -- optional
  if ( insn.itype == NEC850_DISPOSE_r0 )
  {
    if ( insn.Op2.type != o_reglist
      || insn.Op1.type != o_imm
      || insn.Op1.value != 0 )
    {
      return false;
    }
    reglo = check_reglist_range(insn.Op2);
    if ( reglo == -1 )
      return false;
    ea += insn.size;
    if ( decode_insn(&insn, ea) <= 0 )
      return false;

    // br ___ghsldX4return -- optional
    if ( insn.itype == NEC850_BR )
    {
      if ( fn_end == BADADDR )
        fn_end = ea + insn.size;
      ea = to_ea(insn.cs, insn.Op1.addr);
      if ( decode_insn(&insn, ea) <= 0 )
        return false;
    }
  }

  // dispose 0, {lp}, [lp]
  if ( !check_dword(ea, DISPOSE_0_LP_LP) )
    return false;
  ea += 4;
  if ( fn_end == BADADDR )
    fn_end = ea;

  char release_flag = release_code_size > 0 ? '4' : '2';
  if ( reglo == -1 )
    name->sprnt("___ghsld%clp", release_flag);
  else
    name->sprnt("___ghsld%cr%u", release_flag, uint(reglo));
  // assert: fn_end != BADADDR
  fn->start_ea = start;
  fn->end_ea = fn_end;
  return true;
}

//-------------------------------------------------------------------------
static bool check_thunk(qstring *name, func_t *fn, ea_t ea, bool is_callt)
{
  check_bytes_t bytes(name, fn, ea);
  if ( !bytes.start_insn_valid() )
    return false;
  if ( !is_callt )
  {
    return bytes.check_gcc_save()
        || bytes.check_gcc_return()
        || bytes.check_ghs_save()
        || bytes.check_ghs_load();
  }
  else
  {
    return bytes.check_ghs_callt_save()
        || bytes.check_ghs_callt_load();
  }
}

//-------------------------------------------------------------------------
static void mark_function(func_t *pfn, const qstring &name)
{
  // remove hindering functions with dummy names (i.e. IDA-recognized)
  // for each chunk in the FN range
  ea_t ea = pfn->start_ea;
  const func_t *fch = get_fchunk(ea);
  if ( fch == nullptr )
    fch = get_next_fchunk(ea);
  while ( fch != nullptr && fch->start_ea < pfn->end_ea )
  {
    ea_t func_ea = is_func_tail(fch) ? fch->owner : fch->start_ea;
    fch = get_next_fchunk(fch->start_ea); // before del_func!
    if ( has_dummy_name(get_flags32(func_ea)) )
      del_func(func_ea);
  }
  // change the name before creating the function
  // (to avoid unnecessary check_thunk() during creation_
  set_name(ea, name.begin(), SN_FORCE|SN_MULTI);
  pfn->flags |= FUNC_LIB | FUNC_THUNK;
  create_insn(ea);
  add_func_ex(pfn);
}

//-------------------------------------------------------------------------
static special_func_t check_name_or_thunk(
        reglist_t *regs,
        uint32 *spf_feature,
        ea_t ea,
        bool is_callt)
{
  qstring name;
  if ( get_name(&name, ea, GN_NOT_DUMMY) > 0
    && cleanup_name(&name, ea, name.c_str(), CN_KEEP_TRAILING_DIGITS) )
  {
    special_func_t res = check_name(regs, spf_feature, name.begin());
    if ( res != SPF_NONE )
      return res;
  }
  func_t fn;
  if ( check_thunk(&name, &fn, ea, is_callt) )
  {
    special_func_t res = check_name(regs, spf_feature, name.begin());
    if ( res == SPF_NONE )
      TB_INTERR_OR_RETURN(10534, SPF_NONE);
    // mark possible subsequent functions too
    do
    {
      mark_function(&fn, name);
    }
    while ( check_thunk(&name, &fn, fn.end_ea, is_callt) );
    return res;
  }
  return SPF_NONE;
}

//-------------------------------------------------------------------------
// jarl  save..., r10
// jarl  return..., lp
// jr    return...     -- the tail call
// callt save...
static special_func_t check_call(
        const procmod_t &pm,
        reglist_t *regs,
        uint32 *spf_feature,
        const insn_t &insn)
{
  switch ( insn.itype )
  {
    case NEC850_JARL:
    case NEC850_JR:
    case NEC850_CALLT:
      if ( insn.Op1.type == o_near )
        break;
      [[fallthrough]];
    default:
      return SPF_NONE;
  }
  int retreg = -1;
  if ( insn.itype == NEC850_JARL )
  {
    retreg = insn.Op2.reg;
    if ( retreg != rLP && retreg != rR10 )
      return SPF_NONE;
  }
  ea_t target = pm.to_ea(insn.cs, insn.Op1.addr);
  bool is_callt = insn.itype == NEC850_CALLT;
  special_func_t res = check_name_or_thunk(regs, spf_feature,
                                           target, is_callt);
  if ( res == SPF_SAVE )
  {
    if ( insn.itype == NEC850_JR )
      return SPF_NONE;
    if ( (*spf_feature & (GHS|GHS_CALLT)) == (GHS|GHS_CALLT) )
      return is_callt ? res : SPF_NONE;
    if ( is_callt )
      return SPF_NONE;
    // assert: insn.itype == NEC850_JARL
    return retreg == rR10 ? res : SPF_NONE;
  }
  if ( res == SPF_RETURN )
  {
    if ( insn.itype != NEC850_JARL )
      return res;
    return retreg == rLP ? res : SPF_NONE;
  }
  return SPF_NONE;
}

//-------------------------------------------------------------------------
// ENTRY_EA if PROLOG the address of the function start
//          else the address after the function end
static bool handle_ghs_func_with_locals(
        const procmod_t &pm,
        uval_t *locals,
        ea_t entry_ea,
        bool prolog)
{
  if ( prolog ) // go back
  {
    if ( entry_ea < 2 )
      return false;
    entry_ea -= 2;
  }
  else // go forward
  {
    if ( entry_ea > pm.eah().ea_space_end() - 2 )
      return false;
  }
  if ( !is_defarg0(get_flags32(entry_ea)) )
    create_word(entry_ea, 2);
  if ( locals != nullptr )
    *locals = get_word(entry_ea);
  return true;
}

//-------------------------------------------------------------------------
special_func_t nec850_t::is_special_func_call(
        reglist_t *regs,
        uval_t *locals,
        const insn_t &insn) const
{
  uint32 spf_feature;
  special_func_t res = check_call(*this, regs, &spf_feature, insn);
  if ( res == SPF_SAVE
    && (spf_feature & (GHS|GHS_LOCALS)) == (GHS|GHS_LOCALS) )
  {
    // ld.h -6[r10], r12   stsr  ctpc, r10
    // and  0xFFFF, r12    ld.hu -4[r10], r11
    // shl  2, r12         sub   r11, sp
    // sub  r12, sp
    if ( handle_ghs_func_with_locals(*this, locals, insn.ea, true) )
    {
      if ( locals != nullptr && (spf_feature & GHS_CALLT) == 0 )
        *locals *= 4;
      return res;
    }
  }
  else if ( res == SPF_RETURN && is_ghs_ld4_sv5(spf_feature) )
  {
    // stsr  ctpc, lp
    // ld.hu [lp], reg
    // add   reg, sp
    ea_t entry_ea = insn.ea + insn.size;
    if ( handle_ghs_func_with_locals(*this, locals, entry_ea, false) )
      return res;
  }
  if ( locals != nullptr )
    *locals = 0;
  return res;
}

//-------------------------------------------------------------------------
bool nec850_t::special_func_spoils(
        reglist_t *regs,
        const insn_t &insn) const
{
  uint32 spf_feature;
  switch ( check_call(*this, regs, &spf_feature, insn) )
  {
    case SPF_SAVE:
      regs->clear();
      regs->add(rSP);
      // 'ghssv4*' do not spoil R10
      if ( (spf_feature & (GHS|GHS_CALLT|GHS_LOCALS)) != (GHS|GHS_CALLT) )
        regs->add(rR10);  // used as a scratch register
      if ( (spf_feature & GHS) == 0 )
        return true; // GCC functions don't spoil anything extra
      if ( (spf_feature & (GHS_LOCALS|GHS_LP_ONLY)) == GHS_LP_ONLY )
        return true; // 'ghssavelpa/ghssv4lp' don't spoil anything extra
      if ( (spf_feature & GHS_CALLT) == 0 )
      {
        regs->add(rR12);  // R12 is the initial SP
        // @igor says "In some versions r11 is spoiled too"
        // e.g. v850e1_firmware.bin 7DAC
        regs->add(rR11);
      }
      else if ( (spf_feature & GHS_LOCALS) != 0 )
      {
        regs->add(rR11);  // used as a scratch register
      }
      if ( (spf_feature & GHS_LP_ONLY) == 0 )
        regs->add(rR29);  // R29 points after the call
      return true;
    case SPF_RETURN:
      regs->add(rSP);
      regs->add(rLP);   // LP is always used as a return register
      if ( (spf_feature & GHS) != 0 )
      {
        if ( (spf_feature & GHS_CALLT) == 0 )
        {
          // 'ghsloadlp' doesn't spoil anything extra
          if ( (spf_feature & GHS_LP_ONLY) == 0 )
            regs->add(rR12);    // R12 is the SP delta
        }
        else
        {
          // only 'ghsld4lp' spoils R12
          constexpr uint32 ghsld4lp = GHS_LOCALS|GHS_LP_ONLY;
          if ( (spf_feature & ghsld4lp) == ghsld4lp )
            regs->add(rR12);    // R12 is the SP delta
        }
      }
      return true;
    default:
      return false;
  }
}

//-------------------------------------------------------------------------
bool nec850_t::is_special_save_func(const insn_t &insn) const
{
  uint32 spf_feature;
  special_func_t res = check_call(*this, nullptr, &spf_feature, insn);
  return res == SPF_SAVE;
}

//-------------------------------------------------------------------------
bool nec850_t::is_special_save_alloc_func(const insn_t &insn) const
{
  uint32 spf_feature;
  special_func_t res = check_call(*this, nullptr, &spf_feature, insn);
  return res == SPF_SAVE
      && (spf_feature & (GHS|GHS_LOCALS)) == (GHS|GHS_LOCALS);
}

//-------------------------------------------------------------------------
bool nec850_t::is_special_save_r29_func(const insn_t &insn) const
{
  uint32 spf_feature;
  special_func_t res = check_call(*this, nullptr, &spf_feature, insn);
  // R29 points after the call
  return res == SPF_SAVE && (spf_feature & (GHS|GHS_LP_ONLY)) == GHS;
}

//-------------------------------------------------------------------------
bool nec850_t::is_special_return_func(const insn_t &insn) const
{
  uint32 spf_feature;
  special_func_t res = check_call(*this, nullptr, &spf_feature, insn);
  if ( res != SPF_RETURN )
  {
    // FIXME we cannot recognize yet some CALLT return functions
    // see IDA-6572
    // so we check a simple guess
    if ( insn.itype == NEC850_CALLT && insn.Op1.type == o_near )
    {
      ea_t target = to_ea(insn.cs, insn.Op1.addr);
      insn_t tmp;
      if ( decode_insn(&tmp, target) != 0 && is_ret_itype(tmp) )
        return true;
    }
    return false;
  }
  if ( is_gcc_restore(spf_feature) )
  {
    // jr __return_r27_r29 is the 'tail' return insn
    return insn.itype == NEC850_JR;
  }
  // we cannot update SPD after a noret function so we don't format the
  // local size word for ghsld4* functions. do it right now!
  if ( is_ghs_ld4_sv5(spf_feature) )
    handle_ghs_func_with_locals(*this, nullptr, insn.ea + insn.size, false);
  return true;
}

//-------------------------------------------------------------------------
void nec850_t::check_call_table(ea_t start_ea) const
{
  const segment_t *seg = getseg(start_ea);
  if ( seg == nullptr )
    return;
  size_t n = (seg->end_ea - start_ea) / 2;
  if ( n > 64 ) // the call table has no more than 64 entries
    n = 64;
  for ( size_t i = 0; i < n; ++i )
  {
    ea_t ea = start_ea + i * 2;
    uint16 w = get_word(ea);
    ea_t target_ea = eah().trunc_uval(start_ea + w);
    if ( target_ea <= ea )
      break;
    // check a possible function start
    insn_t insn;
    if ( decode_insn(&insn, target_ea) <= 0 )
      break;
    bool ok;
    switch ( insn.itype )
    {
      case NEC850_PREPARE_i:
      case NEC850_PREPARE_sp:
        ok = true;
        break;
      case NEC850_DISPOSE_r:
        // dispose 0, {lp}, [lp] (ghsld2lp)
        ok = insn.Op3.is_reg(rLP) && reglist_t(insn.Op2).has(rLP);
        break;
      case NEC850_DISPOSE_r0:
        // dispose 0, {r20-r29} (ghsld2r20)
        ok = reglist_t(insn.Op2).has(rR29);
        break;
      case NEC850_STSR:
        // stsr ctpc, lp (ghsld4lp)
        ok = insn.Op1.is_reg(rCTPC) && insn.Op2.is_reg(rLP);
        break;
      case NEC850_ADD:
      case NEC850_ADDI:
        // add -0x18, sp (just in case)
        ok = insn.Op1.type == o_imm
          && insn.Op2.is_reg(rSP)
          && (insn.Op3.type == o_void || insn.Op3.is_reg(rSP))
          && sval_t(insn.Op1.value) < 0;
        break;
      default:
        ok = false;
        break;
    }
    if ( !ok )
      break;
    // mark the entry
    create_word(ea, 2);
    auto_make_proc(target_ea);
    op_offset(ea, 0, REF_OFF16, BADADDR, start_ea);
    if ( target_ea < start_ea + n * 2 )
      n = (target_ea - start_ea) / 2;
  }
}
