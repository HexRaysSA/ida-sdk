/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "7900.hpp"

static const char *const BitNamesCPU[] = { "IPL", "N", "V", "m", "x", "D", "I", "Z", "C" };
static const char *const BitNamesPUL[] = { "PS", "0", "DT", "DP0", "Y", "X", "B", "A" };

//----------------------------------------------------------------------
class out_m7900_t : public outctx_t
{
  out_m7900_t(void) = delete; // not used
public:
  void OutReg(int rgnum) { out_register(ph.reg_names[rgnum]); }
  int OutVarName(const op_t &x);
  void SetDP0Plus(const op_t &x) { out_value(x, OOFW_IMM | OOFW_16); }
  void GetNumPUL(uval_t data);
  void GetNumDPRn(uval_t data);
  void GetCLPFlags(uval_t data);
  ea_t OutDPRReg(ea_t Addr, uval_t gDPReg);
  void OutDPR(uint32 Data);
  void OutDT(uint32 Data);
  void OutIMM(uint32 Data);
  void MOVRB(void);
  void MOVR(void);
  void MOV(const op_t &x);

  bool out_operand(const op_t &x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_m7900_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_m7900_t)

//----------------------------------------------------------------------
void out_m7900_t::GetNumPUL(uval_t data)
{
  int bitOut = 0;
  for ( int i=0; i < 8; i++ )
  {
    if ( GETBIT(data, i) == 1 )
    {
      if ( bitOut != 0 )
        out_symbol(',');
      out_register(BitNamesPUL[7-i]);
      if ( bitOut == 0 )
        bitOut++;
    }
  }
}

//----------------------------------------------------------------------
void out_m7900_t::GetNumDPRn(uval_t data)
{
  switch ( data )
  {
    case 0x1:
      out_symbol('0');
      break;
    case 0x2:
      out_symbol('1');
      break;
    case 0x4:
      out_symbol('2');
      break;
    case 0x8:
      out_symbol('3');
      break;
    default:
      out_symbol('(');
      bool add_comma = false;
      for ( int i=0; i < 4; ++i )
      {
        if ( GETBIT(data, i) == 1 )
        {
          if ( add_comma )
            out_symbol(',');
          out_long(i, 10);
          add_comma = true;
        }
      }
      out_symbol(')');
      break;
  }
}

//----------------------------------------------------------------------
void out_m7900_t::GetCLPFlags(uval_t data)
{
  int bitOut = 0;
  for ( int i=0; i < 8; i++ )
  {
    if ( GETBIT(data, i) == 1 )
    {
      if ( bitOut != 0 )
        out_symbol(',');
      out_register(BitNamesCPU[8-i]);
      if ( bitOut == 0 )
        bitOut++;
    }
  }
}

//----------------------------------------------------------------------
int out_m7900_t::OutVarName(const op_t &x)
{
  return out_name_expr(x, to_ea(insn.cs, x.addr), x.addr);
}

//----------------------------------------------------------------------
static int getNumDPR(uval_t iDPR )
{
  switch ( iDPR )
  {
    case 0x0: return 0;
    case 0x40: return 1;
    case 0x80: return 2;
    case 0xC0: return 3;
  }
  return 0;

}

//----------------------------------------------------------------------
ea_t out_m7900_t::OutDPRReg(ea_t Addr, uval_t gDPReg)
{
  if ( gDPReg == 1 )
  {
    char szTemp[5];
    uval_t Data = Addr;
    Data &= 0xC0;
    qsnprintf(szTemp, sizeof(szTemp), "DP%d", getNumDPR(Data));
    out_register(szTemp);
    Addr &= 0xFF3F;
  }
  else
  {
    out_keyword("DP0");
  }
  return Addr;
}

//----------------------------------------------------------------------
static sel_t GetValueDP(const insn_t &insn, int DPR )
{
  if ( getDPReg == 1 )
  {
    switch ( DPR )
    {
      case 0x0: return getDPR0;
      case 0x40: return getDPR1;
      case 0x80: return getDPR2;
      case 0xC0: return getDPR3;
    }
  }
  return 0;
}

//----------------------------------------------------------------------
void out_m7900_t::OutDPR(uint32 Data)
{
  ea_t Val = Data;
  Val = OutDPRReg(Val, getDPReg);
  out_symbol(':');
  out_printf(COLSTR("%a",SCOLOR_NUMBER), Val+GetValueDP(insn, Data&0xC0));
}

//----------------------------------------------------------------------
void out_m7900_t::OutDT(uint32 Data)
{
  out_register("DT");
  out_symbol('+');
  out_symbol(':');
  out_printf(COLSTR("%X",SCOLOR_NUMBER), Data);
}

//----------------------------------------------------------------------
void out_m7900_t::OutIMM(uint32 Data)
{
  out_symbol('#');
  out_printf(COLSTR("%x",SCOLOR_NUMBER), Data);
}

//----------------------------------------------------------------------
void out_m7900_t::MOVRB(void)
{
  int i;
  uint32 Val1, Val2;
  uchar code = get_byte(insn.ea+1);
  uchar nib  = (code >> 4) & 0xF;
  uchar count = code & 0x0F;

  switch ( nib )
  {
    case 0x0:
      for ( i=0; i < count; i++ )
      {
        Val1 = get_byte(insn.ea+2+(i*2));// imm
        Val2 = get_byte(insn.ea+2+(i*2)+1);// dd

        // DPRxx
        OutDPR(Val2);
        out_symbol(',');
        // imm
        OutIMM(Val1);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x1:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_word(insn.ea+2+(i*3));// mmll
        Val1 = get_byte(insn.ea+2+(i*3)+2);// dd

        // DPRxx
        OutDPR(Val1);
        out_symbol(',');
        // DPR
        OutDT(Val2);
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x2:
      for ( i=0; i < count; i++ )
      {
        Val1 = get_byte(insn.ea+2+(i*3));// imm
        Val2 = get_word(insn.ea+2+(i*3)+1);// mmll

        // DPRxx
        OutDT(Val2);
        out_symbol(',');
        // IMM
        OutIMM(Val1);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x4:
      for ( i=0; i < count; i++ )
      {
        Val1 = get_byte(insn.ea+2+(i*2));// dd1
        Val2 = get_byte(insn.ea+2+(i*2)+1);// dd2

        // DPRxx
        OutDPR(Val2);
        out_symbol(',');
        // DPRxx
        OutDPR(Val1);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x6:
      for ( i=0; i < count; i++ )
      {
        Val1 = get_byte(insn.ea+2+(i*3));// imm
        Val2 = get_word(insn.ea+2+(i*3)+1);// mmll

        // DPRxx
        OutDT(Val2);
        out_symbol(',');
        // DPR
        OutDPR(Val1);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x7:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_byte(insn.ea+2+(i*3));// mmll
        Val1 = get_word(insn.ea+2+(i*3)+1);// dd

        // DPRxx
        OutDT(Val1);
        out_symbol(',');
        // DPR
        OutDPR(Val2);
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x8:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_word(insn.ea+2+(i*3));// mmll
        Val1 = get_byte(insn.ea+2+(i*3)+2);// dd

        // DPRxx
        OutDPR(Val1);
        out_symbol(',');
        // DT
        OutDT(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0xA:
      for ( i=0; i < count; i++ )
      {
        Val1 = get_word(insn.ea+2+(i*4));// imm
        Val2 = get_word(insn.ea+2+(i*4)+2);// mmll

        // DPRxx
        OutDT(Val2);
        out_symbol(',');
        // DT
        OutDT(Val1);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;
  }
}

//----------------------------------------------------------------------
void out_m7900_t::MOVR(void)
{
  int i;
  uint32 Val1, Val2;
  uchar code = get_byte(insn.ea+1);
  uchar nib  = (code >> 4) & 0xF;
  uchar count = code & 0x0F;

  switch ( nib )
  {
    case 0x0:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_word(insn.ea+2+(i*3));// mmll
        Val1 = get_byte(insn.ea+2+(i*3)+2);// dd

        // DPRxx
        OutDPR(Val1);
        out_symbol(',');
        // DT
        OutDT(Val2);
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x1:
      for ( i=0; i < count; i++ )
      {
        if ( getFlag_M == 0 )
        {
          Val2 = get_word(insn.ea+2+(i*3));// imm
          Val1 = get_byte(insn.ea+2+(i*3)+2);// dd
        }
        else
        {
          Val2 = get_byte(insn.ea+2+(i*2));// imm
          Val1 = get_byte(insn.ea+2+(i*2)+1);// dd
        }

        // DPRxx
        OutDPR(Val1);
        out_symbol(',');
        // imm
        OutIMM(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x3:
      for ( i=0; i < count; i++ )
      {
        if ( getFlag_M == 0 )
        {
          Val2 = get_word(insn.ea+2+(i*4));// imm
          Val1 = get_word(insn.ea+2+(i*4)+2);// llmm
        }
        else
        {
          Val2 = get_byte(insn.ea+2+(i*3));// imm
          Val1 = get_word(insn.ea+2+(i*3)+1);// llmm
        }

        // DPRxx
        OutDT(Val1);
        out_symbol(',');
        // IMM
        OutIMM(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x5:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_byte(insn.ea+2+(i*2));// dd
        Val1 = get_byte(insn.ea+2+(i*2)+1);// dd

        // DPRxx
        OutDPR(Val1);
        out_symbol(',');
        // DPR
        OutDPR(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x6:
      for ( i=0; i < count; i++ )
      {
        Val1 = get_byte(insn.ea+2+(i*3));// imm
        Val2 = get_word(insn.ea+2+(i*3)+1);// mmll

        // DPRxx
        OutDT(Val2);
        out_symbol(',');
        // DPR
        OutDPR(Val1);
        out_symbol(',');
        OutReg(rX);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x7:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_byte(insn.ea+2+(i*3));// mmll
        Val1 = get_word(insn.ea+2+(i*3)+1);// dd

        // DPRxx
        OutDT(Val1);
        out_symbol(',');
        // DPR
        OutDPR(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0x9:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_word(insn.ea+2+(i*3));// mmll
        Val1 = get_byte(insn.ea+2+(i*3)+2);// dd

        // DPRxx
        OutDPR(Val1);
        out_symbol(',');
        // DPR
        OutDT(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;

    case 0xB:
      for ( i=0; i < count; i++ )
      {
        Val2 = get_word(insn.ea+2+(i*4));// imm
        Val1 = get_word(insn.ea+2+(i*4)+2);// llmm

        // DT
        OutDT(Val1);
        out_symbol(',');
        // DT
        OutDT(Val2);

        if ( i != (count-1) )
          out_symbol(',');
      }
      break;
  }
}

//----------------------------------------------------------------------
void out_m7900_t::MOV(const op_t &x)
{
  switch ( x.TypeOper )
  {
    case m7900_movrb: MOVRB(); break;
    case m7900_movr:  MOVR();  break;
    default:
      // msg("out: %a: bad prefix %d\n", insn.ip, RAZOPER);
      break;
  }
}

//----------------------------------------------------------------------
bool out_m7900_t::out_operand(const op_t &x)
{
  switch ( x.type )
  {
    case o_void:
      return 0;

    case o_reg:
      OutReg(x.reg);
      break;

    case o_phrase:
      out_line(ph.reg_names[x.reg]);
      break;

    case o_ab:
      switch ( x.TypeOper )
      {
        case TAB_L_INDIRECTED_ABS:
          out_symbol('L');
          // fallthrough

        case TAB_INDIRECTED_ABS:
          out_symbol('(');
          if ( !OutVarName(x) )
            out_value(x, OOF_ADDR | OOFS_NOSIGN);
          out_symbol(')');
          break;

        case TAB_INDIRECTED_ABS_X:
          out_symbol('(');

          if ( !OutVarName(x) )
            out_value(x, OOF_ADDR | OOFS_NOSIGN);

          out_symbol(',');
          OutReg(rX);
          out_symbol(')');
          break;

        case TAB_ABS_Y:
        case TAB_ABS_X:
        case TAB_ABS:
          out_register("DT");
          out_symbol(':');

          if ( !OutVarName(x) )
            out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
          break;

        case TAB_ABL_X:
        case TAB_ABL:
          out_register("LG");
          out_symbol(':');

          if ( !OutVarName(x) )
            out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_32);
          break;
      }
      break;

    case o_sr:
      if ( x.TypeOper == TSP_INDEX_SP_Y )
        out_symbol('(');

      if ( x.xmode == IMM_32 )
        out_value(x, OOFW_IMM | OOFW_32);
      else if ( x.xmode == IMM_16 )
        out_value(x, OOFW_IMM | OOFW_16);
      else
        out_value(x, OOFW_IMM);

      if ( x.TypeOper == TSP_INDEX_SP_Y )
      {
        out_symbol(',');
        OutReg(rPS);
        out_symbol(')');
      }
      break;

    case o_stk:
      // there are special cases
      switch ( insn.itype )
      {
        case m7900_pei: SetDP0Plus(x); break;
        case m7900_psh:
        case m7900_pul: GetNumPUL(x.value); break;

        default:
          out_symbol('#');
          out_value(x, OOFW_IMM | OOFS_NOSIGN);
          break;
      }
      break;

    case o_imm:
      // there are special cases
      switch ( insn.itype )
      {
        case m7900_sep:// Set Processor status
        case m7900_clp:// CLear Processor status
          GetCLPFlags(x.value);
          break;

        case m7900_lddn:
        case m7900_tdan:
        case m7900_phdn:
        case m7900_rtsdn:
        case m7900_pldn:
        case m7900_rtld:
        case m7900_phldn:
          GetNumDPRn(x.value);
          break;
        case m7900_bsc:
        case m7900_bss:
          out_value(x, OOFW_IMM);
          break;

        default:
          out_symbol('#');
          out_value(x, OOFW_IMM);
          break;
      }
      break;// case o_imm

    case o_mem:
       // output memory variable name (for example 'byte_98')
      if ( x.TypeOper == m7900_movr || x.TypeOper == m7900_movrb )
      {
        MOV(x);
        break;
      }

      switch ( x.TypeOper )
      {
        case TDIR_DIR_Y:
        case TDIR_DIR_X:
        case TDIR_DIR:
          {
            op_t y = x;
            y.addr = OutDPRReg(y.addr, getDPReg);
            out_symbol(':');
            if ( !OutVarName(y) )
              out_value(y, OOF_ADDR |OOF_NUMBER| OOFS_NOSIGN);
          }
          break;

        case TDIR_L_INDIRECT_DIR_Y:
        case TDIR_L_INDIRECT_DIR:
          out_symbol('L');
          // fallthrough

        case TDIR_INDIRECT_DIR_Y:
        case TDIR_INDIRECT_DIR:
          out_symbol('(');
          {
            op_t y = x;
            y.addr = OutDPRReg(y.addr, getDPReg);
            out_symbol(':');
            if ( !OutVarName(y) )
              out_value(y, OOF_ADDR |OOF_NUMBER| OOFS_NOSIGN);
          }
          out_symbol(')');
         break;

        case TDIR_INDIRECT_DIR_X:
          out_symbol('(');

          {
            op_t y = x;
            y.addr = OutDPRReg(y.addr, getDPReg);
            out_symbol(':');
            if ( !OutVarName(y) )
              out_value(y, OOF_ADDR |OOF_NUMBER| OOFS_NOSIGN);
          }

          out_symbol(',');
          OutReg(rX);
          out_symbol(')');
          break;
      }
      break;

    case o_near:
      {
        ea_t v = to_ea(insn.cs,x.addr);
        if ( !out_name_expr(x, v, x.addr) )
        {
          out_value(x, OOF_ADDR | OOFS_NOSIGN);
          // remember_problem(PR_NONAME, insn.ea);
        }
      }
      break;

    default:
      // warning("out: %a: bad optype %d", insn.ip, x.type);
      break;
  }
  return 1;
}

//----------------------------------------------------------------------
static const char *GetPrefics(int Raz)
{
  switch ( Raz )
  {
    case INSN_PREF_B: return ".b";
    case INSN_PREF_W: return "";
    case INSN_PREF_D: return ".d";
    case INSN_PREF_U: return "";
    default:
      // msg("out: %a: bad prefix %d\n", insn.ip, RAZOPER);
      break;
  }
  return "";
}

//----------------------------------------------------------------------
void out_m7900_t::out_proc_mnem(void)
{
  out_mnem(8, GetPrefics(RAZOPER));      // output instruction mnemonics
}

//----------------------------------------------------------------------
void out_m7900_t::out_insn(void)
{
  out_mnemonic();

  out_one_operand(0);                   // output the first operand

  if ( insn.Op2.type != o_void )
  {
    out_symbol(',');    // operand sep
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      out_char(' ');
    out_one_operand(1);
  }

  if ( insn.Op3.type != o_void )
  {
    out_symbol(',');
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      out_char(' ');
    out_one_operand(2);
  }

  if ( insn.Op4.type != o_void )
  {
    out_symbol(',');
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      out_char(' ');
    out_one_operand(3);
  }


  if ( insn.Op5.type != o_void )
  {
    out_symbol(',');
    if ( (ash.uflag & UAS_NOSPA) == 0 )
      out_char(' ');
    out_one_operand(4);
  }

  out_immchar_cmts();
  flush_outbuf();
}

//--------------------------------------------------------------------------
void m7900_t::m7900_header(outctx_t &ctx)
{
  ctx.gen_header(GH_PRINT_ALL_BUT_BYTESEX, nullptr, ioh.device.c_str());
}

//--------------------------------------------------------------------------
// generate segment header
//lint -esym(1764, ctx) could be made const
//lint -esym(818, Srange) could be made const
void m7900_t::m7900_segstart(outctx_t &ctx, segment_t *Srange) const
{
  qstring sname;
  get_visible_segm_name(&sname, Srange);

  if ( ash.uflag & UAS_SEGM )
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("SEGMENT %s", SCOLOR_ASMDIR), sname.c_str());
  else
    ctx.gen_printf(DEFAULT_INDENT, COLSTR(".SECTION %s", SCOLOR_ASMDIR), sname.c_str());

  ea_t orgbase = ctx.insn_ea - get_segm_para(Srange);
  if ( orgbase != 0 )
  {
    char buf[MAX_NUMBUF];
    btoa(buf, sizeof(buf), orgbase);
    ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s %s", SCOLOR_ASMDIR), ash.origin, buf);
  }
}

//--------------------------------------------------------------------------
void m7900_t::m7900_footer(outctx_t &ctx) const
{
  if ( ash.end != nullptr )
  {
    ctx.gen_empty_line();
    ctx.out_line(ash.end, COLOR_ASMDIR);
    qstring name;
    if ( get_colored_name(&name, inf_get_start_ea()) > 0 )
    {
      size_t i = strlen(ash.end);
      do
        ctx.out_char(' ');
      while ( ++i < 8 );
      ctx.out_line(name.begin());
    }
    ctx.flush_outbuf(DEFAULT_INDENT);
  }
  else
  {
    ctx.gen_cmt_line("end of file");
  }
}
