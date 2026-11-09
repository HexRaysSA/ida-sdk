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

#include "java.hpp"

static const char badlocvar[] = "Invalid local variable number";

//----------------------------------------------------------------------
uval_t java_t::SearchFM(ushort name, ushort dscr, char *naprN)
{
  char buf[(qmax(sizeof(FieldInfo), sizeof(SegInfo))+1+3)&~3];
  sval_t pos = curClass.FieldCnt;
  uint32 csz = sizeof(FieldInfo);
  sval_t napr = *naprN;

  if ( napr != 1 )
  {
    if ( napr != -1 )
      INTERNAL("SearchFM");
    pos = 0-(uval_t)curClass.MethodCnt;
    csz = sizeof(SegInfo);
  }
  void *p = buf;
  for ( ; pos; pos -= napr )
  {
    if ( ClassNode.supval(pos, p, sizeof(buf)) != csz )
      DESTROYED("SearchFM");
    if ( ((_FMid_ *)p)->extflg & EFL_NAMETYPE
      || CmpString(name, ((_FMid_ *)p)->name)
      || CmpString(dscr, ((_FMid_ *)p)->dscr) )
    {
      continue;
    }
    if ( napr >= 0 )
      return curClass.start_ea + ((FieldInfo *)p)->id.Number;
    if ( ((SegInfo *)p)->CodeSize )
      *naprN = 0;
    return ((SegInfo *)p)->start_ea;
  }
  return BADADDR;
}

//------------------------------------------------------------------------
void java_t::mark_and_comment(ea_t ea, const char *cmt) const
{
  remember_problem(PR_ATTN, ea);
  if ( *cmt && (!has_cmt(get_flags(ea)) || ea == curClass.start_ea) )
    append_cmt(ea, cmt, false);
}

//------------------------------------------------------------------------
void java_t::TouchArg(const insn_t &insn, const op_t &x, bool isload)
{
  const char *p;

  switch ( x.type )
  {
    case o_void:       // not operand
      break;

    case o_cpool:      // ConstantPool reference (index)
      if ( x.ref )
      {
        p = x.ref == 1
          ? "Invalid string in constant pool"
          : "Invalid index in constant pool";
        goto mark;
      }
      if ( x.cp_ind )
      {
        ea_t ea;
        char npr = -1;

        switch ( (uchar)x.cp_type )
        {
          case CONSTANT_Fieldref:
            npr = 1;
            // fallthrough
          case CONSTANT_InterfaceMethodref:
          case CONSTANT_Methodref:
            if ( !(x._subnam | x._name | x._class) )
              break;
            if ( x._class == curClass.This.Dscr )
            {
              ea = SearchFM(x._subnam, x._dscr, &npr);
              if ( ea == BADADDR )
                break;
            }
            else
            {
              if ( !insn.xtrn_ip )
                break;
              ea = insn.xtrn_ip == 0xFFFF
                 ? curClass.start_ea
                 : curClass.xtrnEA + insn.xtrn_ip;
              if ( npr < 0 )
                npr = 0;
            }
            if ( npr <= 0 )
            {
              insn.add_cref(ea, x.offb, fl_CF);
              if ( !npr )
                auto_cancel(ea, ea+1);
            }
            else
            {
              dref_t type = insn.itype == j_putstatic || insn.itype == j_putfield
                          ? dr_W
                          : dr_R;
              insn.add_dref(ea, x.offb, type);
            }
            break;

          case CONSTANT_Class:
            if ( insn.xtrn_ip )
            {
              ea_t target = insn.xtrn_ip == 0xFFFF
                          ? curClass.start_ea
                          : curClass.xtrnEA + insn.xtrn_ip;
              insn.add_dref(target, x.offb, dr_I);
            }
            break;
          default:
            break;
        }
      }
      break;

    case o_array:      // type!
      if ( x.ref )
      {
        p = "Invalid array type";
        goto mark;
      }
      break;

    case o_imm:        // const (& #data)
      if ( x.ref < 2 )
        set_immd(insn.ea);
      break;

    case o_mem:        // local data pool
      if ( x.ref )
      {
        p = badlocvar;
mark:
        mark_and_comment(insn.ea, p);
      }
      else
      {
        dref_t ref = isload ? dr_R : dr_W;
        ea_t adr   = curSeg.DataBase + x.addr;
        insn.add_dref(adr, x.offb, ref);
        if ( (x.dtype == dt_qword || x.dtype == dt_double)
          && get_item_size(adr) <= 1 )
        {
          insn.add_dref(adr + 1, x.offb, ref);
        }
      }
      break;

    case o_near:
      if ( x.ref )
      {
        p = "Invalid jump address";
        goto mark;
      }
      insn.add_cref(
              curSeg.start_ea + x.addr,
              x.offb,
              (Feature & CF_CALL) != 0 ? fl_CN : fl_JN);
      break;

    default:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n,
              x.type);
      break;
  }
}

//----------------------------------------------------------------------
int java_t::emu(const insn_t &insn)
{
  Feature = insn.get_canon_feature(ph);

  if ( insn.wid > 1 )
    mark_and_comment(insn.ea, "Limited usage instruction");

  if ( insn.itype >= j_a_software )
    mark_and_comment(insn.ea, "Undocumented instruction");

  if ( insn.Op1.type == o_void && insn.Op1.ref )
  {
    if ( (char)insn.Op1.ref < 0 )
    {
      mark_and_comment(insn.ea, badlocvar);
    }
    else
    {
      dref_t ref = (insn.itype >= j_istore_0) ? dr_W : dr_R;
      insn.add_dref(insn.Op1.addr, 0, ref);
      if ( (insn.Op1.ref & 2) && get_item_size(insn.Op1.addr) <= 1 )
        insn.add_dref(insn.Op1.addr + 1, 0, ref);
    }
  }

  if ( Feature & CF_USE1 )
    TouchArg(insn, insn.Op1, true);
  if ( Feature & CF_USE2 )
    TouchArg(insn, insn.Op2, true);
  if ( Feature & CF_USE3 )
    TouchArg(insn, insn.Op3, true);

  if ( Feature & CF_CHG1 )
    TouchArg(insn, insn.Op1, false);

  if ( insn.swit )  // tableswitch OR lookupswitch
  {
    uval_t count, addr, rnum;

    if ( insn.swit & 0200 )
      mark_and_comment(insn.ea, badlocvar);
    if ( insn.swit & 0100 )
      mark_and_comment(insn.ea, "Nonzero filler (warning)");

    rnum = insn.Op2.value - 1;   // for lookupswtitch
    for ( addr=insn.Op2.addr, count=insn.Op3.value; count; addr +=4, count-- )
    {
      uval_t refa;

      if ( insn.itype != j_lookupswitch )
      {
        ++rnum;
      }
      else
      {
        rnum = get_dword(curSeg.start_ea + addr); // skip pairs
        addr += 4;
      }
      refa = trunc_uval(insn.ip + get_dword(curSeg.start_ea + addr));

      if ( refa < curSeg.CodeSize )
      {
        add_cref(insn.ea, (refa += curSeg.start_ea), fl_JN);
        if ( !has_cmt(get_flags(refa)) )
        {
          char str[32];
          qsnprintf(str, sizeof(str), "case %" FMT_EA "u", rnum);
          set_cmt(refa, str, false);
        }
      }
    }
  }

  if ( !(Feature&CF_STOP) && (!(Feature&CF_CALL) || func_does_return(insn.ea)) )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
size_t java_t::make_locvar_cmt(qstring *buf, const insn_t &insn)
{
  LocVar lv;

  if ( curSeg.varNode )
  {
    const char *p = nullptr;
    uval_t idx = insn.Op1.addr;

    if ( insn.Op1.type == o_mem )
    {
      if ( !insn.Op1.ref )
      {
        switch ( insn.itype )
        {
          case j_ret:
            p = "Return";
            break;
          case j_iinc:
            p = "Add 8-bit signed const to";
            break;
          default:
            p = "Push";
            if ( insn.get_canon_feature(ph) & CF_CHG1 )
              p = "Pop";
            break;
        }
      }
    }
    else if ( insn.Op1.type == o_void
           && (char)insn.Op1.ref >= 0
           && (int32)(idx -= curSeg.DataBase) >= 0 )
    {
      p = "Push";
      if ( insn.itype >= j_istore_0 )
        p = "Pop";
    }

    if ( p != nullptr && netnode(curSeg.varNode).supval(idx,&lv,sizeof(lv)) == sizeof(lv) )
    {
      if ( fmtName(lv.var.Name, tmp_name, sizeof(tmp_name), fmt_UnqualifiedName) )
        return buf->sprnt("%s %s", p, tmp_name).length();
    }
  }
  return 0;
}
