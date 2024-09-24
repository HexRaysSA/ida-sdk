/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"
#include <frame.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include <typeinf.hpp>
#include <funcs.hpp>

static void create_ext_ram_seg(ea_t &v)
{
  if ( (v & 0xFF0000) >= 0x80000 ) // these are references to code
  {
    v = v & 0x7FFFF;
    return;
  }

  if ( v && getseg(v) == nullptr )
  {
    ea_t start = v & 0xFFFF0000;

    char sname[32];
    qsnprintf(sname, sizeof(sname), "RAM%02x", int((start&0xFF0000)>>16));

    add_segm(start>>4, start, start+0x10000, sname, "DATA");
  }
}

static int check_insn(
        insn_t &insn,
        int prev,
        int itype,
        optype_t op1type,
        ea_t op1value,
        optype_t op2type,
        ea_t op2value)
{
  if ( prev && decode_prev_insn(&insn, insn.ea) == BADADDR )
    return 0;

  switch ( itype )
  {
    case XA_mov:
      if ( insn.itype != XA_mov && insn.itype != XA_movs )
        return 0;
      break;
    case XA_add:
    case XA_sub:
      if ( insn.itype != itype && insn.itype != XA_adds )
        return 0;
      break;
    default:
      if ( insn.itype != itype )
        return 0;
      break;
  }

  if ( op1type != o_void )
  {
    if ( insn.Op1.type != op1type )
      return 0;

    if ( op1value != BADADDR )
    {
      switch ( op1type )
      {
        case o_imm:
          if ( insn.Op1.value != op1value )
            return 0;
          break;
        case o_reg:
        case o_phrase:
          if ( insn.Op1.reg != op1value )
            return 0;
          break;
        default:
          if ( insn.Op1.addr != op1value )
            return 0;
          break;
      }
    }
  }

  if ( op2type != o_void )
  {
    if ( insn.Op2.type != op2type )
      return 0;

    if ( op2value != BADADDR )
    {
      switch ( op2type )
      {
        case o_imm:
          if ( insn.Op2.value != op2value )
            return 0;
          break;
        case o_reg:
        case o_phrase:
          if ( insn.Op2.reg != op2value )
            return 0;
          break;
        default:
          if ( insn.Op2.addr != op2value )
            return 0;
          break;
      }
    }
  }

  return 1;
}

//------------------------------------------------------------------------
// Handle an operand with an immediate value:
//      - mark it with FF_IMMD flag
//      - for bit logical instructions specify the operand type as a number
//        because such an operand is likely a plain number rather than
//        an offset or of another type.

static void set_immd_bit(const insn_t &insn, const op_t &x)
{
  set_immd(insn.ea);
  if ( is_defarg(get_flags(insn.ea), x.n) )
    return;
  switch ( insn.itype )
  {
    case XA_and:
    case XA_or:
    case XA_xor:
      op_num(insn.ea,x.n);
      break;
  }
}

//----------------------------------------------------------------------
static void attach_name_comment(const insn_t &insn, const op_t &x, ea_t v)
{
  qstring qbuf;
  if ( get_name_expr(&qbuf, insn.ea, x.n, v, v&0xFFFF) > 0 )
    set_cmt(insn.ea, qbuf.begin(), false);
}

//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace

void xa_t::handle_operand(insn_t &insn, const op_t &x, bool loading)
{
  flags64_t F = get_flags(insn.ea);
  switch ( x.type )
  {
    case o_reg:              // no special hanlding for these types
      break;

    case o_imm:                         // an immediate number as an operand
      if ( !loading )
        goto BAD_LOGIC;                 // this can't happen!
      set_immd_bit(insn, x);             // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, dr_O, 0);

      break;

    case o_displ:
      if ( x.phrase != fRi )
        set_immd_bit(insn, x);            // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( op_adds_xrefs(F, x.n) )
        insn.add_off_drefs(x, loading?dr_R:dr_W, OOF_SIGNED|OOF_ADDR);

      // Handle stack variables in a form [R7] and [R7+xx]
      // There is no frame pointer and all references are SP (R7) based
      if ( may_create_stkvars()
        && !is_defarg(F, x.n)
        && x.indreg == rR7
        && (x.n != 1 || !check_insn(insn, 0, XA_lea, o_reg, rR7, o_void, BADADDR)) )
      {
        func_t *pfn = get_func(insn.ea);
        if ( pfn != nullptr )
        {
          insn_t saved = insn;
          int n = x.n;
          op_t fake = x;

          if ( decode_insn(&insn, insn.ea+insn.size) > 0 )
          {
            if ( fake.dtype == dt_word )
            {
              QASSERT(10088, n == 0 || n == 1);
              if ( saved.itype == insn.itype
                && saved.ops[n].type      == insn.ops[n].type
                && saved.ops[n].phrase    == insn.ops[n].phrase
                && saved.ops[n].indreg    == insn.ops[n].indreg
                && saved.ops[n].addr + 2  == insn.ops[n].addr
                && saved.ops[1-n].type    == insn.ops[1-n].type
                && saved.ops[1-n].reg + 1 == insn.ops[1-n].reg )
              {
                fake.dtype = dt_dword;
              }
            }
            else
            { // dt_byte
              if ( saved.itype == XA_mov //-V501 identical sub-expressions
                && insn.itype == XA_mov
                && n == 1
                && insn.Op2.type == o_reg
                && saved.Op1.reg == insn.Op2.reg
                && insn.Op1.type == o_mem
                && insn.Op1.addr == ES
                && decode_insn(&insn, insn.ea+insn.size) > 0
                && insn.itype == XA_mov
                && insn.Op1.type == o_reg
                && insn.Op1.dtype == dt_word
                && insn.Op2.type == o_displ
                && insn.Op2.addr + 2 == saved.Op2.addr )
              {
                fake.dtype = dt_dword;
                fake.addr -= 2;
              }
            }
          }

          insn = saved;

          if ( insn.create_stkvar(fake, fake.addr, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, x.n);
          else
          {
            if ( fake.dtype == dt_dword )
            {
              fake.dtype = dt_word;
              if ( insn.create_stkvar(fake, fake.addr, STKVAR_VALID_SIZE) )
              {
                fake.dtype = dt_dword;
                insn.create_stkvar(fake, fake.addr, STKVAR_VALID_SIZE);
                op_stkvar(insn.ea, x.n);
              }
            }
          }
        }
      }
      // fallthru

    case o_phrase:
      if ( x.indreg != rR7 && (x.phrase == fRi || x.phrase == fRip) ) // catch ES:offset references
      {
        int reg = x.indreg - rR0;
        insn_t saved = insn;

        if ( check_insn(insn, 1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR) )
        {
          ea_t v = EXTRAMBASE + insn.Op2.value;
          int dtype;

          create_ext_ram_seg(v);
          if ( !is_defarg(F, 1) )
            op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);

          insn = saved;
          dtype = x.dtype;
          if ( dtype == dt_word )
          {
            int n = x.n;
            if ( decode_insn(&insn, insn.ea+insn.size) > 0
              && insn.ops[n].type == o_displ
              && insn.ops[n].indreg == reg+rR0 )
            {
              dtype = dt_dword;
            }
            insn = saved;
          }
          insn.create_op_data(v, x.offb, dtype);
          insn.add_dref(v, x.offb, loading ? dr_R : dr_W);

          attach_name_comment(insn, x, v);
        }
        else if ( check_insn(insn, 0, XA_setb, o_bit, 0x218+reg, o_void, BADADDR) )
        {
          if ( check_insn(insn, 1, XA_mov, o_mem, ES, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + (insn.Op2.value << 16);
            if ( check_insn(insn, 1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR)
              || check_insn(insn, 0, XA_lea, o_reg, reg+rR0, o_displ, BADADDR) )
            {
              int dtype;
              v += insn.Op2.type == o_imm ? insn.Op2.value : insn.Op2.addr;
              create_ext_ram_seg(v);
              if ( !is_defarg(F, 1) )
                op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
              insn = saved;

              dtype = x.dtype;
              if ( dtype == dt_word )
              {
                int n = x.n;
                if ( decode_insn(&insn, insn.ea+insn.size) > 0
                  && insn.ops[n].type == o_displ
                  && insn.ops[n].indreg == reg+rR0 )
                {
                  dtype = dt_dword;
                }
                insn = saved;
              }

              insn.create_op_data(v, x.offb, dtype);
              insn.add_dref(v, x.offb, loading ? dr_R : dr_W);

              attach_name_comment(insn, x, v);
            }
          }
          else if ( check_insn(insn, 0, XA_mov, o_mem, ES, o_reg, 2*reg+rR1L)
                 || check_insn(insn, 0, XA_mov, o_mem, CS, o_reg, 2*reg+rR1L) )
          { // MOV.B ES/CS,R1L
            int prev = 0;
            ea_t v = EXTRAMBASE;
            int ok = 0;
            if ( check_insn(insn, 1, XA_jb, o_bit, BADADDR, o_void, BADADDR)
              && (insn.Op1.addr & 0xf) == 0xf
              && (insn.Op1.addr & 0xFFF0) == ((reg+1)<<4) )
            {
              prev = 1;
            }

            if ( check_insn(insn, prev, XA_add, o_reg, reg+rR0, o_reg, BADADDR) )
              prev = 1;
            else
              prev = 0;

            if ( check_insn(insn, prev, XA_mov, o_reg, 2*reg+rR1H, o_imm, 0) )
            {
              if ( check_insn(insn, 1, XA_mov, o_reg, 2*reg+rR1L, o_mem, DS) )
                ok = 1;
            }
            else if ( check_insn(insn, 0, XA_mov, o_reg, reg+rR1, o_imm, BADADDR)
                   || check_insn(insn, 0, XA_addc, o_reg, reg+rR1, o_imm, BADADDR) )
            {
              v += (insn.Op2.value << 16);
              ok = 1;
            }
            if ( ok
              && (check_insn(insn, 1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR)
               || check_insn(insn, 0, XA_add, o_reg, reg+rR0, o_imm, BADADDR)) )
            {
              int dtype;
              v += insn.Op2.value;
              create_ext_ram_seg(v);
              if ( !is_defarg(F, 1) )
                op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
              insn = saved;

              dtype = x.dtype;
              if ( dtype == dt_word )
              {
                int n = x.n;
                if ( decode_insn(&insn, insn.ea+insn.size) > 0
                  && insn.ops[n].type == o_displ
                  && insn.ops[n].indreg == reg+rR0 )
                {
                  dtype = dt_dword;
                }
                insn = saved;
              }

              insn.create_op_data(v, x.offb, dtype);
              insn.add_dref(v, x.offb, loading ? dr_R : dr_W);
              attach_name_comment(insn, x, v);
            }
          }
          else if ( check_insn(insn, 0, XA_mov, o_reg, reg+rR0, o_imm, BADADDR) )
          { // mov.w Rx,#xxxx
            ea_t v = insn.Op2.value;
            if ( check_insn(insn, 1, XA_mov, o_mem, ES, o_reg, BADADDR)
              && insn.Op1.dtype == dt_byte )
            {
              int reg2 = insn.Op2.reg;
              if ( check_insn(insn, 1, XA_mov, o_reg, reg2, o_imm, BADADDR) )
              {
                int dtype;
                v += EXTRAMBASE + (insn.Op2.value << 16);
                create_ext_ram_seg(v);
                insn = saved;

                dtype = x.dtype;
                if ( dtype == dt_word )
                {
                  int n = x.n;
                  if ( decode_insn(&insn, insn.ea+insn.size) > 0
                    && insn.ops[n].type == o_displ
                    && insn.ops[n].indreg == reg+rR0 )
                  {
                    dtype = dt_dword;
                  }
                  insn = saved;
                }

                insn.create_op_data(v, x.offb, dtype);
                insn.add_dref(v, x.offb, loading ? dr_R : dr_W);
                attach_name_comment(insn, x, v);
              }
            }
          }
        }
        else if ( check_insn(insn, 0, XA_mov, o_mem, ES, o_reg, BADADDR)
               && insn.Op2.dtype == dt_byte )
        { // MOV.B ES,RxL
          int reg2 = (insn.Op2.reg - rR0L) >> 1;
          if ( check_insn(insn, 1, XA_jb, o_bit, BADADDR, o_void, BADADDR)
            && (insn.Op1.addr & 0xf) == 0xf
            && (insn.Op1.addr & 0xFFF0) == (reg2<<4)
            && check_insn(insn, 1, XA_setb, o_bit, 0x218+reg, o_void, BADADDR) )
          {
            int prev = 0;
            if ( check_insn(insn, 1, XA_add, o_reg, reg+rR0, o_void, BADADDR) )
              prev = 1;
            if ( check_insn(insn, prev, XA_mov, o_reg, reg2+rR0, o_imm, BADADDR)
              || check_insn(insn, 0, XA_addc, o_reg, reg2+rR0, o_imm, BADADDR) )
            {
              ea_t v = (insn.Op2.value & 0x8000) ? 0 : EXTRAMBASE;
              v += (insn.Op2.value & 0xff) << 16;
              if ( check_insn(insn, 1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR)
                || check_insn(insn, 0, XA_add, o_reg, reg+rR0, o_imm, BADADDR) )
              {
                int dtype;
                v += insn.Op2.value;
                create_ext_ram_seg(v);
                op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
                insn = saved;

                dtype = x.dtype;
                if ( dtype == dt_word )
                {
                  int n = x.n;
                  if ( decode_insn(&insn, insn.ea+insn.size) > 0
                    && insn.ops[n].type == o_displ
                    && insn.ops[n].indreg == reg+rR0 )
                  {
                    dtype = dt_dword;
                  }
                  insn = saved;
                }

                insn.create_op_data(v, x.offb, dtype);
                insn.add_dref(v, x.offb, loading ? dr_R : dr_W);
                attach_name_comment(insn, x, v);
              }
            }
          }
        }
        insn = saved;
      }
      break;

    case o_bit:                         // 8051 specific operand types - bits
    case o_bitnot:
      {
        int addr = int(x.addr >> 3);
        int bit = x.addr & 7;
        ea_t dea;

        if ( addr & 0x40 ) // SFR
        {
          addr += 0x3c0;
        }
        else if ( (x.addr & 0x20) == 0 ) // Register file
        {
          break;
        }
        attach_bit_comment(insn, addr, bit);  // attach a comment if necessary
        dea = map_addr(addr);
        insn.create_op_data(dea, x.offb, dt_byte);
        insn.add_dref(dea, x.offb, loading ? dr_R : dr_W);
      }
      break;

    case o_mem:                         // an ordinary memory data reference
      {
        ea_t dea = map_addr(x.addr);
        insn.create_op_data(dea, x);
        insn.add_dref(dea, x.offb, loading ? dr_R : dr_W);
      }
      break;

    case o_near:                        // a code reference
      {
        ea_t ea = to_ea(insn.cs, x.addr);
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(ea, x.offb, iscall ? fl_CN : fl_JN);

        if ( flow && iscall )
        {
          if ( !func_does_return(ea) )
            flow = false;
        }
      }
      break;

    case o_far:                        // a code reference
      {
        ea_t ea = x.addr + (x.specval << 16);
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        insn.add_cref(ea, x.offb, iscall ? fl_CF : fl_JF);
        if ( flow && iscall )
        {
          if ( !func_does_return(ea) )
            flow = false;
        }
      }
      break;

    default:
BAD_LOGIC:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(ph), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static bool add_stkpnt(const insn_t &insn, sval_t delta)
{
  func_t *pfn = get_func(insn.ea);
  if ( pfn == nullptr )
    return false;

  return add_auto_stkpnt(pfn, insn.ea+insn.size, delta);
}

//----------------------------------------------------------------------
int xa_t::emu(const insn_t &_insn)
{
  insn_t insn = _insn;
  uint32 Feature = insn.get_canon_feature(ph);
  flow = ((Feature & CF_STOP) == 0);

  // you may emulate selected instructions with a greater care:
  flags64_t F = get_flags(insn.ea);
  switch ( insn.itype )
  {
    case XA_mov:
    case XA_movs:
// mov R7,#xxx
      if ( insn.Op1.type == o_reg && insn.Op1.reg == rR7 )
      {
        if ( insn.Op2.type == o_imm && !is_defarg(F, 1) )
          op_offset(insn.ea, 1, REF_OFF16, INTMEMBASE + insn.Op2.value, INTMEMBASE);
      }

// mov DS,#xx
      if ( check_insn(insn, 0, XA_mov, o_mem, DS, o_imm, BADADDR) )
      {
        ea_t v = EXTRAMBASE + (insn.Op2.value << 16);
        create_ext_ram_seg(v);
      }

// mov ES,#xx
      if ( check_insn(insn, 0, XA_mov, o_mem, ES, o_void, BADADDR) ) // MOV ES,xx
      {
        insn_t saved = insn;
        ea_t v = 0;

        if ( insn.Op2.type == o_imm )
        {
          v = EXTRAMBASE + (insn.Op2.value << 16);
        }
        else if ( insn.Op2.type == o_reg && insn.Op1.dtype == dt_byte )
        {
          int reg = insn.Op2.reg;
          if ( check_insn(insn, 1, XA_mov, o_reg, reg, o_imm, BADADDR) )
            v = EXTRAMBASE + (insn.Op2.value << 16);
        }

        create_ext_ram_seg(v);

        if ( insn.Op2.type == o_imm && check_insn(insn, 1, XA_mov, o_reg, BADADDR, o_imm, BADADDR) && insn.Op1.dtype == dt_word )
        {
          v += insn.Op2.value;
          if ( !is_defarg(F, 1) )
            op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
        }
        insn = saved;
        F = get_flags(insn.ea);
      }

// mov CS,#xx
      if ( check_insn(insn, 0, XA_mov, o_mem, CS, o_imm, BADADDR) ) // MOV CS,#xx
      {
        insn_t saved = insn;
        ea_t v = (insn.Op2.value << 16);
        create_ext_ram_seg(v);

        if ( check_insn(insn, 1, XA_mov, o_reg, BADADDR, o_imm, BADADDR) && insn.Op1.dtype == dt_word )
        {
          v += insn.Op2.value;
          if ( !is_defarg(F, 1) )
            op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
        }
        insn = saved;
        F = get_flags(insn.ea);
      }

// mov Rx,#xxxx
      if ( check_insn(insn, 0, XA_mov, o_reg, BADADDR, o_imm, BADADDR) && insn.Op1.dtype == dt_word )
      {
        insn_t saved = insn;

        if ( check_insn(insn, 1, XA_mov, o_mem, ES, o_reg, BADADDR) && insn.Op1.dtype == dt_byte )
        {
          int regL = insn.Op2.reg - rR0L;
          if ( check_insn(insn, 1, XA_mov, o_reg, regL, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + (insn.Op2.value << 16) + saved.Op2.value;
            create_ext_ram_seg(v);
            insn = saved;
            F = get_flags(insn.ea);
            if ( !is_defarg(F, 1) )
              op_offset(saved.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
          }
        }
        insn = saved;
        F = get_flags(insn.ea);
      }

// mov.b R1H, #0
      if ( check_insn(insn, 0, XA_mov, o_reg, BADADDR, o_imm, 0) )
      {
        int reg = (insn.Op1.reg - rR1H) >> 1;
        insn_t saved = insn;
        if ( check_insn(insn, 1, XA_mov, o_reg, 2*reg+rR1L, o_mem, DS) ) // mov rx,DS
        {
          if ( check_insn(insn, 1, XA_mov, o_reg, reg+rR0, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + insn.Op2.value;
            F = get_flags(insn.ea);
            if ( !is_defarg(F, 1) )
              op_offset(insn.ea, 1, REF_OFF16, v, EXTRAMBASE);
          }
        }
        insn = saved;
      }

      break;

    case XA_push:
    case XA_pop:
      if ( insn.Op1.type == o_phrase
        && (insn.Op1.phrase == fRlistL || insn.Op1.phrase == fRlistH) )
      {
        func_t *pfn = get_func(insn.ea);
        int bits = 0, firstreg = 0;

        for ( int bit = 7; bit >= 0; bit-- )
        {
          if ( insn.Op1.indreg & (1<<bit) )
          {
            bits++;
            firstreg = bit;
          }
        }
        if ( bits && may_trace_sp() && pfn && !get_sp_delta(pfn, insn.ea) )
          add_stkpnt(insn, insn.itype == XA_push ? -2*bits : 2*bits);

        if ( insn.itype == XA_push
          && bits == 2
          && (insn.Op1.indreg & (1<<(firstreg+1))) ) // dword push
        {
          insn_t save = insn;
          if ( check_insn(insn, 1, XA_mov, o_reg, firstreg+rR1, o_imm, BADADDR) )
          {
            ea_t v = EXTRAMBASE + (insn.Op2.value << 16);
            if ( check_insn(insn, 1, XA_mov, o_reg, firstreg+rR0, o_imm, BADADDR) )
            {
              v += insn.Op2.value;
              create_ext_ram_seg(v);
              if ( !is_defarg(F, 1) )
                op_offset(insn.ea, 1, REF_OFF16, v, v & 0xFFFF0000);
            }
          }
          insn = save;
        }
      }
      else if ( insn.Op1.type == o_mem )
      {
        func_t *pfn = get_func(insn.ea);
        if ( may_trace_sp() && pfn && !get_sp_delta(pfn, insn.ea) )
          add_stkpnt(insn, insn.itype == XA_push ? -2 : 2);
      }
      else
      {
        warning("emu: strange push/pop instruction operand at %a", insn.ea);
      }
      break;

   case XA_add:
   case XA_sub:
   case XA_adds:
     if ( !may_trace_sp() )
       break;
     if ( insn.Op1.type == o_reg && insn.Op1.reg == rR7 )
     {
       if ( insn.Op2.type == o_imm )
       {
         func_t *pfn = get_func(insn.ea);

         sval_t offset = (insn.Op2.value < 0x8000 || insn.Op2.value > 0x80000000)
                       ? insn.Op2.value
                       : insn.Op2.value - 0x10000;

         if ( may_trace_sp() && pfn && !get_sp_delta(pfn, insn.ea) )
           add_stkpnt(insn, insn.itype == XA_sub ? -offset : offset);
       }
       else
       {
         warning("emu: add/adds/sub with R7 and non-imm operand at %a", insn.ea);
       }
     }
     break;
    case XA_lea:
      if ( !may_trace_sp() )
        break;
      if ( insn.Op1.type == o_reg && insn.Op1.reg == rR7 )
      {
        if ( insn.Op2.type == o_displ && insn.Op2.indreg == rR7 )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn && !get_sp_delta(pfn, insn.ea) )
            add_stkpnt(insn, insn.Op2.addr);
        }
        else
        {
          warning("emu: lea with R7 and unknown 2nd operand at %a", insn.ea);
        }
      }
      break;
  }

  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_USE3 )
    handle_operand(insn, insn.Op3, true);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, false);
  if ( Feature & CF_CHG3 )
    handle_operand(insn, insn.Op3, false);

  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyze the next instruction.

  if ( flow )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  return 1;    // actually the return value is unimportant, but let's it be so
}

//----------------------------------------------------------------------
// Special functions for Hisoft XA C compiler
bool xa_t::xa_create_func(func_t *pfn) const
{
  ea_t prologue = pfn->start_ea;
  bool prologue_at_end = false;
  uval_t frsize = 0;
  ushort regs = 0;

  insn_t insn;
  if ( decode_insn(&insn, prologue) > 0 )
  {
    if ( insn.itype == XA_jmp || insn.itype == XA_br )
    {
      prologue = to_ea(insn.cs, insn.Op1.addr);
      prologue_at_end = true;
    }
    bool more;
    do
    {
      more = false;
      if ( decode_insn(&insn, prologue) == 0 )
        break;
      if ( insn.itype == XA_push
        && insn.Op1.type == o_phrase
        && (insn.Op1.phrase == fRlistL || insn.Op1.phrase == fRlistH) )
      {
        for ( int bit = 0; bit < 8; bit++ )
        {
          if ( insn.Op1.indreg & (1<<bit) )
            regs += 2;
        }
        more = true;
      }
      if ( insn.itype == XA_lea
        && insn.Op1.type == o_reg
        && insn.Op1.reg == rR7
        && insn.Op2.type == o_displ
        && (insn.Op2.phrase == fRid8 || insn.Op2.phrase == fRid16)
        && insn.Op2.indreg == rR7 )
      {
        sval_t offset = insn.Op2.addr;
        if ( offset >= 0 )
        {
          warning("%a: positive offset %a", insn.ea, uval_t(offset));
          offset -= 0x10000;
        }
        frsize -= offset;
        more = true;
      }
      if ( insn.itype == XA_sub
        && insn.Op1.type == o_reg
        && insn.Op1.reg == rR7
        && insn.Op2.type == o_imm )
      {
        frsize += insn.Op2.value;
        more = true;
      }
      if ( insn.itype == XA_adds
        && insn.Op1.type == o_reg
        && insn.Op1.reg == rR7
        && insn.Op2.type == o_imm )
      {
        frsize -= insn.Op2.value;
        more = true;
      }
      prologue += insn.size;
    } while ( more );
  }
  add_frame(pfn, frsize, regs, 0);
  if ( prologue_at_end )
  {
    decode_insn(&insn, pfn->start_ea);
    add_stkpnt(insn, 0-frsize-regs);
  }

  return 1;
}

//----------------------------------------------------------------------
bool xa_t::xa_is_switch(switch_info_t *si, const insn_t &_insn)
{
  bool got_value = false;
  int prev;
  insn_t insn = _insn;

  if ( insn.Op1.type == o_phrase && insn.Op1.phrase == fRi )
  {
    insn_t saved = insn;
    int jumpreg, datareg;

    jumpreg = insn.Op1.indreg;
    if ( check_insn(insn, 1, XA_movc, o_reg, jumpreg, o_phrase, fRip)
      && insn.Op2.indreg == jumpreg )
    {
      if ( check_insn(insn, 1, XA_add, o_reg, jumpreg, o_imm, BADADDR) )
      {
        si->jumps = (insn.ea & 0xFFFF0000) + insn.Op2.value;
        op_offset(insn.ea, 1, REF_OFF16, si->jumps, insn.ea & 0xFFFF0000);
        if ( check_insn(insn, 1, XA_asl, o_reg, jumpreg, o_imm, 1) )
        {
          if ( check_insn(insn, 1, XA_mov, o_reg, rR0H + 2*(jumpreg-rR0), o_imm, 0) )
          {
            datareg = insn.Op1.reg - 1;
            prev = 0;
            if ( check_insn(insn, 1, XA_nop, o_void, BADADDR, o_void, BADADDR) )
              prev = 1;
            if ( check_insn(insn, prev, XA_bg, o_void, BADADDR, o_void, BADADDR)
              || (check_insn(insn, 0, XA_jmp, o_void, BADADDR, o_void, BADADDR)
               && check_insn(insn, 1, XA_bl, o_void, BADADDR, o_void, BADADDR)) )
            {
              if ( check_insn(insn, 1, XA_cmp, o_reg, datareg, o_imm, BADADDR) )
              {
                si->ncases = ushort(insn.Op2.value+1);
                if ( check_insn(insn, 1, XA_bcs, o_void, BADADDR, o_void, BADADDR) )
                {
                  si->defjump = insn.Op1.addr;
                  if ( check_insn(insn, 1, XA_sub, o_reg, datareg, o_imm, BADADDR)
                    || check_insn(insn, 0, XA_adds, o_reg, datareg, o_imm, BADADDR) )
                  {
                    if ( insn.itype == XA_sub )
                    {
                      si->lowcase = insn.Op2.value;
                    }
                    else
                    {
                      si->lowcase = 0-insn.Op2.value;
                    }
                    got_value = true;
                    si->startea = insn.ea;
                  }
                  else
                  {
                    warning("%a: no sub/add, may start with 0", insn.ea);
                  }
                }
                else
                {
                  si->lowcase = 0;
                  got_value = true;
                  si->startea = insn.ea + insn.size;
                }
              }
              else
              {
                warning("%a: no cmp", insn.ea);
              }
            }
            else
            {
              warning("%a: no bg, may be signed", insn.ea);
            }
          }
          else
          {
            prev = 0;
            if ( check_insn(insn, 0, XA_nop, o_void, BADADDR, o_void, BADADDR) )
              prev = 1;
            if ( check_insn(insn, prev, XA_bg, o_void, BADADDR, o_void, BADADDR)
              || (check_insn(insn, 0, XA_jmp, o_void, BADADDR, o_void, BADADDR)
               && check_insn(insn, 1, XA_bl, o_void, BADADDR, o_void, BADADDR)) )
            {
              if ( check_insn(insn, 1, XA_cmp, o_reg, BADADDR, o_imm, BADADDR) )
              {
                datareg = insn.Op1.reg;
                si->ncases = ushort(insn.Op2.value+1);
                if ( check_insn(insn, 1, XA_bcs, o_void, BADADDR, o_void, BADADDR) )
                {
                  si->defjump = insn.Op1.addr;
                  if ( check_insn(insn, 1, XA_sub, o_reg, datareg, o_imm, BADADDR)
                    || check_insn(insn, 0, XA_adds, o_reg, datareg, o_imm, BADADDR) )
                  {
                    if ( insn.itype == XA_sub )
                      si->lowcase = insn.Op2.value;
                    else
                      si->lowcase = 0-insn.Op2.value;
                    got_value = true;
                    si->startea = insn.ea;
                  }
                  else
                  {
                    warning("no sub/add, may start with 0");
                  }
                }
                else
                {
                  si->lowcase = 0;
                  got_value = true;
                  si->startea = insn.ea + insn.size;
                }
              }
              else
              {
                warning("%a: no cmp", insn.ea);
              }
            }
            else
            {
              warning("%a: no bg, may be signed", insn.ea);
            }
          }
        }
      }
    }

    if ( got_value )
    {
      if ( get_byte(si->jumps + 2*si->ncases) == 0xfe )
        insn.add_cref(si->jumps + 2*si->ncases, int(saved.ea), fl_F);
    }
  }
  return got_value;
}

//----------------------------------------------------------------------
//lint -esym(714,xa_frame_retsize)
//lint -esym(818,pfn)
int xa_t::xa_frame_retsize(const func_t *pfn)
{
  return pfn->is_far() ? 2 : 4;
}

//----------------------------------------------------------------------
void xa_t::xa_stkvar_def(outctx_t &ctx, const udm_t *stkvar, sval_t v)
{
  char sign = '+';
  if ( v < 0 )
  {
    v = -v; sign = '-';
  }

  char vstr[MAX_NUMBUF];
  btoa(vstr, sizeof(vstr), v);
  ctx.out_printf(COLSTR("%-*s", SCOLOR_LOCNAME)
                 " "
                 COLSTR("set     %c", SCOLOR_SYMBOL)
                 COLSTR("%s",SCOLOR_DNUM),
                 inf_get_indent()-1, stkvar->name.c_str(), sign, vstr);
}

//----------------------------------------------------------------------
int xa_t::xa_align_insn(ea_t ea)
{
  if ( get_byte(ea) == 0 )
    return 1;
  return 0;
}
