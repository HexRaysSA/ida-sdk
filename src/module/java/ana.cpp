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

//----------------------------------------------------------------------
int java_t::LoadIndex(insn_t &insn)
{
  ushort top;

  insn.Op1.type = o_mem;
//  insn.Op1.ref = 0;
  insn.Op1.offb = char(insn.size);
  top = insn.wid ? insn.get_next_word() : insn.get_next_byte();
  insn.Op1.addr = top;
  if ( ((insn.Op1.dtype == dt_qword || insn.Op1.dtype == dt_double) && !++top)
    || top >= curSeg.DataSize )
  {
    if ( !debugmode )
      return 0;
    ++insn.Op1.ref;
  }
  return 1;
}

//----------------------------------------------------------------------
void java_t::copy_const_to_opnd(op_t &x, const const_desc_t &co) const
{
  x.addr = co.value2;
  x.value = co.value;
#ifdef __EA64__
  // in IDA64 the 'value' field is 64bit, so copy the value there
  x.value = make_uint64(x.value, x.addr);
#endif
}

//----------------------------------------------------------------------
int java_t::ConstLoad(insn_t &insn, CIC_param ctype)
{
  const_desc_t cntopis;

  insn.Op1.type = o_cpool;
//  insn.Op1.ref = 0;

  if ( !insn.Op1.cp_ind )
    goto dmpchk;  // nullptr Ptr

  if ( !LoadOpis(lm_normal, insn.Op1.cp_ind, 0, &cntopis) )
    goto dmpchk;

  CASSERT(offsetof(const_desc_t,flag) == (offsetof(const_desc_t,type) + sizeof(uchar) )
       && (sizeof(cntopis.type) == sizeof(uchar))
       && (sizeof(cntopis.flag) == sizeof(uchar))
       && (sizeof(insn.Op1.cp_type) >= (2*sizeof(uchar)))
       && (sizeof(ushort) == sizeof(insn.Op1.cp_type)));
  insn.Op1.cp_type = *((ushort *)&cntopis.type);

  switch ( ctype )
  {
    case C_Class:
      if ( cntopis.type != CONSTANT_Class )
        break;
      // no break
    case C_4byte: // ldc/ldcw
      switch ( cntopis.type )
      {
        case CONSTANT_Class:
          if ( !(cntopis.flag & HAS_CLSNAME) )
            goto wrnret;
          insn.Op1.addr = 0x10001 * (ushort)fmt_fullname;
loadref1:
          insn.xtrn_ip = cntopis.ref_ip;
          // no break
        case CONSTANT_Integer:
        case CONSTANT_Float:
        case CONSTANT_String:
          insn.Op1.value = cntopis.value;  // for string index to Utf8
          return 1;                      // or TWO index for other
        default:
          break;
      }
      break;

    case C_8byte:
      if ( cntopis.type == CONSTANT_Long || cntopis.type == CONSTANT_Double )
        goto load2;
      break;

    case C_Field:
      if ( cntopis.type != CONSTANT_Fieldref )
        break;
      if ( (cntopis.flag & NORM_FIELD) != NORM_FIELD )
        goto wrnret;
loadref2:
      insn.xtrn_ip = cntopis.ref_ip;
load2:
      copy_const_to_opnd(insn.Op1, cntopis); // for string index to Utf8
      return 1;

    case C_Interface:
      if ( cntopis.type == CONSTANT_InterfaceMethodref )
        goto methodchk;
      break;
    case C_Method:
      if ( cntopis.type != CONSTANT_Methodref )
        break;
methodchk:
      if ( (cntopis.flag & NORM_METOD) == NORM_METOD )
        goto loadref2; // load 3 ind. & xtrn_ref
      goto wrnret;

    case C_CallSite:
      if ( cntopis.type != CONSTANT_InvokeDynamic )
        break;
      goto wrnret;

    case C_Type:
      if ( cntopis.type != CONSTANT_Class )
        break;
      if ( !(cntopis.flag & HAS_TYPEDSCR) )
        goto wrnret;
      insn.Op1.addr = ((uint32)fmt_FieldDescriptor << 16) | (ushort)fmt_ClassName;
      goto loadref1; // load 1 ind.

    case C_TypeName:
      if ( cntopis.type != CONSTANT_Class )
        break;
      if ( !(cntopis.flag & (HAS_TYPEDSCR | HAS_CLSNAME)) )
        goto wrnret;
      insn.Op1.addr = ((uint32)fmt_ClassName_or_Array << 16)
                    | (ushort)((cntopis.flag & HAS_CLSNAME)
                     ? fmt_fullname
                     : fmt_ClassName);
      goto loadref1; // load 1 ind.

    default:
      warning("Illegal CIC call (%x)", ctype);
      return 0;
  }
dmpchk:
  if ( !debugmode )
    return 0;
  ++insn.Op1.ref;
wrnret:
  ++insn.Op1.ref;
  insn.Op1.addr_shorts.low = insn.Op1.cp_ind;    // for dmp out
  return 1;
}

//----------------------------------------------------------------------
int java_t::ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  CIC_param ctype;
  segment_t *s = getMySeg(insn.ea); // also set curSeg

  if ( s->type != SEG_CODE || insn.ip >= curSeg.CodeSize )
  {
    warning("Can't decode non-code fragment!");
    return 0;
  }

  insn.Op1.dtype = dt_void;
  insn.wid = insn.swit = 0;
  insn.Op1.ref = 0;

  insn.itype = insn.get_next_byte();
  if ( insn.itype == j_wide )
  {
    insn.itype = insn.get_next_byte();
    if ( insn.itype == j_iinc
      || (insn.itype >= j_iload && insn.itype <= j_aload)
      || (insn.itype >= j_istore && insn.itype <= j_astore)
      || insn.itype == j_ret )
    {
      insn.wid = 1; // _w
    }
    else
    {
      if ( !debugmode )
        return 0;
      insn.size = 1;
      insn.itype = j_wide;
    }
  }

  if ( insn.itype >= j_lastnorm )
  {
    if ( !debugmode )
      return 0;
    if ( insn.itype < j_quick_last )
    {
      static const uchar redefcmd[j_quick_last - j_lastnorm] =
      {
        j_ldc,                    // j_ldc_quick
        j_ldcw,                   // j_ldcw_quick
        j_ldc2w,                  // j_ldc2w_quick
        j_getfield,               // j_getfield_quick
        j_putfield,               // j_putfield_quick
        j_getfield,               // j_getfield2_quick
        j_putfield,               // j_putfield2_quick
        j_getstatic,              // j_getstatic_quick
        j_putstatic,              // j_putstatic_quick
        j_getstatic,              // j_getstatic2_quick
        j_putstatic,              // j_putstatic2_quick
        j_invokevirtual,          // j_invokevirtual_quick
        j_invokespecial,          // j_invokenonvirtual_quick
        j_a_invokesuper,          // j_invokesuper_quick
        j_invokestatic,           // j_invokestatic_quick
        j_invokeinterface,        // j_invokeinterface_quick
        j_a_invokevirtualobject,  // j_invokevirtualobject_quick
        j_a_invokeignored,        // j_invokeignored_quick
        j_new,                    // j_new_quick
        j_anewarray,              // j_anewarray_quick
        j_multianewarray,         // j_multianewarray_quick
        j_checkcast,              // j_checkcast_quick
        j_instanceof,             // j_instanceof_quick
        j_invokevirtual,          // j_invokevirtual_quick_w
        j_getfield,               // j_getfield_quick_w
        j_putfield                // j_putfield_quick_w
      };

      insn.wid = 2; // _quick;
      switch ( insn.itype )
      {
        case j_getstatic2_quick:
        case j_putstatic2_quick:
        case j_getfield2_quick:
        case j_putfield2_quick:
          insn.wid = 3;  // 2_quick
          break;
        case j_invokevirtual_quick_w:
        case j_getfield_quick_w:
        case j_putfield_quick_w:
          insn.wid = 4;  // _quick_w
          break;
        default:
          break;
      }
      insn.itype = redefcmd[insn.itype - j_lastnorm];
    }
    else if ( insn.itype < j_software )
    {
      return 0;
    }
    else
    {
      insn.itype -= (j_software - j_a_software);
    }
  }
//---
  switch ( insn.itype )
  {
    default:
      {
        uint refs, ref2f;

        if ( insn.itype >= j_iload_0 && insn.itype <= j_aload_3 )
        {
          refs = (insn.itype - j_iload_0) % 4;
          ref2f = (insn.itype - j_iload_0) / 4;
          ref2f = ref2f == ((j_lload_0 - j_iload_0) / 4)
               || ref2f == ((j_dload_0 - j_iload_0) / 4);
          goto refer;
        }
        if ( insn.itype >= j_istore_0 && insn.itype <= j_astore_3 )
        {
          refs = (insn.itype - j_istore_0) % 4;
          ref2f = (insn.itype - j_istore_0) / 4;
          ref2f = ref2f == ((j_lstore_0 - j_istore_0) / 4)
               || ref2f == ((j_dstore_0 - j_istore_0) / 4);
refer:
          insn.Op1.addr = curSeg.DataBase + (ushort)refs;
          insn.Op1.ref = (uchar)(ref2f + 1);
          if ( (ushort)(refs + ref2f) >= curSeg.DataSize )
            insn.Op1.ref |= 0x80;
          break;
        }
      } // end refs/refx
      if ( insn.itype < j_ifeq || insn.itype > j_jsr )
        break;
    case j_ifnull:
    case j_ifnonnull:
      insn.Op1.addr = (short)insn.get_next_word();
b_near:
      insn.Op1.type = o_near;
      insn.Op1.offb = 1;
      insn.Op1.addr = trunc_uval(insn.Op1.addr + insn.ip);
      if ( insn.Op1.addr >= curSeg.CodeSize )
        goto set_bad_ref;
      break;

    case j_goto_w:
    case j_jsr_w:
      insn.Op1.addr = insn.get_next_dword();
      goto b_near;

    case j_bipush:
      insn.Op1.dtype = dt_byte;
      insn.Op1.value = (char)insn.get_next_byte();
      goto setdat;
    case j_sipush:
      insn.Op1.dtype = dt_word;
      insn.Op1.value = (short)insn.get_next_word();
setdat:
      insn.Op1.type = o_imm;
      insn.Op1.offb = 1;
      break;

    case j_ldc:
      insn.Op1.cp_ind = insn.get_next_byte();
      ctype = C_4byte;
      goto constchk;
    case j_ldcw:
      ctype = C_4byte;
      goto const2w;
    case j_ldc2w:
      ctype = C_8byte;
const2w:
      insn.Op1.cp_ind = insn.get_next_word();
constchk:
      if ( !ConstLoad(insn, ctype) )
        return 0;
      break;

    case j_getstatic:
    case j_putstatic:
    case j_getfield:
    case j_putfield:
      if ( insn.wid > 1 )       // _quick form
      {
        insn.Op1.type = o_imm;
        insn.Op1.ref = 2;        // #data
        insn.Op1.offb = 1;
        if ( insn.wid == 4 )
        {
          insn.Op1.dtype = dt_word;
          insn.Op1.value = insn.get_next_word();
        }
        else
        {
          insn.Op1.dtype = dt_byte;
          insn.Op1.value = insn.get_next_byte();
          ++insn.size;           // SKIP
        }
        break;
      }
      ctype = C_Field;
      goto const2w;

    case j_new:
      ctype = C_Class;
      goto const2w;

    case j_anewarray:
//\\ ?/
    case j_checkcast:
    case j_instanceof:
      ctype = C_TypeName;
      goto const2w;

    case j_a_invokesuper:
    case j_a_invokeignored:
      goto fictarg;
    case j_invokevirtual:
    case j_a_invokevirtualobject:
      insn.Op2.dtype = dt_void;
      if ( insn.wid > 1 )
      {
        if ( insn.wid == 4 )
        {
fictarg:
          insn.Op1.value = insn.get_next_word(); //???
          insn.Op1.dtype = dt_word;
        }
        else
        {
          insn.Op2.type = o_imm;
          insn.Op1.ref = 2;        // #data
          insn.Op1.dtype = insn.Op2.dtype = dt_byte;
          insn.Op1.value = insn.get_next_byte();
          insn.Op2.offb = 2;
          insn.Op2.value = insn.get_next_byte();
        }
        insn.Op1.offb = 1;
        insn.Op1.type = o_imm;
        insn.Op1.ref = 2;        // #data
        break;
      }
      // fallthrough
    case j_invokespecial:
    case j_invokestatic:
      ctype = C_Method;
      goto const2w;
    case j_invokedynamic:
      ctype = C_CallSite;
      insn.Op1.cp_ind = insn.get_next_word();
      if ( !ConstLoad(insn, ctype) )
        return 0;
      insn.get_next_word(); // eat two mandatory 0's
      insn.Op1.ref = 0;
      break;
    case j_invokeinterface:
      ctype = C_Interface;
      insn.Op1.cp_ind = insn.get_next_word();
      insn.Op2.type = o_imm;
      insn.Op2.ref = 1;          // not descriptor
      insn.Op2.dtype = dt_byte;
      insn.Op2.value = insn.get_next_byte();
      if ( insn.wid > 1 )
      {
        insn.Op3.type = o_imm;
        insn.Op3.ref = 2;        // #data
        insn.Op3.value = insn.get_next_byte();
        insn.Op3.offb = 4;
        insn.Op3.dtype = dt_byte;
      }
      else
      {
        ++insn.size;  // reserved
        insn.Op3.dtype = dt_void;
      }
      goto constchk;

    case j_multianewarray:
      insn.Op1.cp_ind = insn.get_next_word();
      insn.Op2.type = o_imm;
      insn.Op2.ref = 1;         // not descriptor
      insn.Op2.dtype = dt_byte;
      insn.Op2.value = insn.get_next_byte();
      if ( insn.Op2.value == 0 && !debugmode )
        return 0;
      ctype = C_Type;
      goto constchk;

    case j_iinc:
    case j_iload:
    case j_istore:
      insn.Op1.dtype = dt_dword;
      goto memref;
    case j_lload:
    case j_lstore:
      insn.Op1.dtype = dt_qword;
      goto memref;
    case j_fload:
    case j_fstore:
      insn.Op1.dtype = dt_float;
      goto memref;
    case j_dload:
    case j_dstore:
      insn.Op1.dtype = dt_double;
      goto memref;
    case j_aload:
    case j_astore:
      insn.Op1.dtype = dt_string;
      goto memref;
    case j_ret:
      insn.Op1.dtype = dt_code;
memref:
      if ( !LoadIndex(insn) )
        return 0;
      if ( insn.itype == j_iinc )
      {
        insn.Op2.type = o_imm;
        insn.Op2.ref = 0;
        insn.Op2.offb = (uchar)insn.size;
        if ( insn.wid )
        {
          insn.Op2.dtype = dt_word;
          insn.Op2.value = (short)insn.get_next_word();
        }
        else
        {
          insn.Op2.dtype = dt_byte;
          insn.Op2.value = (char)insn.get_next_byte();
        }
      }
      break;

    case j_tableswitch:
    case j_lookupswitch:
      {
        int32 count;
        uint32 top;

        insn.swit = 1;
        for ( top = (4 - uint32((insn.ip + insn.size) % 4)) & 3; top; top-- )
        {
          if ( insn.get_next_byte() )
          {
            if ( !debugmode )
              return 0;
            insn.swit |= 0100;
          }
        }
        insn.Op3.type = o_near;
        insn.Op3.offb = (uchar)insn.size;
        insn.Op3.addr = insn.get_next_dword();
        insn.Op3.addr = trunc_uval(insn.Op3.addr + insn.ip);
        insn.Op3.ref = 0;

        if ( insn.Op3.addr >= curSeg.CodeSize )
        {
          if ( !debugmode )
            return 0;
          ++insn.Op3.ref;
        }

        insn.swit |= 2;  // start out arguments

        count = insn.get_next_dword();
        if ( insn.itype == j_tableswitch )
        {
          insn.Op1.type  = o_imm;
          insn.Op1.dtype = dt_dword;
          insn.Op1.value = count;  // minimal value
          insn.Op2.ref   = 0;
          insn.Op2.type  = o_imm;
          insn.Op2.dtype = dt_dword;
          insn.Op2.value = insn.get_next_dword();
          count = uint32(insn.Op2.value) - count + 1;
        }
        insn.Op3.value = count;
        insn.Op2.addr = insn.ip + insn.size;
        top = uint32(curSeg.CodeSize - insn.ip);
        while ( count-- )
        {
          if ( insn.itype == j_lookupswitch )
            insn.get_next_dword(); // skip pairs;
          if ( trunc_uval(insn.ip + insn.get_next_dword()) >= curSeg.CodeSize )
          {
            if ( !debugmode )
              return 0;
            insn.swit |= 0200;
          }
          if ( (uint32)insn.size >= top )
            return 0;
        }
      }
      break;

    case j_newarray:
      insn.Op1.type = o_array;       // type!
      insn.Op1.offb = 1;
      insn.Op1.cp_type = insn.get_next_byte();
      if ( insn.Op1.cp_type < T_BOOLEAN || (uchar)insn.Op1.cp_type > T_LONG )
      {
set_bad_ref:
        if ( !debugmode )
          return 0;
        ++insn.Op1.ref;
      }
      break;
  } // switch ( insn.itype )

  return insn.size;
}

//----------------------------------------------------------------------

bool idaapi can_have_type(const op_t &x)
{
  if ( x.type == o_cpool )
    return (uchar)x.cp_type == CONSTANT_Integer
        || (uchar)x.cp_type == CONSTANT_Long;
  return x.type == o_imm;
}
