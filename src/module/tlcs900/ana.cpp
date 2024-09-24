/*
 *      TLCS900 processor module for IDA.
 *      Copyright (c) 1998-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "tosh.hpp"

// (number of bytes -1) -> dtype
static const uchar bt_type[4]= { dt_byte, dt_word, dt_tbyte, dt_dword };

//  power of 2 -> dtype
static const uchar btp_type[4]= { dt_byte, dt_word, dt_dword, uchar(-1) };

// memory reference (o_mem/o_displ)
struct MemRefDef
{
  uint32 disp;      // offset
  ushort off_pos;   // place of offset in insn (if any)
  optype_t type;    // dtype: o_mem/o_displ
  uchar flags;      // flags
  uchar base_reg;   // base reg
  uchar add_reg;    // additional reg (DAfull number)
  uchar inc_size;   // increment size (+/-4)
  uchar dtype;
};

//-----------------------------------------------------------------------------
// short reg to full reg
static uchar Reg7ToFull(uchar reg7, uchar size)
{
  reg7&=7;    // fix reg number
  // byte reg
  if ( size == 0 )
    return 0xE0+(1-(reg7&1))+(reg7&6)*2;
  // word or double wor dreg
  return 0xE0+reg7*4;
}

//-----------------------------------------------------------------------------
// set number of the reg into operand
// reg_code - byte reg num
// size - 0,1,2 (2^x bytes)
static void SetRegistr(op_t &op, uchar reg_code, uchar size)
{
  op.type=o_reg;
  op.addr=op.value=reg_code;
  op.dtype = btp_type[size&3];
}

//-----------------------------------------------------------------------------
// set register
// regcode - reg number (3 bits)
// size - 0,1,2 (2^x bytes)
static void SetRegistr7(op_t &op, uchar regcode, uchar size)
{
  SetRegistr(op, Reg7ToFull(regcode, size), size);
}

//-----------------------------------------------------------------------------
// load N ibytes and return result
static uint32 LoadDataValue(insn_t &insn, int bytes)
{
  uint32 val=0;
  for ( int i=0; i < bytes; i++ )
    val |= ((uint32)insn.get_next_byte())<<(8*i);
  return val;
}

//-----------------------------------------------------------------------------
// currnet bytes are the memory address
// len - number of bytes
static void SetDirectMemRef(insn_t &insn, op_t &op, int len)
{
  op.type = o_mem;
  // elem offset
  op.offb = (uchar)insn.size;
  // size of offset
  op.dtype = bt_type[(len-1)&3];
  // elem value
  op.addr = op.value = LoadDataValue(insn, len);
}

//-----------------------------------------------------------------------------
// code ref
static void SetJmp(insn_t &insn, op_t &op, int len)
{
  op.type = o_near;
  op.offb = (uchar)insn.size;
  op.dtype = dt_dword;
  if ( len > 0 )
  {
    // absolute
    op.addr = op.value = LoadDataValue(insn, len);
  }
  else
  {
    // relative
    len = -len;
    op.addr = LoadDataValue(insn, len);
    // sig
    if ( op.addr & (uval_t(1)<<(8*len-1)) )
    {
      op.addr |= BADADDR<<(8*len);
    }
    // target offset
    op.addr += insn.ip + insn.size;
    op.value = op.addr;
  }
}

//-----------------------------------------------------------------------------
// MemRef to Operand
static void MemRefToOp(op_t &op, const MemRefDef &mr)
{
  op.value     = mr.disp;
  op.addr      = mr.disp;
  op.dtype     = mr.dtype;
  op.reg       = mr.base_reg;
  op.specflag2 = mr.inc_size;
  op.offb      = (uchar)mr.off_pos;
  op.specval_shorts.low = mr.add_reg;
  op.specflag1 = mr.flags;
  op.type      = mr.type;
}

//-----------------------------------------------------------------------------
// load memory ref
// first_code - firt insn byte
static int LoadMemRef(insn_t &insn, MemRefDef &mr, uchar first_code)
{
  memset(&mr, 0, sizeof(mr));
  mr.dtype = btp_type[(first_code>>4)&3];
  if ( (first_code&0x40) == 0 )
  {
    // ref is reg (with offset or not)
    mr.type = o_displ;
    // reg name
    mr.base_reg = Reg7ToFull(first_code, 2);
    if ( first_code&0x8 )
    {
      // offset
      mr.off_pos = insn.size;
      mr.disp = insn.get_next_byte();
    }
  }
  else
  {
    switch ( first_code & 7 )
    {
      // direct, byte
      case 0:
        mr.off_pos = insn.size;
        mr.disp = LoadDataValue(insn, 1);
        mr.type = o_mem;
        break;
      // direct, word
      case 1:
        mr.off_pos = insn.size;
        mr.disp = LoadDataValue(insn, 2);
        mr.type = o_mem;
        break;
      // direct, 24 bit
      case 2:
        mr.off_pos=insn.size;
        mr.disp=LoadDataValue(insn, 3);
        mr.type=o_mem;
        break;
      // two regs
      case 3:
        {
          uchar mem_val;
          mr.type = o_displ;
          mem_val = insn.get_next_byte();
          if ( (mem_val&2) == 0 )
          {
            // with reg
            mr.base_reg = mem_val & 0xFC;
            // and ofsset?
            if ( mem_val&1 )
            {
              mr.off_pos = insn.size;
              mr.disp = LoadDataValue(insn, 2);
            }
          }
          else
          { // two regs
            if ( (mem_val&1) == 0 )
              return 0; // wrong
            if ( (mem_val>>2) > 1 )
            {
              // LDAR!
              // check for F3/13
              //msg("Ldar Op");
              if ( first_code == 0xF3 && mem_val == 0x13 )
              {
                // yes!
                insn.itype=T900_ldar;
                // elem offset
                insn.Op2.offb=(uchar)insn.size;
                uint32 target=LoadDataValue(insn, 2);
                target+=uint32(insn.ea+4);
                insn.Op2.type=o_mem;
                // size of offset
                insn.Op2.dtype = dt_word;
                // elem value
                insn.Op2.addr = insn.Op2.value = target;
                // get reg
                mem_val=insn.get_next_byte();
                // available?
                if ( (mem_val&0xE8) != 0x20 )
                  return 0;
                SetRegistr7(insn.Op1, mem_val, ((mem_val>>4)-1)&3);
                //msg("ldar ok");
                return 1;
              }
              return 0;
            }
            mr.base_reg = insn.get_next_byte();     // 1st reg
            mr.add_reg  = insn.get_next_byte();     // 2nd reg
            if ( mem_val & 0x4 )
              mr.flags|=URB_WORD;// 2nd reg - word
          }
        }
        break;
      // inc/dec
      case 4:
      case 5:
        {
          uchar regg = insn.get_next_byte();
          if ( (regg&3) == 3 )
            return 0;
          mr.type = o_displ;
          mr.base_reg = regg&0xFC;
          mr.inc_size = 1<<(regg&3);
          // negative inc
          if ( (first_code&1) == 0 )
            mr.inc_size|=URB_DECR;
        }
        break;
    }
  }
  return 1;
}

//-----------------------------------------------------------------------------
static void SetImmData(insn_t &insn, op_t &op, int bytes)
{
  op.type = o_imm;
  op.offb = (uchar)insn.size;
  op.dtype = bt_type[(bytes-1)&3];
  op.addr = op.value = LoadDataValue(insn, bytes);
}

//-----------------------------------------------------------------------------
static void SetImm8Op(op_t &op, uchar code)
{
  op.type = o_imm;
  op.dtype = dt_byte;      // actually, it is not a byte
  op.flags |= OF_NUMBER;
  op.addr = op.value = code;
}

//-----------------------------------------------------------------------------
// set imm3 for inc/dec
static void SetImm3Op(op_t &op, uchar code)
{
  code &= 7;
  SetImm8Op(op, code ? code : 8);
}

//-----------------------------------------------------------------------------
// condition phrase
static void SetCondOp(op_t &op, int cond)
{
  static const uchar cond_p[16] =
  {
    fCF, fCLT, fCLE, fCULE, fCPE, fCMI, fCZ,  fCC,
    fCT, fCGE, fCGT, fCUGT, fCPO, fCPL, fCNZ, fCNC
  };
  op.type = o_phrase;
  op.phrase = cond_p[cond&0xf];
}

//-----------------------------------------------------------------------------
// arith insns
static const uchar Add_List[8] =
{
  T900_add, T900_adc, T900_sub, T900_sbc,
  T900_and, T900_xor, T900_or, T900_cp
};

// shift insns (not simple)
static const uchar Shift_List[8] =
{
  T900_rlc, T900_rrc, T900_rl, T900_rr,
  T900_sla, T900_sra, T900_sll, T900_srl
};

// shift for memory cells
static const uchar Shift_List1[8] =
{
  T900_rlc_mem, T900_rrc_mem, T900_rl_mem, T900_rr_mem,
  T900_sla_mem, T900_sra_mem, T900_sll_mem, T900_srl_mem
};

// flag C
static const uchar COp_List[5] =
{
  T900_andcf, T900_orcf, T900_xorcf, T900_ldcf, T900_stcf
};

// other flag C
static const uchar COp2_List[5] =
{
  T900_res, T900_set, T900_chg, T900_bit, T900_tset
};

//-----------------------------------------------------------------------------
// parse regs
static int RegAnalyser(insn_t &insn, uchar code)
{
  static const uchar reg_codes[32] =
  {
    255,        255,        255,           255,
    T900_andcf, T900_andcf, T900_res,      T900_minc1,
    T900_mul,   T900_muls,  T900_div,      T900_divs,
    T900_inc,   T900_dec,   T900_scc,      T900_scc,
    T900_add,   T900_ld,    T900_adc,      T900_ld,
    T900_sub,   T900_ld,    T900_sbc,      T900_ex,
    T900_and,   254,        T900_xor,      253,
    T900_or,    T900_rlc,   T900_cp,       T900_rlc
  };
  uchar reg_size = (code>>4) & 3;  // 0 - byte, 1 - word, 2 - long
  uchar reg_num;         // byte reg number
  if ( code & 8 )
  {
    reg_num = Reg7ToFull(code, reg_size);
  }
  else
  { // aux byte
    reg_num = insn.get_next_byte();
  }
  uchar reg_op = 0;        // Op1 is reg by default
  uchar reg_byte = insn.get_next_byte();
  insn.itype = reg_codes[(reg_byte>>3)&0x1F];
  switch ( insn.itype )
  {
    case T900_ex:
    case T900_add:
    case T900_adc:
    case T900_sub:
    case T900_sbc:
    case T900_and:
    case T900_xor:
    case T900_or:
    case T900_cp:
      SetRegistr7(insn.Op1, reg_byte, reg_size);
      reg_op=1;
      break;

    case 255:
      {
        static const uchar LCodes[] =
        {
          0,         0,         0,         T900_ld,
          T900_push, T900_pop,  T900_cpl,  T900_neg,
          T900_mul,  T900_muls, T900_div,  T900_divs,
          T900_link, T900_unlk, T900_bs1f, T900_bs1b,
          T900_daa,  0,         T900_extz, T900_exts,
          T900_paa,  0,         T900_mirr, 0,
          0,         T900_mula, 0,         0,
          T900_djnz, 0,         0,         0
        };

        if ( reg_byte >= qnumber(LCodes) )
          return 0;

        insn.itype = LCodes[reg_byte];
        switch ( insn.itype )
        {
          // illegal
          case 0:
            return 0;

          // LD r, #
          case T900_ld:
            SetImmData(insn, insn.Op2, 1<<reg_size);
            break;

          // MUL rr, #
          // DIV rr, #
          case T900_div:
          case T900_divs:
          case T900_mul:
          case T900_muls:
            SetImmData(insn, insn.Op2, 1<<reg_size);
            // hig reg used
            reg_size++;
            if ( reg_size == 3 )
              return 0;
            break;

          // LINK r, dd
          case T900_link:
            SetImmData(insn, insn.Op2, 2);
            break;

          // BS1F A,r
          case T900_bs1f:
          case T900_bs1b:
            SetRegistr7(insn.Op1, 1, 0);
            reg_op=1;
            break;
          // MULA r
          case T900_mula:
            // high reg used
            reg_size++;
            if ( reg_size == 3 )
              return 0;
            break;
          // DJNZ r, d
          case T900_djnz:
            SetJmp(insn, insn.Op2, -1);
            break;
        }
      }
      break;

    // ANDCF-STCF  XXX #, r
    case T900_andcf:
      if ( reg_byte > 0x2C )
      {
        switch ( reg_byte )
        {
          case 0x2D:
            return 0;
            // compilcated insn LDC - skip it for now
          case 0x2E:
            SetImmData(insn, insn.Op1, 1);
            reg_op=1;
            break;
          case 0x2F:
            SetImmData(insn, insn.Op2, 1);
            break;
        }
        insn.itype=T900_ldc;
      }
      else if ( (reg_byte&7) < 5 ) // not an LDC
      {
        reg_op = 1;
        insn.itype = COp_List[reg_byte&7];
        if ( reg_byte & 8 )
          SetRegistr7(insn.Op1, 1, 0);
        else
          SetImmData(insn, insn.Op1, 1);
      }
      else
      {
        return 0;
      }
      break;

    // RES-TSET
    case T900_res:
      if ( (reg_byte&7) > 4 )
        return 0;
      insn.itype = COp2_List[reg_byte&7];
      SetImmData(insn, insn.Op1, 1);
      reg_op = 1;
      break;

    // MINC/MDEC
    case T900_minc1:
      {
        static const uchar dinc[8] =
        {
          T900_minc1, T900_minc2, T900_minc4, 0,
          T900_mdec1, T900_mdec2, T900_mdec4, 0
        };
        if ( (insn.itype=dinc[reg_byte&7]) == 0 )
          return 0;
        SetImmData(insn, insn.Op1, 2);
        // fix op
        insn.Op1.value += uval_t(1)<<(reg_byte&3);
        insn.Op1.addr = insn.Op1.value;
        reg_op = 1;
      }
      break;
    // mul/div  XXX R, r
    case T900_mul:
    case T900_muls:
    case T900_div:
    case T900_divs:
      SetRegistr7(insn.Op1, reg_size == 0 ? (reg_byte&7)/2 : reg_byte, reg_size+1);
      reg_op=1;
      break;

    // INC/DEC #3, r
    case T900_inc:
    case T900_dec:
      SetImm3Op(insn.Op1, reg_byte);
      reg_op=1;
      break;

    // set SCC, r
    case T900_scc:
      SetCondOp(insn.Op1, reg_byte&0xF);
      reg_op=1;
      break;
    // LD
    case T900_ld:
      if ( reg_byte < 0x90 )
        reg_op = 1;
      if ( reg_byte < 0xA0 )
        SetRegistr7(insn.ops[1-reg_op], reg_byte, reg_size);
      else
        SetImm8Op(insn.Op2, reg_byte&7);
      break;

    // another arithmetics XXX r, #)
    case 254:
      insn.itype=Add_List[reg_byte&7];
      SetImmData(insn, insn.Op2, 1<<reg_size);
      break;
    // CP r, #3
    case 253:
      insn.itype=T900_cp;
      SetImm8Op(insn.Op2, reg_byte&7);
      break;
    // shifts
    case T900_rlc:
      insn.itype=Shift_List[reg_byte&7];
      if ( reg_byte >= 0xF8 )
      {
        SetRegistr7(insn.Op1, 1, 0);
      }
      else
      {
        uchar ShL = insn.get_next_byte();
        SetImm8Op(insn.Op1, ShL == 0 ? 16 : ShL);
      }
      reg_op = 1;
      break;
    default:
      return 0;
  }
  // set reg
  SetRegistr(insn.ops[reg_op], reg_num, reg_size);
  return insn.size;
}

//-----------------------------------------------------------------------------
// parse 2nd byte DST
static int DSTAnalyser(insn_t &insn, uchar code)
{
  // memory op number
  char memrefop = 1;
  MemRefDef mr;   // memory ref
  // main opcodes
  static const uchar dst_codes[32] =
  {
    255,        0,         255,           0,
    T900_lda,   255,       T900_lda,      0,
    T900_ld,    0,         T900_ldw,      0,
    T900_ld,    0,         0,             0,
    T900_andcf, T900_orcf, T900_xorcf,    T900_ldcf,
    T900_stcf,  T900_tset, T900_res,      T900_set,
    T900_chg,   T900_bit,  T900_jp_cond,  T900_jp_cond,
    T900_call,  T900_call, T900_ret_cond, T900_ret_cond
  };
  // get mem ref
  if ( LoadMemRef(insn, mr, code) == 0 )
    return 0;
  // check for LDAR
  if ( insn.itype == T900_ldar )
    return insn.size;
  // opcode
  uchar dst_byte = insn.get_next_byte();
  // need to check for mr.dtyp - byte by default
  mr.dtype = dt_byte;

  insn.itype=dst_codes[(dst_byte>>3)&0x1F];
  switch ( insn.itype )
  {
    case 0:
      return 0;

    // go further
    case 255:
      if ( dst_byte < 0x2D && dst_byte >= 0x28 )
      {
        // bit insn
        insn.itype = COp_List[dst_byte-0x28];
        // reg A
        SetRegistr7(insn.Op1, 1, 0);
        // mem ref
        break;
      }

      switch ( dst_byte )
      {
        // ld byte
        case 0x00:
          insn.itype=T900_ld;
          SetImmData(insn, insn.Op2, 1);
          memrefop=0;
          break;

        // ld word
        case 0x02:
          insn.itype = T900_ldw;
          SetImmData(insn, insn.Op2, 2);
          mr.dtype = dt_word;
          memrefop = 0;
          break;

        // pop byte
        case 0x04:
          insn.itype=T900_pop;
          memrefop=0;
          break;

        // pop word
        case 0x06:
          insn.itype = T900_popw;
          mr.dtype = dt_word;
          memrefop = 0;
          break;

        // ld byte xx
        case 0x14:
          insn.itype = T900_ld;
          SetDirectMemRef(insn, insn.Op2, 2);
          memrefop = 0;
          break;

        // ld word
        case 0x16:
          insn.itype = T900_ldw;
          SetDirectMemRef(insn, insn.Op2, 2);
          mr.dtype = dt_word;
          memrefop = 0;
          break;


        default:
          return 0;
      }
      break;
    // load 40, 50, 60
    case T900_ldw:
    case T900_ld:
      SetRegistr7(insn.Op2, dst_byte, (dst_byte>>4)&0x3);
      mr.dtype = btp_type[(dst_byte>>4)&3];
      memrefop = 0;
      break;
    // load 20, 30
    case T900_lda:
      {
        uchar size = ((dst_byte>>4)&0x3)-1;
        SetRegistr7(insn.Op1, dst_byte, size);
        mr.dtype = btp_type[size];
        mr.flags |= URB_LDA|URB_LDA2;// address, not data!
      }
      break;
    // branches
    case T900_jp_cond:
      if ( (dst_byte&0xF) == 0x8 )
        insn.itype=T900_jp;
      // fallthrough
    case T900_call:         // set cond code
      SetCondOp(insn.Op1, dst_byte&0xF);
      mr.flags |= URB_LDA;      // address, not data!
      break;
    // return
    case T900_ret_cond:     // 1st byte == 0xb0
      if ( code != 0xB0 )
        return 0;
      if ( (dst_byte&0xF) == 0x8 )
        insn.itype=T900_ret;
      SetCondOp(insn.Op1, dst_byte&0xF);
      return insn.size;

    // ANDCF, ....
    default:
      SetImm8Op(insn.Op1, dst_byte&7);
      break;
  }
  MemRefToOp(insn.ops[uchar(memrefop)], mr);
  return insn.size;
}

//-----------------------------------------------------------------------------
static int SRCAnalyser(insn_t &insn, uchar code)
{
  uchar memrefop=1; // number of operand with mem ref
  MemRefDef mr;
  static const uchar aa[] =
  {
    255,      0,         255,      255,
    T900_ld,  0,         T900_ex,  254,
    T900_mul, T900_muls, T900_div, T900_divs,
    T900_inc, T900_dec,  0,        253,
    T900_add, T900_add,  T900_adc, T900_adc,
    T900_sub, T900_sub,  T900_sbc, T900_sbc,
    T900_and, T900_and,  T900_xor, T900_xor,
    T900_or,  T900_or,   T900_cp,  T900_cp
  };

  if ( LoadMemRef(insn, mr, code) == 0 )
    return 0;
  uchar src_byte = insn.get_next_byte();
  insn.itype=aa[(src_byte>>3)&0x1F];
  uchar reg_size = (code>>4)&3; // 0, 1, 2
  switch ( insn.itype )
  {
    case 0:
      return 0;

    case 255:
      switch ( src_byte )
      {
        default:
          return 0;
        // push
        case 4:
          insn.itype=T900_push;
          memrefop=0;
          break;
        // rld
        case 6:
          insn.itype=T900_rld;
          SetRegistr7(insn.Op1, 1, 0);
          break;
        // rrd
        case 7:
          insn.itype=T900_rrd;
          SetRegistr7(insn.Op1, 1, 0);
          break;
        // ldi
        case 0x10:
          insn.itype=T900_ldi;
          mr.inc_size|=URB_UINC;
          mr.base_reg--;
          MemRefToOp(insn.Op1, mr);
          mr.base_reg++;
          if ( reg_size )
            insn.itype++;
          break;
        // ldir
        case 0x11:
          insn.itype=T900_ldir;
          mr.inc_size|=URB_UINC;
          mr.base_reg--;
          MemRefToOp(insn.Op1, mr);
          mr.base_reg++;
          if ( reg_size )
            insn.itype++;
          break;
        // ldd
        case 0x12:
          insn.itype=T900_ldd;
          mr.inc_size|=URB_UDEC;
          mr.base_reg--;
          MemRefToOp(insn.Op1, mr);
          mr.base_reg++;
          if ( reg_size )
            insn.itype++;
          break;
        // lddr
        case 0x13:
          insn.itype=T900_lddr;
          mr.inc_size|=URB_UDEC;
          mr.base_reg--;
          MemRefToOp(insn.Op1, mr);
          mr.base_reg++;
          if ( reg_size )
            insn.itype++;
          break;
        // cpi
        case 0x14:
          insn.itype=T900_cpi;
          mr.inc_size|=URB_UINC;
          if ( reg_size )
            SetRegistr7(insn.Op1, 0, 1);
          else
            SetRegistr7(insn.Op1, 1, 0);
          break;
        // cpir
        case 0x15:
          insn.itype=T900_cpir;
          mr.inc_size|=URB_UINC;
          if ( reg_size )
            SetRegistr7(insn.Op1, 0, 1);
          else
            SetRegistr7(insn.Op1, 1, 0);
          break;
        // cpd
        case 0x16:
          insn.itype=T900_cpd;
          mr.inc_size|=URB_UDEC;
          if ( reg_size )
            SetRegistr7(insn.Op1, 0, 1);
          else
            SetRegistr7(insn.Op1, 1, 0);
          break;
        // cpdr
        case 0x17:
          insn.itype=T900_cpdr;
          mr.inc_size|=URB_UDEC;
          if ( reg_size )
            SetRegistr7(insn.Op1, 0, 1);
          else
            SetRegistr7(insn.Op1, 1, 0);
          break;
        // ld
        case 0x19:
          if ( code&0x10 )
            insn.itype=T900_ldw;
          else
            insn.itype=T900_ld;
          SetDirectMemRef(insn, insn.Op1, 2);
          break;
      }
      break;
    // add and others
    case 254:
      insn.itype=Add_List[src_byte&7];
      SetImmData(insn, insn.Op2, 1<<((code>>4)&3));
      // word size
      if ( reg_size != 0 )
        insn.itype++;
      memrefop=0;
      break;
    // shifts  xxxx (mem)
    case 253:
      insn.itype=Shift_List1[src_byte&7];
      // word size
      if ( reg_size != 0 )
        insn.itype++;
      memrefop=0;
      break;
    // inc
    case T900_inc:
    case T900_dec:
      SetImm3Op(insn.Op1, src_byte);
      // wor size
      if ( reg_size != 0 )
        insn.itype++;
      break;

    case T900_ld:
      SetRegistr7(insn.Op1, src_byte, reg_size);
      break;
    // mul/div
    case T900_mul:
    case T900_div:
    case T900_muls:
    case T900_divs:
      SetRegistr7(insn.Op1, reg_size == 0 ? (src_byte&7)/2 : src_byte, reg_size+1);
      break;
    // ex
    case T900_ex:
      SetRegistr7(insn.Op2, src_byte, reg_size);
      memrefop=0;
      break;
    // add and others
    case T900_add:
    case T900_adc:
    case T900_sub:
    case T900_sbc:
    case T900_and:
    case T900_xor:
    case T900_or:
    case T900_cp:
      if ( src_byte&0x8 )
        memrefop=0;
      SetRegistr7(insn.ops[1-memrefop], src_byte, reg_size);
      break;
  }
  MemRefToOp(insn.ops[memrefop], mr);
  return insn.size;
}

//-----------------------------------------------------------------------------
static void ClearOperand(op_t &op)
{
  op.dtype = dt_byte;
  op.type = o_void;
  op.specflag1 = 0;
  op.specflag2 = 0;
  op.offb = 0;
  op.offo = 0;
  op.reg = 0;
  op.value = 0;
  op.addr = 0;
  op.specval = 0;
}

//-----------------------------------------------------------------------------
int idaapi T900_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  ClearOperand(insn.Op1);
  ClearOperand(insn.Op2);
  ClearOperand(insn.Op3);

  uchar code = insn.get_next_byte();
  // split u pto two parts
  if ( code&0x80 )
  {
    // check for illegal
    if ( (code&0xF8) == 0xF8 )
    {
      // SWI (F8-FF)
      insn.itype=T900_swi;
      // trap number
      SetImm8Op(insn.Op1, code&7);
      // trap addres - is not working for now
      insn.Op1.addr = 0xFFFF00+(code&7)*4;
      insn.Op1.value = insn.Op1.addr;
      return insn.size;
    }
    if ( code == 0xF7 )
    {
      // LDX
      insn.itype=T900_ldx;
      // skip zero byte
      if ( insn.get_next_byte() != 0 )
        return 0;
      // address is in regs
      SetDirectMemRef(insn, insn.Op1, 1);
      // skip zero byte
      if ( insn.get_next_byte() != 0 )
        return 0;
      // data
      SetImmData(insn, insn.Op2, 1);
      // length is 6 bytes
      insn.size = 6;
      return insn.size;
    }
    // unknow codes (C6, D6, E6, F6)
    if ( (code & 0xCF) == 0xC6 )
      return 0;
    // large general reg (C8, D8, E8)
    if ( (code & 0x48) == 0x48 )
      return RegAnalyser(insn, code);
    // is smart reg ? (C7, D7, E7, F7)
    if ( (code & 0xCF) == 0xC7 )
      return RegAnalyser(insn, code);
    // memref
    // segments  dst (B0, B8, F0)
    if ( (code & 0xB0) == 0xB0 )
      return DSTAnalyser(insn, code);
    // src
    return SRCAnalyser(insn, code);
  }
  // low part
  else if ( code < 0x20 )
  {
    static const uchar FirstOp[] =
    {
      T900_nop,  T900_normal, T900_push, T900_pop,
      T900_max,  T900_halt,   T900_ei,   T900_reti,
      T900_ld,   T900_push,   T900_ldw,  T900_pushw,
      T900_incf, T900_decf,   T900_ret,  T900_retd,
      T900_rcf,  T900_scf,    T900_ccf,  T900_zcf,
      T900_push, T900_pop,    T900_ex,   T900_ldf,
      T900_push, T900_pop,    T900_jp,   T900_jp,
      T900_call, T900_call,   T900_calr, 0
    };
    insn.itype = FirstOp[code];
    switch ( insn.itype )
    {
      case 0x00:
        return 0;

      case T900_push:
      case T900_pop:
        switch ( code&0x18 )
        {
          case 0x00:
            insn.Op1.type=o_phrase;
            insn.Op1.phrase=fSR;
            break;
          // push only
          case 0x08:
            SetImmData(insn, insn.Op1, 1);
            break;
          // xxx A
          case 0x10:
            SetRegistr7(insn.Op1, 1, 0);
            break;
          // xxx F
          case 0x18:
            insn.Op1.type=o_phrase;
            insn.Op1.phrase=fSF;
            break;
        }
        break;
      // ei
      case T900_ei:   // next byte is imm
        SetImmData(insn, insn.Op1, 1);
        if ( insn.Op1.value == 7 )
        {
          insn.itype=T900_di;
          insn.Op1.type=o_void;
        }
        break;
      // ld (n), n
      case T900_ld:
        SetDirectMemRef(insn, insn.Op1, 1);
        SetImmData(insn, insn.Op2, 1);
        break;

      // ldw
      case T900_ldw:
        SetDirectMemRef(insn, insn.Op1, 1);
        SetImmData(insn, insn.Op2, 2);
        break;
      // pushW
      // retd
      case T900_pushw:
      case T900_retd:
        SetImmData(insn, insn.Op1, 2);
        break;
      // ex F, F'
      case T900_ex:
        insn.Op1.type   = o_phrase;
        insn.Op1.phrase = fSF;
        insn.Op2.type   = o_phrase;
        insn.Op2.phrase = fSF1;
        break;
      // ldf
      case T900_ldf:
        SetImmData(insn, insn.Op1, 1);
        break;

      case T900_jp:
      case T900_call:
        SetJmp(insn, insn.Op1, 2+(code&1));
        insn.Op1.specflag1 |= URB_LDA;
        break;

      // callr 16
      case T900_calr:
        SetJmp(insn, insn.Op1, -2);
        insn.Op1.specflag1 |= URB_LDA;
        break;
    }
  }
  else
  {
    switch ( code & 0x78 )
    {
      // ld
      case 0x20:
      case 0x30:
      case 0x40:
        insn.itype=T900_ld;
        SetRegistr7(insn.Op1, code, (code>>4)-2);
        SetImmData(insn, insn.Op2, 1<<((code>>4)-2));
        break;
      // push
      case 0x28:
      case 0x38:
        insn.itype=T900_push;
        SetRegistr7(insn.Op1, code, (code>>4)-1);
        break;
      // pop
      case 0x48:
      case 0x58:
        insn.itype=T900_pop;
        SetRegistr7(insn.Op1, code, (code>>4)-3);
        break;
      // reserved
      case 0x50:
        return 0;
      // JR
      case 0x60:
      case 0x68:
        if ( (code&0xF) == 0x8 )
          insn.itype = T900_jr;
        else
          insn.itype = T900_jr_cond;
        SetCondOp(insn.Op1, code&0xF);
        SetJmp(insn, insn.Op2, -1);
        insn.Op2.specflag1|=URB_LDA;
        break;
      // JRL
      case 0x70:
      case 0x78:
        if ( (code&0xF) == 0x8 )
          insn.itype=T900_jrl;
        else
          insn.itype=T900_jrl_cond;
        SetCondOp(insn.Op1, code&0xF);
        SetJmp(insn, insn.Op2, -2);
        insn.Op2.specflag1 |= URB_LDA;
        break;
    }
  }
  return insn.size;
}
