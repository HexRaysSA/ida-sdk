/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Instruction decoder
 *
 */
#include "necv850.hpp"

#include <search.hpp>

static const int bcond_map[16] =
{
  NEC850_BV,   NEC850_BL,
  NEC850_BZ,   NEC850_BNH,
  NEC850_BN,   NEC850_BR,
  NEC850_BLT,  NEC850_BLE,
  NEC850_BNV,  NEC850_BNC,
  NEC850_BNZ,  NEC850_BH,
  NEC850_BP,   NEC850_BSA,
  NEC850_BGE,  NEC850_BGT
};

struct vec_lstore_ins_t
{
  uint16 post_inc_itype = 0;
  uint16 post_dec_itype = 0;
  uint16 post_inc_ext_itype = 0;
  uint16 mod_addr_itype = 0;
  uint16 bit_rev_itype = 0;

  bool flipped = false;
  bool set = false;

  vec_lstore_ins_t() = default;
  vec_lstore_ins_t(uint16 _post_inc_itype, uint16 _post_dec_itype, uint16 _post_inc_ext_itype,
                   uint16 _mod_addr_itype, uint16 _bit_rev_itype, bool _flipped) :
    post_inc_itype(_post_inc_itype), post_dec_itype(_post_dec_itype),
    post_inc_ext_itype(_post_inc_ext_itype), mod_addr_itype(_mod_addr_itype),
    bit_rev_itype(_bit_rev_itype), flipped(_flipped), set(true)
  {
  }

  void set_vload_store(insn_t *ins, uint32 w, uint subop) const;
};

//------------------------------------------------------------------------
// The instruction formats 5 to 10 have bit10 and bit9 on and are a word
// The rest of the instructions are half-word and their format is 1 to 4
int detect_inst_len(uint16 w)
{
  return ((w & 0x600) == 0x600) ? 4 : 2;
}

//------------------------------------------------------------------------
// Fetchs an instruction (uses ua_next_xxx(insn)) of a correct size (ready for decoding)
// Returns the size of the instruction
int fetch_instruction(uint32 *w, insn_t *insn)
{
  uint16 hw = insn->get_next_word();
  int r = detect_inst_len(hw);
  if ( r == 4 )
    *w = (insn->get_next_word() << 16) | hw;
  else
    *w = hw;
  return r;
}

//------------------------------------------------------------------------
static sval_t fetch_disp32(const uint32 w, insn_t *ins)
{
  // 15             0 31            16 47            32
  // xxxxxxxxxxxxxxxx ddddddddddddddd0 DDDDDDDDDDDDDDDD
  uint32 d_low = (w >> 16);// ddddddddddddddd0
  if ( ins->size == 2 )
    d_low = ins->get_next_word();
  else if ( ins->size != 4 )
  {
    // bad format
    ins->size = 0;
    ins->itype = 0;
    return 1;
  }
  uint16 d_high = ins->get_next_word(); // DDDDDDDDDDDDDDDD
  int32 addr = (d_high<<16) | d_low;
  return sval_t(addr);
}

//------------------------------------------------------------------------
static bool decode_disp23(const uint32 w, insn_t *ins, int opidx, op_dtype_t dt)
{
  // LD.B disp23 [reg1] , reg3
  // 00000111100RRRRR wwwwwddddddd0101 DDDDDDDDDDDDDDDD
  // ddddddd is the lower 7 bits of disp23.
  // DDDDDDDDDDDDDDDD is the higher 16 bits of disp23
  // LD.H disp23[reg1], reg3
  // 00000111100RRRRR wwwwwdddddd00111 DDDDDDDDDDDDDDDD
  // dddddd is the lower side bits 6 to 1 of disp23.
  // DDDDDDDDDDDDDDDD is the higher 16 bits of disp23.

  // we need at least 32 bits of opcode here
  if ( ins->size != 4 )
    return false;

  uint16 d_low = ( w >> 20 ) & 0x7F; // ddddddd
  if ( dt != dt_byte && ( d_low & 1 ) != 0 )
    return false;
  uint16 d_high = ins->get_next_word(); // DDDDDDDDDDDDDDDD
  sval_t addr = ( d_high << 7 ) | d_low;
  SIGN_EXTEND(sval_t, addr, 23);

  op_t &op = ins->ops[opidx];
  op.type = o_displ;
  op.reg = w & 0x1F;
  op.addr = addr;
  op.dtype = dt;
  op.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED | N850F_VAL32;
  return true;
}

//------------------------------------------------------------------------
static void set_opreg(op_t *op, int reg, op_dtype_t dtyp = dt_dword)
{
  op->type = o_reg;
  op->dtype = dtyp;
  op->reg = reg;
}

//------------------------------------------------------------------------
static void set_opvreg(op_t *op, int reg, op_dtype_t dtyp = dt_qword)
{
  op->type = o_reg;
  op->dtype = dtyp;
  op->reg = rVR0 + reg;
}

//----------------------------------------------------------------------
// Create operand of condition type
static void set_opcond(op_t *x, uval_t value)
{
  x->type = o_cond;
  x->dtype = dt_qword;
  x->value = value;
}

//------------------------------------------------------------------------
static void set_opimm(op_t *op, uval_t value, int dtyp = dt_dword)
{
  op->type = o_imm;
  op->dtype = dtyp;
  op->value = value;
}

//------------------------------------------------------------------------
static void set_opwreg(op_t *op, int reg, op_dtype_t dtyp = dt_qword)
{
  op->type = o_reg;
  op->dtype = dtyp;
  op->reg = rWR0 + reg;
}

//------------------------------------------------------------------------
static void set_opdisp16(op_t *op, uint64 w, uint16 reg)
{
  uint16 disp16 = (w >> 32) & 0xFFFF;
  op->type = o_displ;
  op->addr = disp16;
  op->dtype = dt_word;
  op->reg = reg;
  op->specflag1 = N850F_USEBRACKETS;
}

//------------------------------------------------------------------------
void vec_lstore_ins_t::set_vload_store(insn_t *ins, uint32 w, uint subop) const
{
  int r1 = w & 0x1F;
  int r2 = (w & 0xF800) >> 11;
  int r3 = (w & 0xF8000000) >> 27;

  op_t *reading_op = flipped ? &ins->Op2 : &ins->Op1;
  set_opreg(reading_op, r1, dt_byte);

  reading_op->specflag1 = N850F_USEBRACKETS;

  if ( (subop & 1) == 0 )
  {
    reading_op->specflag1 |= N850F_POST_INCREMENT;

    if ( r2 != 0 )
    {
      ins->itype = post_inc_ext_itype;
      set_opreg(flipped ? &ins->Op3 : &ins->Op2, r2, dt_dword);
      set_opvreg(flipped ? &ins->Op1 : &ins->Op3, r3, dt_qword);
    }
    else
    {
      ins->itype = post_inc_itype;
      set_opvreg(flipped ? &ins->Op1 : &ins->Op2, r3, dt_qword);
    }
  }
  else
  {
    if ( r2 != 0 )
    {
      set_opreg(flipped ? &ins->Op3 : &ins->Op2, r2 & 0x1E, dt_dword);

      if ( r2 & 0x1 )
      {
        ins->itype = mod_addr_itype;
        reading_op->specflag1 |= N850F_MODULO_ADRESSING;
      }
      else
      {
        ins->itype = bit_rev_itype;
        reading_op->specflag1 |= N850F_BIT_REV_ADRESSING;
      }
    }
    else
    {
      ins->itype = post_dec_itype;
      reading_op->specflag1 |= N850F_POST_DECREMENT;
    }

    op_t *vop = flipped ? &ins->Op1 : (r2 == 0 ? &ins->Op2 : &ins->Op3);
    set_opvreg(vop, r3, dt_qword);
  }
}

//------------------------------------------------------------------------
bool nec850_t::decode_ext_simd(const uint32 lower_w, insn_t *ins)
{
  uint16 ext = ins->get_next_word();
  uint64 w = lower_w | (static_cast<uint64>(ext) << 32);

  uint32 subop = (w >> 17) & 0xFFF;
  uint8 subop_4bit = subop & 0xF;

  uint16 wreg1 = w & 0x1F;
  uint16 wreg3 = (w >> 27) & 0x1F;
  uint16 wreg2 = (w >> 43) & 0x1F;

  if ( subop_4bit == 0xE )
  {
    if ( ((w >> 22) & 0x1F) == 0x1A )
    {
      // SHFLV.W4 imm12, wreg1, wreg2, wreg3
      // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 1 1 0 1 0 I 1 1 1 0 1
      // r r r r r i i i i i i i i i i i
      ins->itype = NEC850_SHFLV_W4;

      uint8 bit21 = (w >> 21) & 1;
      uint16 imm11 = (w >> 32) & 0x7FF;

      uint16 imm12 = imm11 | (static_cast<uint16>(bit21) << 11);
      set_opimm(&ins->Op1, imm12, dt_word);
      set_opwreg(&ins->Op2, wreg1, dt_qword);
      set_opwreg(&ins->Op3, wreg2, dt_qword);
      set_opwreg(&ins->Op4, wreg3, dt_qword);
      ins->auxpref |= N850F_FP;
      return true;
    }

    // LDV.W (bit 25, 26 are 0)
    if ( ((w >> 25) & 3) == 0 )
    {
      // LDV.W imm4, disp16[reg1], wreg3
      // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 0 0 i i i i 1 1 1 0 1
      // d d d d d d d d d d d d d d 0 0
      ins->itype = NEC850_LDV_W;

      set_opimm(&ins->Op1, (w >> 21) & 0xF, dt_byte);
      set_opdisp16(&ins->Op2, w, wreg1);
      set_opwreg(&ins->Op3, wreg3, dt_qword);
    }
    else
    {
      uint8 subop_23_26 = (w >> 23) & 0xF;
      switch ( subop_23_26 )
      {
        case 5:
          {
            op_t *disp_op = &ins->Op1;
            op_t *wreg_op = &ins->Op2;
            uint8 bit21_22 = (w >> 21) & 3;
            if ( bit21_22 == 0 )
            {
              // LDV.QW disp16[reg1], wreg3
              // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 0 1 0 1 0 0 1 1 1 0 1
              // d d d d d d d d d d d d 0 0 0 0
              ins->itype = NEC850_LDV_QW;
            }
            else
            {
              // STV.QW wreg3, disp16[reg1]
              // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 0 1 0 1 0 1 1 1 1 0 1
              // d d d d d d d d d d d d 0 0 0 0
              ins->itype = NEC850_STV_QW;
              wreg_op = &ins->Op1;
              disp_op = &ins->Op2;
            }

            set_opdisp16(disp_op, w, wreg1);
            set_opwreg(wreg_op, wreg3, dt_qword);
            break;
          }
        case 4: // NEC850_STV_W
        case 6: // NEC850_LDV_DW
          // LDV.DW imm2, disp16[reg1], wreg3
          // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 0 1 1 0 i i 1 1 1 0 1
          // d d d d d d d d d d d d d 0 0 0
          ins->itype = subop_23_26 == 0b0110 ? NEC850_LDV_DW : NEC850_STV_W;
          set_opimm(&ins->Op1, (w >> 21) & 3, dt_byte);
          set_opdisp16(ins->itype == NEC850_LDV_DW ? &ins->Op2 : &ins->Op3, w, wreg1);
          set_opwreg(ins->itype == NEC850_LDV_DW ? &ins->Op3 : &ins->Op2, wreg3, dt_qword);
          break;
        case 7:
          {
            // Bit 22 is zero
            if ( ((w >> 22) & 1) == 0 )
            {
              // STV.DW imm1, wreg3, disp16[reg1]
              // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 0 1 1 1 0 i 1 1 1 0 1
              // d d d d d d d d d d d d d 0 0 0
              ins->itype = NEC850_STV_DW;

              uint8 imm1 = (w >> 21) & 1;
              set_opimm(&ins->Op1, imm1, dt_byte);
              set_opwreg(&ins->Op2, wreg3, dt_qword);
              set_opdisp16(&ins->Op3, w, wreg1);
              break;
            }
            uint8 bit21_22 = (w >> 21) & 3;
            switch ( bit21_22 )
            {
              case 2:
              case 3:
                // LDVZ.H4 disp16[reg1], wreg3
                // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 0 1 1 1 1 0 1 1 1 0 1
                // d d d d d d d d d d d d d 0 0 0
                ins->itype = bit21_22 == 2 ? NEC850_LDVZ_H4 : NEC850_STVZ_H4;
                set_opdisp16(ins->itype == NEC850_LDVZ_H4 ? &ins->Op1 : &ins->Op2, w, wreg1);
                set_opwreg(ins->itype == NEC850_LDVZ_H4 ? &ins->Op2 : &ins->Op1, wreg3, dt_qword);
              default:
                break;
            }
            break;
          }
        case 0xC:
          {
            // CMOVF.W4 wreg4, wreg1, wreg2, wreg3
            // 0 0 0 0 0 1 1 1 1 0 1 R R R R R w w w w w 1 1 0 0 0 0 1 1 1 0 1
            // r r r r r 0 0 0 0 0 0 W W W W W
            ins->itype = NEC850_CMOVF_W4;
            uint16 wreg4 = (w >> 32) & 0x1F;
            set_opwreg(&ins->Op1, wreg4, dt_qword);
            set_opwreg(&ins->Op2, wreg1, dt_qword);
            set_opwreg(&ins->Op3, wreg2, dt_qword);
            set_opwreg(&ins->Op4, wreg3, dt_qword);
            break;
          }
        default:
          break;
      }
    }
  }

  if ( ins->itype != NEC850_NULL )
  {
    ins->auxpref |= N850F_FP;
    return true;
  }

  return false;
}

//------------------------------------------------------------------------
// Decodes an instruction "w" into cmd structure
bool nec850_t::decode_coprocessor(const uint32 w, insn_t *ins) const
{ // 11111  1            33222 2 222 22 2111 1
  // 54321  098765 43210 10987 6 543 21 0987 6
  // reg2  |opcode|reg1 |reg3 |b|cat|ty|subo|b|
  // ..... |111111|.....|.....|1|...|..|....|0|
  int r1 = w & 0x1F;
  int r2 = ( w & 0xF800 ) >> 11;
  int r3 = ( w & 0xF8000000 ) >> 27;
  int cat = ( w >> 23 ) & 7;
  int typ = ( w >> 21 ) & 3;
  int subop = ( w >> 17 ) & 0xF;
  ins->itype = NEC850_NULL;
  // we only support V850E2M and RH850 FP instructions
  if ( !is_v850e2m() )
    return false;
  if ( typ == 0 && cat == 0 )
  {
    // CMOVF.D: cat = 000, type = 00, subop = 1fff, reg3 != 0
    // CMOVF.S : cat = 000, type = 00, subop = 0fff, reg3 != 0
    // TRFSR: cat = 000, type = 00, subop = 0fff, reg1 = 0, reg3 = 0
    if ( r3 != 0 )
    {
      // CMOVF.S|D fcbit, reg1, reg2, reg3
      ins->itype = ( subop & 8 ) ? NEC850_CMOVF_D : NEC850_CMOVF_S;
      int fcbit = subop & 7;
      set_opimm(&ins->Op1, fcbit);
      set_opreg(&ins->Op2, r1);
      set_opreg(&ins->Op3, r2);
      set_opreg(&ins->Op4, r3);
    }
    else if ( subop < 8 )
    {
      ins->itype = NEC850_TRFSR;
      int fcbit = subop & 7;
      set_opimm(&ins->Op1, fcbit);
    }
  }
  else if ( typ == 1 && cat == 0 && r3 < 0x10 )
  {
    // CMPF.D:  cat = 000, type = 01, subop = 1fff, reg3 = 0FFFF
    // CMPF.S : cat = 000, type = 01, subop = 0fff, reg3 = 0FFFF
    // CMPF.S|D fcond, reg2, reg1, fcbit
    ins->itype = ( subop & 8 ) ? NEC850_CMPF_D : NEC850_CMPF_S;
    int fcbit = subop & 7;
    set_opcond(&ins->Op1, r3);
    set_opreg(&ins->Op2, r2);
    set_opreg(&ins->Op3, r1);
    set_opimm(&ins->Op4, fcbit);
  }
  else if ( typ == 3 )
  {
    // reg1, reg2, reg3
    if ( cat == 0 )
    {
      switch ( subop & 7 )
      {
        case 0:
          ins->itype = ( subop & 8 ) ? NEC850_ADDF_D : NEC850_ADDF_S;
          break;
        case 1:
          ins->itype = ( subop & 8 ) ? NEC850_SUBF_D : NEC850_SUBF_S;
          break;
        case 2:
          ins->itype = ( subop & 8 ) ? NEC850_MULF_D : NEC850_MULF_S;
          break;
        case 4:
          ins->itype = ( subop & 8 ) ? NEC850_MAXF_D : NEC850_MAXF_S;
          break;
        case 5:
          ins->itype = ( subop & 8 ) ? NEC850_MINF_D : NEC850_MINF_S;
          break;
        case 7:
          ins->itype = ( subop & 8 ) ? NEC850_DIVF_D : NEC850_DIVF_S;
          break;

      }
    }
    else if ( cat == 1 && subop < 4 )
    {
      if ( is_rh850() )
      {
        uint16 itypes[] = { NEC850_FMAF_S, NEC850_FMSF_S, NEC850_FNMAF_S, NEC850_FNMSF_S };
        ins->itype = itypes[subop];
      }
    }
    if ( ins->itype != NEC850_NULL )
    {
      bool dbl = ( subop & 8 ) != 0;
      op_dtype_t dt = dbl ? dt_double : dt_float;
      set_opreg(&ins->Op1, r1, dt);
      set_opreg(&ins->Op2, r2, dt);
      set_opreg(&ins->Op3, r3, dt);
    }
  }
  else if ( typ == 2 && cat == 0 )
  {
    // reg2, reg3 conversions
    op_dtype_t dtsrc = dt_float, dtdst = dt_float;
    switch ( subop )
    {
      case 0:
        {
          // ROUNDF.SW cat = 0 type = 2 subop = 0 reg1 = 0
          // TRNCF.SW cat = 0 type = 2 subop = 0 reg1 = 1
          // CEILF.SW cat = 0 type = 2 subop = 0 reg1 = 2
          // FLOORF.SW cat = 0 type = 2 subop = 0 reg1 = 3
          // CVTF.SW cat = 0 type = 2 subop = 0 reg1 = 4
          // ROUNDF.SUW cat = 0 type = 2 subop = 0 reg1 = 16
          // TRNCF.SUW cat = 0 type = 2 subop = 0 reg1 = 17
          // CEILF.SUW cat = 0 type = 2 subop = 0 reg1 = 18
          // FLOORF.SUW cat = 0 type = 2 subop = 0 reg1 = 19
          // CVTF.SUW cat = 0 type = 2 subop = 0 reg1 = 20
          static const int ops[] =
          {
            NEC850_ROUNDF_SW, NEC850_TRNCF_SW, NEC850_CEILF_SW, NEC850_FLOORF_SW, // 0-3
            NEC850_CVTF_SW, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_SUW, NEC850_TRNCF_SUW, NEC850_CEILF_SUW, NEC850_FLOORF_SUW, // 16-19
            NEC850_CVTF_SUW  // 20
          };
          if ( r1 < qnumber(ops) )
            ins->itype = ops[r1];
          dtsrc = dt_float;
          dtdst = dt_dword;
        }
        break;
      case 1:
        {
          // CVTF.WS cat=0 type=2 subop=1 reg1=0   dw f
          // CVTF.LS cat=0 type=2 subop=1 reg1=1   dq f
          // CVTF.HS cat=0 type=2 subop=1 reg1=2   h f
          // CVTF.SH cat=0 type=2 subop=1 reg1=3   f h
          // CVTF.UWS cat=0 type=2 subop=1 reg1=16 dw f
          // CVTF.ULS cat=0 type=2 subop=1 reg1=17 dq f
          static const int ops[] =
          {
            NEC850_CVTF_WS, NEC850_CVTF_LS, NEC850_CVTF_HS, NEC850_CVTF_SH, // 0-3
            NEC850_CVTF_SW, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_CVTF_UWS, NEC850_CVTF_ULS // 16-17
          };
          if ( r1 < qnumber(ops) )
            ins->itype = ops[r1];
          // NB: we use dt_float for half-precision
          op_dtype_t srct[] = { dt_dword, dt_qword, dt_float, dt_float };
          dtsrc = srct[r1&3];
          dtdst = dt_float;
        }
        break;
      case 2:
        {
          // ROUNDF.SL cat=0 type=2 subop=2 reg1=0
          // TRNCF.SL cat=0 type=2 subop=2 reg1=1
          // CEILF.SL cat=0 type=2 subop=2 reg1=2
          // FLOORF.SL cat=0 type=2 subop=2 reg1=3
          // CVTF.SL cat=0 type=2 subop=2 reg1=4
          // ROUNDF.SUL cat=0 type=2 subop=2 reg1=16
          // TRNCF.SUL cat=0 type=2 subop=2 reg1=17
          // CEILF.SUL cat=0 type=2 subop=2 reg1=18
          // FLOORF.SUL cat=0 type=2 subop=2 reg1=19
          // CVTF.SUL cat=0 type=2 subop=2 reg1=20
          static const int ops[] =
          {
            NEC850_ROUNDF_SL, NEC850_TRNCF_SL, NEC850_CEILF_SL, NEC850_FLOORF_SL, // 0-3
            NEC850_CVTF_SL, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_SUL, NEC850_TRNCF_SUL, NEC850_CEILF_SUL, NEC850_FLOORF_SUL, // 16-19
            NEC850_CVTF_SUL  // 20
          };
          if ( r1 < qnumber(ops) )
            ins->itype = ops[r1];
          dtsrc = dt_float;
          dtdst = dt_qword;
        }
        break;
      case 4:
      case 12:
        {
          // ABSF.S cat = 0 type = 2 subop = 4 reg1 = 0
          // NEGF.S cat = 0 type = 2 subop = 4 reg1 = 1
          // ABSF.D cat = 0 type = 2 subop = 12 reg1 = 0
          // NEGF.D cat = 0 type = 2 subop = 12 reg1 = 1
          if ( r1 == 0 )
            ins->itype = subop == 4 ? NEC850_ABSF_S : NEC850_ABSF_D;
          else if ( r1 == 1 )
            ins->itype = subop == 4 ? NEC850_NEGF_S : NEC850_NEGF_D;

          dtsrc = subop == 4 ? dt_float: dt_double;
          dtdst = dtsrc;
        }
        break;
      case 7:
      case 15:
        {
          // SQRTF.S cat=0 type=2 subop=7 reg1=0
          // RECIPF.S cat=0 type=2 subop=7 reg1=1
          // RSQRTF.S cat=0 type=2 subop=7 reg1=2
          // SQRTF.D cat=0 type=2 subop=15 reg1=0
          // RECIPF.D cat=0 type=2 subop=15 reg1=1
          // RSQRTF.D cat=0 type=2 subop=15 reg1=2

          if ( r1 == 0 )
            ins->itype = subop == 7 ? NEC850_SQRTF_S : NEC850_SQRTF_D;
          else if ( r1 == 1 )
            ins->itype = subop == 7 ? NEC850_RECIPF_S : NEC850_RECIPF_D;
          else if ( r1 == 2 )
            ins->itype = subop == 7 ? NEC850_RSQRTF_S : NEC850_RSQRTF_D;

          dtsrc = subop == 7 ? dt_float : dt_double;
          dtdst = dtsrc;
        }
        break;
      case 8:
        {
          // ROUNDF.DW cat=0 type=2 subop=8 reg1=0
          // TRNCF.DW cat=0 type=2 subop=8 reg1=1
          // CEILF.DW cat=0 type=2 subop=8 reg1=2
          // FLOORF.DW cat=0 type=2 subop=8 reg1=3
          // CVTF.DW cat=0 type=2 subop=8 reg1=4
          // TRNCF.DUW cat=0 type=2 subop=8 reg1=17
          // CEILF.DUW cat=0 type=2 subop=8 reg1=18
          // FLOORF.DUW cat=0 type=2 subop=8 reg1=19
          // CVTF.DUW cat=0 type=2 subop=8 reg1=20
          static const int ops[] =
          {
            NEC850_ROUNDF_DW, NEC850_TRNCF_DW, NEC850_CEILF_DW, NEC850_FLOORF_DW, // 0-3
            NEC850_CVTF_DW, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_DUW, NEC850_TRNCF_DUW, NEC850_CEILF_DUW, NEC850_FLOORF_DUW, // 16-19
            NEC850_CVTF_DUW  // 20
          };
          if ( r1 < qnumber(ops) )
            ins->itype = ops[r1];
          dtsrc = dt_double;
          dtdst = dt_dword;
        }
        break;
      case 9:
        {
          // CVTF.WD cat=0 type=2 subop=9 reg1=0 dw d
          // CVTF.LD cat=0 type=2 subop=9 reg1=1 dq d
          // CVTF.SD cat=0 type=2 subop=9 reg1=2 f d
          // CVTF.DS cat=0 type=2 subop=9 reg1=3 d f
          // CVTF.UWD cat=0 type=2 subop=9 reg1=16 dw d
          // CVTF.ULD cat=0 type=2 subop=9 reg1=17 dq d
          static const int ops[] =
          {
            NEC850_CVTF_WD, NEC850_CVTF_LD, NEC850_CVTF_SD, NEC850_CVTF_DS, // 0-3
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL,  // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_CVTF_UWD, NEC850_CVTF_ULD  // 16-17
          };
          if ( r1 < qnumber(ops) )
            ins->itype = ops[r1];
          op_dtype_t srct[] = { dt_dword, dt_qword, dt_float, dt_double };
          dtsrc = srct[r1 & 3];
          dtdst = r1 == 3 ? dt_float : dt_double;
        }
        break;
      case 10:
        {
          // ROUNDF.DL cat=0 type=2 subop=10 reg1=0
          // TRNCF.DL cat=0 type=2 subop=10 reg1=1
          // CEILF.DL cat=0 type=2 subop=10 reg1=2
          // FLOORF.DL cat=0 type=2 subop=10 reg1=3
          // CVTF.DL cat=0 type=2 subop=10 reg1=4
          // ROUNDF.DUL cat=0 type=2 subop=10 reg1=4
          // TRNCF.DUL cat=0 type=2 subop=10 reg1=17
          // CEILF.DUL cat=0 type=2 subop=10 reg1=18
          // FLOORF.DUL cat=0 type=2 subop=10 reg1=19
          // CVTF.DUL cat=0 type=2 subop=10 reg1=20
          static const int ops[] =
          {
            NEC850_ROUNDF_DL, NEC850_TRNCF_DL, NEC850_CEILF_DL, NEC850_FLOORF_DL, // 0-3
            NEC850_CVTF_DL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 4-7
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 8-11
            NEC850_NULL, NEC850_NULL, NEC850_NULL, NEC850_NULL, // 12-15
            NEC850_ROUNDF_DUL, NEC850_TRNCF_DUL, NEC850_CEILF_DUL, NEC850_FLOORF_DUL, // 16-19
            NEC850_CVTF_DUL // 20
          };
          if ( r1 < qnumber(ops) )
            ins->itype = ops[r1];

          dtsrc = dt_double;
          dtdst = dt_qword;
        }
        break;
    }
    if ( ins->itype != NEC850_NULL )
    {
      set_opreg(&ins->Op1, r2, dtsrc);
      set_opreg(&ins->Op2, r3, dtdst);
    }
  }
  if ( ins->itype == NEC850_NULL && (is_v850e2m() && !is_rh850()) && ( cat >> 1 ) == 1 )
  {
    // reg1, reg2, reg3, reg4
    // MADDF.S: cat = 01W type = 00, subop = WWWW
    // MSUBF.S : cat = 01W type = 01, subop = WWWW
    // NMADDF.S : cat = 01W type = 10, subop = WWWW
    // NMSUBF.S : cat = 01W type = 11, subop = WWWW
    // WWWWW: reg4. (The least significant bit of reg4 is bit 23.)

    // Special case for MSUBF.S
    int r4 = (subop << 1) | (cat & 1);
    if ( typ == 1 && r4 != 1 )
    {
      ins->itype = NEC850_MSUBF_S;
    }
    else
    {
      static const uint16 itypes[] = { NEC850_MADDF_S, NEC850_NULL, NEC850_NMADDF_S, NEC850_NMSUBF_S };
      ins->itype = itypes[typ];
    }

    if ( ins->itype != NEC850_NULL )
    {
      set_opreg(&ins->Op1, r1, dt_float);
      set_opreg(&ins->Op2, r2, dt_float);
      set_opreg(&ins->Op3, r3, dt_float);
      set_opreg(&ins->Op4, r4, dt_float);
    }
  }

  if ( ins->itype == NEC850_NULL )
  {
    subop = (w >> 17) & 0x3F;

    switch ( cat )
    {
      case 1:
        {
          if ( is_rh850() )
          {
            if ( subop >= 0x20 && subop <= 0x23 )
            {
              static const uint16 map[] =
              {
                NEC850_FMAF_S4, NEC850_FMSF_S4,
                NEC850_FNMAF_S4, NEC850_FNMSF_S4
              };

              uint idx = subop - 0x20;
              if ( idx < qnumber(map) )
              {
                ins->itype = map[idx];
                if ( ins->itype != NEC850_NULL )
                {
                  set_opwreg(&ins->Op1, r1, dt_qword);
                  set_opwreg(&ins->Op2, r2, dt_qword);
                  set_opwreg(&ins->Op3, r3, dt_qword);
                  break;
                }
              }
            }
          }
          break;
        }
      case 3:
        {
          if ( is_rh850() )
          {
            switch ( subop )
            {
              case 0x10:
                {
                  switch ( r1 )
                  {
                    case 0x1E:
                      // MOVV.W4 wreg2, wreg3
                      // r r r r r 1 1 1 1 1 1 1 1 1 1 0 w w w w w 1 0 1 1 0 1 0 0 0 0 0
                      ins->itype = NEC850_MOVV_W4;
                      set_opwreg(&ins->Op1, r2, dt_qword);
                      set_opwreg(&ins->Op2, r3, dt_qword);
                      break;
                    case 0x1F:
                      // TRFSRV.W4 imm3, wreg2
                      // r r r r r 1 1 1 1 1 1 1 1 1 1 1 0 0 i i i 1 0 1 1 0 1 0 0 0 0 0
                      ins->itype = NEC850_TRFSRV_W4;
                      set_opimm(&ins->Op1, r3, dt_byte);
                      set_opwreg(&ins->Op2, r2);
                      break;
                    default:
                      if ( r1 <= 0x14 )
                      {
                        static const uint16 map[] =
                        {
                          NEC850_ROUNDF_SW4, NEC850_ROUNDF_SUW4, NEC850_TRNCF_SW4,
                          NEC850_TRNCF_SUW4, NEC850_CEILF_SW4, NEC850_CEILF_SUW4,
                          NEC850_FLOORF_SW4, NEC850_FLOORF_SUW4, NEC850_CVTF_SW4,
                          NEC850_CVTF_SUW4, NEC850_CVTF_WS4, NEC850_CVTF_UWS4,
                          NEC850_CVTF_HS4, NEC850_CVTF_SH4, NEC850_NULL,
                          NEC850_NULL, NEC850_ABSF_S4, NEC850_NEGF_S4,
                          NEC850_SQRTF_S4, NEC850_RECIPF_S4, NEC850_RSQRTF_S4
                        };

                        uint idx = r1;
                        if ( idx < qnumber(map) )
                        {
                          ins->itype = map[idx];
                          if ( ins->itype != NEC850_NULL )
                          {
                            set_opwreg(&ins->Op1, r2, dt_qword);
                            set_opwreg(&ins->Op2, r3, dt_qword);
                            break;
                          }
                        }
                      }

                      if ( ((r1 >> 2) & 7) == 6 )
                      {
                        // FLPV.S4
                        // r r r r r 1 1 1 1 1 1 1 1 0 i i w w w w w 1 0 1 1 0 1 0 0 0 0 0
                        ins->itype = NEC850_FLPV_S4;
                        set_opimm(&ins->Op1, w & 3, dt_byte);
                        set_opwreg(&ins->Op2, r2, dt_qword);
                        set_opwreg(&ins->Op3, r3, dt_qword);
                      }
                      break;
                  }
                break;
                }
              default:
                {
                  if ( subop >= 0x12 && subop <= 0x2F )
                  {
                    static const uint16 map[] =
                    {
                      NEC850_ADDF_S4, NEC850_SUBF_S4, NEC850_MULF_S4,
                      NEC850_MAXF_S4, NEC850_MINF_S4, NEC850_DIVF_S4,
                      NEC850_NULL, NEC850_NULL, NEC850_ADDRF_S4,
                      NEC850_SUBRF_S4, NEC850_MULRF_S4, NEC850_MAXRF_S4,
                      NEC850_MINRF_S4, NEC850_NULL, NEC850_NULL,
                      NEC850_NULL, NEC850_ADDXF_S4, NEC850_SUBXF_S4,
                      NEC850_MULXF_S4, NEC850_NULL, NEC850_NULL,
                      NEC850_NULL, NEC850_ADDSUBF_S4, NEC850_SUBADDF_S4,
                      NEC850_ADDSUBXF_S4, NEC850_SUBADDXF_S4, NEC850_ADDSUBNF_S4,
                      NEC850_SUBADDNF_S4, NEC850_ADDSUBNXF_S4, NEC850_SUBADDNXF_S4
                    };

                    uint idx = subop - 0x12;
                    if ( idx < qnumber(map) )
                    {
                      ins->itype = map[idx];
                      if ( ins->itype != NEC850_NULL )
                      {
                        set_opwreg(&ins->Op1, r1, dt_qword);
                        set_opwreg(&ins->Op2, r2, dt_qword);
                        set_opwreg(&ins->Op3, r3, dt_qword);
                        break;
                      }
                    }
                  }

                  if ( ((subop >> 4) & 3) == 0 )
                  {
                    ins->itype = NEC850_CMPF_S4;
                    set_opcond(&ins->Op1, subop & 0xF);
                    set_opwreg(&ins->Op2, r1, dt_qword);
                    set_opwreg(&ins->Op3, r2, dt_qword);
                    set_opwreg(&ins->Op4, r3, dt_qword);
                  }
                  break;
                }
            }
          }
          break;
        }
      case 4:
        {
          switch ( subop )
          {
            case 0x3F:
              {
                static const uint16 map[] =
                {
                  NEC850_VABS_H, NEC850_VABS_W,
                  NEC850_VNEG_H, NEC850_VNEG_W,
                  NEC850_CNVQ15Q30, NEC850_CNVQ31Q62,
                  NEC850_CNVQ30Q15, NEC850_CNVQ62Q31,
                  NEC850_EXPQ31
                };

                if ( r1 < qnumber(map) )
                {
                  ins->itype = map[r1];
                  set_opvreg(&ins->Op1, r2, dt_qword);

                  if ( ins->itype != NEC850_EXPQ31 )
                    set_opvreg(&ins->Op2, r3, dt_qword);
                  else
                    set_opreg(&ins->Op2, r3, dt_dword);
                }
                break;
              }
            case 0x38:
            case 0x39:
              {
                ins->itype = subop == 0x38 ? NEC850_VCALCH : NEC850_VCALCW;

                uint8 bit31 = (w >> 31) & 1;
                uint8 bit4 = (w >> 4) & 1;
                uint8 bit15 = (w >> 15) & 1;

                uint combined_vreg4 = (bit31 << 2) | (bit15 << 1) | bit4;
                set_opvreg(&ins->Op1, combined_vreg4 | 0b11000, dt_qword);
                set_opvreg(&ins->Op2, r1, dt_qword);
                set_opvreg(&ins->Op3, r2, dt_qword);
                set_opvreg(&ins->Op4, r3, dt_qword);
                break;
              }
            default:
              {
                if ( subop <= 0x36 )
                {
                  static const uint16 map[] =
                  {
                    NEC850_VADD_H, NEC850_VADD_W, NEC850_VSUB_H,
                    NEC850_VSUB_W, NEC850_VADDS_H, NEC850_VADDS_W,
                    NEC850_VSUBS_H, NEC850_VSUBS_W, NEC850_VADDSAT_H,
                    NEC850_VADDSAT_W, NEC850_VSUBSAT_H, NEC850_VSUBSAT_W,
                    NEC850_VMUL_H, NEC850_VMUL_W, NEC850_VMULT_H,
                    NEC850_VMULT_W, NEC850_VCMPEQ_H, NEC850_VCMPEQ_W,
                    NEC850_VCMPNE_H, NEC850_VCMPNE_W, NEC850_VCMPLT_H,
                    NEC850_VCMPLT_W, NEC850_VCMPLE_H, NEC850_VCMPLE_W,
                    NEC850_VMSUMAD_H, NEC850_VMSUMAD_W, NEC850_VMSUMADIM_H,
                    NEC850_VMSUMADIM_W, NEC850_VMSUMADRE_H, NEC850_VMSUMADRE_W,
                    NEC850_VMSUMADRN_H, NEC850_NULL, NEC850_VMADSAT_H,
                    NEC850_VMADSAT_W, NEC850_VMADRN_H, NEC850_VMADRN_W,
                    NEC850_VMULCX_H, NEC850_VMULCX_W, NEC850_VMSUM_H,
                    NEC850_VMSUM_W, NEC850_NULL, NEC850_NULL,
                    NEC850_NULL, NEC850_NULL, NEC850_VADD_DW,
                    NEC850_VSUB_DW, NEC850_VBIQ_H, NEC850_PKQ30Q31,
                    NEC850_PKQ31Q15, NEC850_PKI64I32, NEC850_PKI32I16,
                    NEC850_PKI16UI8, NEC850_PKQ15Q31, NEC850_PKI16I32,
                    NEC850_PKUI8I16
                  };

                  if ( subop < qnumber(map) )
                  {
                    ins->itype = map[subop];
                    if ( ins->itype != NEC850_NULL )
                    {
                      set_opvreg(&ins->Op1, r1, dt_qword);
                      set_opvreg(&ins->Op2, r2, dt_qword);
                      set_opvreg(&ins->Op3, r3, dt_qword);
                      break;
                    }
                  }
                }

                if ( subop >= 0x28 && subop <= 0x2B )
                {
                  struct instruction_pair_t { uint16 lower_variant; uint16 higher_variant; };
                  static const instruction_pair_t map[] =
                  {
                    { NEC850_VMAXGT_H, NEC850_VMAXGE_H },
                    { NEC850_VMAXGT_W, NEC850_VMAXGE_W },
                    { NEC850_VMINLT_H, NEC850_VMINLE_H },
                    { NEC850_VMINLT_W, NEC850_VMINLE_W }
                  };

                  uint idx = subop - 0x28;
                  if ( idx < qnumber(map) )
                  {
                    auto &entry = map[idx];

                    bool bit27_set = ((w >> 27) & 1) == 1;
                    ins->itype = bit27_set ? entry.higher_variant : entry.lower_variant;

                    set_opreg(&ins->Op1, r1, dt_dword);
                    set_opvreg(&ins->Op2, r2, dt_qword);
                    set_opvreg(&ins->Op3, bit27_set ? (r3 >> 1) & 0xF : r3, dt_qword);
                    break;
                  }
                }
                break;
              }
          }
          break;
        }
      case 5:
        {
          switch ( subop )
          {
            case 0:
            case 1:
            case 2:
              {
                // VAND, VOR, VXOR vreg1, vreg2, vreg3
                //
                // VAND: r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 0 0 0 0 0 0
                // VOR:  r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 0 0 0 0 1 0
                // VXOR: r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 0 0 0 1 0 0
                static const uint16 map[] =
                {
                  NEC850_VAND, NEC850_VOR, NEC850_VXOR
                };

                ins->itype = map[subop];
                set_opvreg(&ins->Op1, r1, dt_qword);
                set_opvreg(&ins->Op2, r2, dt_qword);
                set_opvreg(&ins->Op3, r3, dt_qword);
                break;
              }
            case 0xC:
            case 0xD:
            case 0xE:
            case 0xF:
            case 0x10:
              {
                // Those cases are special because: The I value (bit 17) is the highest bit of 6-bit immediate data
                // We ignore the last bit in the subop
                uint subop2 = subop >> 1;
                switch ( subop2 )
                {
                  case 6:
                    // VSAR.DW imm6, vreg2, vreg3
                    // r r r r r 1 1 1 1 1 1 i i i i i w w w w w 1 1 0 1 0 0 1 1 0 I 0
                    ins->itype = NEC850_VSAR_DW;
                    break;
                  case 7:
                    // VSHR.DW imm6, vreg2, vreg3
                    // r r r r r 1 1 1 1 1 1 i i i i i w w w w w 1 1 0 1 0 0 1 1 1 I 0
                    ins->itype = NEC850_VSHR_DW;
                    break;
                  case 8:
                    // VSHL.DW imm6, vreg2, vreg3
                    // r r r r r 1 1 1 1 1 1 i i i i i w w w w w 1 1 0 1 0 1 0 0 0 I 0
                    ins->itype = NEC850_VSHL_DW;
                    break;
                  default:
                    break;
                }
                uint imm6 = ((subop & 1) << 6) | r1;
                set_opimm(&ins->Op1, imm6, dt_byte);
                set_opvreg(&ins->Op2, r2, dt_qword);
                set_opvreg(&ins->Op3, r3, dt_qword);
                break;
              }
              case 0x12:
                // VSAR.W reg1, vreg2, vreg3
                // r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 0 0 1 1 0 0
                ins->itype = NEC850_VSAR_W;
                set_opimm(&ins->Op1, r1 & 0xF, dt_byte);
                set_opvreg(&ins->Op2, r2, dt_qword);
                set_opvreg(&ins->Op3, r3, dt_qword);
                break;
              case 0x13:
                // VSHR.W reg1, vreg2, vreg3
                // r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 0 0 1 1 1 0
                ins->itype = NEC850_VSHR_W;
                set_opimm(&ins->Op1, r1 & 0x1F, dt_byte);
                set_opvreg(&ins->Op2, r2, dt_qword);
                set_opvreg(&ins->Op3, r3, dt_qword);
                break;
              case 0x14:
                // VSHL.W reg1, vreg2, vreg3
                // r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 0 1 0 0 0 0
                ins->itype = NEC850_VSHL_W;
                set_opimm(&ins->Op1, r1 & 0x1F, dt_byte);
                set_opvreg(&ins->Op2, r2, dt_qword);
                set_opvreg(&ins->Op3, r3, dt_qword);
                break;
              case 0x15:
              case 0x16:
                {
                  uint bit4 = ((w >> 4) & 1);

                  // VSAR.H imm4, vreg2, vreg3
                  // r r r r r 1 1 1 1 1 1 0 i i i i w w w w w 1 1 0 1 0 1 0 1 0 1 0
                  //
                  // VSHR.H imm4, vreg2, vreg3
                  // r r r r r 1 1 1 1 1 1 1 i i i i w w w w w 1 1 0 1 0 1 0 1 0 1 0
                  //
                  // VSHL.H imm4, vreg2, vreg3
                  // r r r r r 1 1 1 1 1 1 0 i i i i w w w w w 1 1 0 1 0 1 0 1 1 0 0

                  static const uint16 map[] =
                  {
                    // bit4 == 0   bit4 == 1
                    NEC850_VSAR_H, NEC850_VSHR_H, // 0x15
                    NEC850_VSHL_H, NEC850_NULL    // 0x16
                  };

                  uint idx = ((subop - 0x15) * 2) + bit4;
                  if ( idx < qnumber(map) )
                  {
                    ins->itype = map[idx];
                    if ( ins->itype != NEC850_NULL )
                    {
                      set_opimm(&ins->Op1, r1 & 0xF, dt_byte);
                      set_opvreg(&ins->Op2, r2, dt_qword);
                      set_opvreg(&ins->Op3, r3, dt_qword);
                    }
                  }
                  break;
                }
              case 0x17:
                {
                  // VSHUFL.B reg1, vreg2, vreg3
                  // r r r r r 1 1 1 1 1 1 R R R R R w w w w w 1 1 0 1 0 1 0 1 1 1 0
                  ins->itype = NEC850_VSHUFL_B;
                  set_opreg(&ins->Op1, r1, dt_dword);
                  set_opvreg(&ins->Op2, r2, dt_qword);
                  set_opvreg(&ins->Op3, r3, dt_qword);
                  break;
                }
              case 0x18:
              case 0x19:
                {
                  // VCMOV vreg4, vreg1, vreg2, vreg3
                  // W r r r r 1 1 1 1 1 1 W R R R R W w w w w 1 1 0 1 0 1 1 0 0 0 0
                  //
                  // VCONCAT.B reg4, vreg1, vreg2, vreg3
                  // W r r r r 1 1 1 1 1 1 W R R R R W w w w w 1 1 0 1 0 1 1 0 0 1 0
                  ins->itype = subop == 0x18 ? NEC850_VCMOV : NEC850_VCONCAT_B;

                  uint8 bit31 = (w >> 31) & 1;
                  uint8 bit4 = (w >> 4) & 1;
                  uint8 bit15 = (w >> 15) & 1;

                  uint combined_r1 = (bit31 << 2) | (bit15 << 1) | bit4;

                  if ( ins->itype == NEC850_VCMOV )
                  {
                    combined_r1 |= 0b11000;
                    set_opvreg(&ins->Op1, combined_r1, dt_qword);
                  }
                  else
                  {
                    combined_r1 |= 0b1000;
                    set_opreg(&ins->Op1, combined_r1, dt_byte);
                  }

                  set_opvreg(&ins->Op2, w & 0xF, dt_qword);
                  set_opvreg(&ins->Op3, (w >> 11) & 0xF, dt_qword);
                  set_opvreg(&ins->Op4, (w >> 27) & 0xF, dt_qword);
                  break;
                }
              case 0x2C:
                // MODADD
                // r r r r 0 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 1 0 1 1 0 1 1 0 0 0
                ins->itype = NEC850_MODADD;
                set_opreg(&ins->Op1, r2, dt_dword);
                break;
              case 0x2D:
                {
                  uint8 imm = w & 1;
                  uint type = (w >> 1) & 0xF;

                  // MOV.DW vreg2, reg3
                  // r r r r r 1 1 1 1 1 1 1 1 0 0 0 w w w w w 1 1 0 1 1 0 1 1 0 1 0
                  //
                  // MOV.DW reg2, vreg3
                  // r r r r r 1 1 1 1 1 1 1 1 1 0 0 w w w w w 1 1 0 1 1 0 1 1 0 1 0

                  ins->itype = (type == 0xC || type == 0xE) ? NEC850_MOV_DW : NEC850_MOV_W;

                  switch ( type )
                  {
                    case 0:
                      // MOV.W imm1, vreg2, vreg3
                      // r r r r r 1 1 1 1 1 1 0 0 0 0 i w w w w w 1 1 0 1 1 0 1 1 0 1 0
                      set_opimm(&ins->Op1, imm, dt_byte);
                      set_opvreg(&ins->Op2, r2, dt_qword);
                      set_opvreg(&ins->Op3, r3, dt_qword);
                      break;
                    case 4:
                      // MOV.W imm1, vreg2, reg3
                      // r r r r r 1 1 1 1 1 1 0 1 0 0 i w w w w w 1 1 0 1 1 0 1 1 0 1 0
                      set_opimm(&ins->Op1, imm, dt_byte);
                      set_opvreg(&ins->Op2, r2, dt_qword);
                      set_opreg(&ins->Op3, r3, dt_dword);
                      break;
                    case 8:
                      // MOV.W imm1, reg2, vreg3
                      // r r r r r 1 1 1 1 1 1 0 1 0 0 i w w w w w 1 1 0 1 1 0 1 1 0 1 0
                      set_opimm(&ins->Op1, imm, dt_byte);
                      set_opreg(&ins->Op2, r2, dt_dword);
                      set_opvreg(&ins->Op3, r3, dt_qword);
                      break;
                    case 0xC:
                      // MOV.DW vreg2, reg3
                      // r r r r r 1 1 1 1 1 1 1 1 0 0 0 w w w w w 1 1 0 1 1 0 1 1 0 1 0
                      set_opvreg(&ins->Op1, r2, dt_qword);
                      set_opreg(&ins->Op2, r3, dt_dword);
                      break;
                    case 0xE:
                      // MOV.DW reg2, vreg3
                      // r r r r r 1 1 1 1 1 1 1 1 1 0 0 w w w w w 1 1 0 1 1 0 1 1 0 1 0
                      set_opreg(&ins->Op1, r2, dt_dword);
                      set_opvreg(&ins->Op2, r3, dt_qword);
                      break;
                    default:
                      break;
                  }
                  break;
                }
              case 0x2E:
              case 0x2F:
                {
                  uint subop2 = w & 0x1F;
                  uint8 subop2_3bits = (subop2 >> 2) & 7;
                  uint8 last_subop_bit = subop & 1;

                  switch ( subop2_3bits )
                  {
                    case 0:
                      {
                        if ( last_subop_bit == 0 )
                        {
                          // MOV.H imm2, vreg2, vreg3
                          // r r r r r 1 1 1 1 1 1 0 0 0 i i w w w w w 1 1 0 1 1 0 1 1 1 0
                          ins->itype = NEC850_MOV_H;
                          set_opimm(&ins->Op1, w & 3, dt_byte);
                        }
                        break;
                      }
                    case 4:
                    case 6:
                      {
                        // DUP.H imm2, vreg2, vreg3
                        // r r r r r 1 1 1 1 1 1 1 0 0 i i w w w w w 1 1 0 1 1 0 1 1 1 0 0
                        //
                        // DUP.W imm1, vreg2, vreg3
                        // r r r r r 1 1 1 1 1 1 1 1 0 0 i w w w w w 1 1 0 1 1 0 1 1 1 1 0
                        ins->itype = last_subop_bit == 0 ? NEC850_DUP_H : NEC850_DUP_W;
                        set_opimm(&ins->Op1, last_subop_bit == 0 ? w & 3 : w & 1, dt_byte);
                        break;
                      }
                    default:
                      break;
                  }

                  if ( ins->itype != NEC850_NULL )
                  {
                    set_opvreg(&ins->Op2, r2, dt_qword);
                    set_opvreg(&ins->Op3, r3, dt_qword);
                    break;
                  }

                  static const int map[] =
                  {
                    NEC850_VITLV_H, NEC850_VITLVHW_H, NEC850_VITLVWH_H,
                    NEC850_VITLV_W, NEC850_VNOT, NEC850_VBSWAP_H,
                    NEC850_VBSWAP_W, NEC850_VBSWAP_DW
                  };

                  if ( subop2 < qnumber(map) )
                    ins->itype = map[subop2];

                  set_opvreg(&ins->Op1, r2, dt_qword);
                  set_opvreg(&ins->Op2, r3, dt_qword);
                  break;
                }
              default:
                {
                  if ( subop >= 3 && subop <= 0xB )
                  {
                    static const uint16 map[] =
                    {
                      NEC850_NULL, NEC850_NULL, NEC850_NULL,
                      NEC850_VSAR_DW, NEC850_VSHR_DW, NEC850_VSHL_DW,
                      NEC850_VSAR_W, NEC850_VSHR_W, NEC850_VSHL_W,
                      NEC850_VSAR_H, NEC850_VSHR_H, NEC850_VSHL_H
                    };

                    if ( subop < qnumber(map) )
                    {
                      ins->itype = map[subop];
                      if ( ins->itype != NEC850_NULL )
                      {
                        set_opreg(&ins->Op1, r1, dt_byte);
                        set_opvreg(&ins->Op2, r2, dt_qword);
                        set_opvreg(&ins->Op3, r3, dt_qword);
                        break;
                      }
                    }
                  }

                  if ( subop >= 0x30 && subop <= 0x3F )
                  {
                    static const vec_lstore_ins_t map[] =
                    {
                      { NEC850_VLD_DW, NEC850_VLD_DW, NEC850_VLD_DW_FMT3, NEC850_VLD_DW_FMT4, NEC850_NULL, false },
                      { NEC850_VST_DW, NEC850_VST_DW, NEC850_VST_DW, NEC850_VST_DW_FMT_4_5, NEC850_VST_DW_FMT_4_5, true },
                      { NEC850_VLD_W, NEC850_VLD_W, NEC850_VLD_W, NEC850_VLD_W_FMT4, NEC850_NULL, false },
                      { NEC850_VST_W, NEC850_VST_W, NEC850_VST_W, NEC850_VST_W_FMT_4_5, NEC850_VST_W_FMT_4_5, true },
                      { NEC850_VLD_H, NEC850_VLD_H, NEC850_VLD_H, NEC850_VLD_H_FMT4, NEC850_NULL, false },
                      {},
                      { NEC850_VLD_B, NEC850_VLD_B, NEC850_VLD_B_FMT3, NEC850_VLD_B_FMT4, NEC850_NULL, false },
                      { NEC850_VST_B, NEC850_VST_B, NEC850_VST_B, NEC850_VST_B_FMT4, NEC850_NULL, true },
                    };

                    uint idx = (subop - 0x30) / 2;
                    if ( idx < qnumber(map) )
                    {
                      auto &entry = map[idx];
                      if ( entry.set )
                      {
                        entry.set_vload_store(ins, w, subop);
                        break;
                      }
                    }
                  }

                  uint disp_subop = (subop >> 1) & 0x1F;
                  if ( disp_subop == 0x10 || disp_subop == 0x11 )
                  {
                    bool is_vst = disp_subop == 0x11;
                    ins->itype = is_vst ? NEC850_VST_DW : NEC850_VLD_DW;

                    uint8 bit17 = subop & 1;
                    uint combined = (r2 | (bit17 << 6)) << 2;

                    op_t *displ_op = is_vst ? &ins->Op2 : &ins->Op1;

                    displ_op->type = o_displ;
                    displ_op->dtype = dt_dword;
                    displ_op->reg = r1;
                    displ_op->addr = combined;
                    displ_op->specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;

                    set_opvreg(is_vst ? &ins->Op1 : &ins->Op2, r3, dt_qword);
                  }
                  break;
                }
          }
          break;
        }
      default:
        break;
    }
  }

  if ( ins->itype != NEC850_NULL )
  {
    ins->auxpref |= N850F_FP;
    return true;
  }
  return false;
}

  //------------------------------------------------------------------------
// Decodes an instruction "w" into cmd structure
bool nec850_t::decode_instruction(const uint32 w, insn_t *ins)
{
#define PARSE_L12 (((w & 1) << 11) | (w >> 21))
#define PARSE_R1  (w & 0x1F)
#define PARSE_R2  ((w & 0xF800) >> 11)

  typedef struct
  {
    int itype;
    int flags;
  } itype_flags_t;
  // If an instruction deals with displacement it should
  // initialize this pointer to the operand location.
  // At the end we will transform the operand to o_mem
  // if we know how to resolve its address
  op_t *displ_op = nullptr;

  do
  {
    uint32 op;

    //
    // Format I
    //
    op = (w & 0x7E0) >> 5; // Take bit5->bit10
    if ( op <= 0xF )
    {
      static const int inst_1[] =
      {
        /* MOV reg1, reg2 */ NEC850_MOV,             /* NOT reg1, reg2 */ NEC850_NOT,
        /* DIVH  reg1, reg2 */ NEC850_DIVH,          /* JMP [reg1] */ NEC850_JMP,
        /* SATSUBR reg1, reg2 */ NEC850_SATSUBR,     /* SATSUB reg1, reg2 */ NEC850_SATSUB,
        /* SATADD reg1, reg2 */ NEC850_SATADD,       /* MULH reg1, reg2 */ NEC850_MULH,
        /* OR reg1, reg2 */ NEC850_OR,               /* XOR reg1, reg2 */ NEC850_XOR,
        /* AND reg1, reg2 */ NEC850_AND,             /* TST reg1, reg2 */ NEC850_TST,
        /* SUBR reg1, reg2 */ NEC850_SUBR,           /* SUB reg1, reg2 */ NEC850_SUB,
        /* ADD reg1, reg2 */ NEC850_ADD,             /* CMP reg1, reg2 */ NEC850_CMP
      };

      //
      // NOP, Equivalent to MOV R, r (where R=r=0)
      if ( w == 0 )
      {
        ins->itype     = NEC850_NOP;
        ins->Op1.type  = o_void;
        ins->Op1.dtype = dt_void;
        break;
      }

      uint16 r1 = PARSE_R1;
      uint16 r2 = PARSE_R2;
      if ( is_v850e() && op == 2 && r1 == 0 )
      {
        switch ( r2 )
        {
          case 0:
            if ( is_v850e2m() )
              ins->itype = NEC850_RIE;
            break;
          case 0x1C:
            if ( is_rh850() )
              ins->itype = NEC850_DBHVTRAP;
            break;
          case 0x1D:
            if ( is_rh850() )
              ins->itype = NEC850_DBCP;
            break;
          case 0x1E:
            if ( is_v850e2m() )
              ins->itype = NEC850_RMTRAP;
            break;
          case 0x1F:
            ins->itype = NEC850_DBTRAP;
            break;
          default:
            if ( is_v850e2() && r2 < 0x10 )
            {
              ins->itype = NEC850_FETRAP;
              set_opimm(&ins->Op1, r2);
            }
            break;
        }
        if ( ins->itype != 0 )
          break;
      }

      ins->itype = inst_1[op];
      set_opreg(&ins->Op1, r1);

      if ( is_v850e() )
      {
        if ( r2 == 0 )
        {
          if ( is_v850e2m() && op == 0 )
          {
            switch ( r1 )
            {
              case 0x1C:
                if ( is_rh850() )
                  ins->itype = NEC850_SYNCI;
                else
                  ins->itype = NEC850_NULL;
                break;
              case 0x1D:
                ins->itype = NEC850_SYNCE;
                break;
              case 0x1E:
                ins->itype = NEC850_SYNCM;
                break;
              case 0x1F:
                ins->itype = NEC850_SYNCP;
                break;
              default:
                ins->itype = NEC850_NULL;
                break;
            }
            if ( ins->itype != NEC850_NULL )
            {
              ins->Op1.type = o_void;
              ins->Op2.type = o_void;
              break;
            }
          }
          else if ( ins->itype == NEC850_DIVH )
          {
            ins->itype = NEC850_SWITCH;
            break;
          }
          else if ( ins->itype == NEC850_SATSUBR )
          {
            ins->itype = NEC850_ZXB;
            break;
          }
          else if ( ins->itype == NEC850_SATSUB )
          {
            ins->itype = NEC850_SXB;
            break;
          }
          else if ( ins->itype == NEC850_SATADD )
          {
            ins->itype = NEC850_ZXH;
            break;
          }
          else if ( ins->itype == NEC850_MULH )
          {
            ins->itype = NEC850_SXH;
            break;
          }
        }
        // case when r2 != 0
        else
        {
          // SLD.BU / SLD.HU
          if ( ins->itype == NEC850_JMP )
          {
            bool   sld_hu = (w >> 4) & 1;
            uint32 addr = w & 0xF;

            if ( sld_hu )
            {
              ins->itype       = NEC850_SLD_HU;
              ins->Op1.dtype   = dt_word;
              addr <<= 1;
            }
            else
            {
              ins->itype       = NEC850_SLD_BU;
              ins->Op1.dtype   = dt_byte;
            }

            ins->Op1.type      = o_displ;
            displ_op           = &ins->Op1;
            ins->Op1.reg       = rEP;
            ins->Op1.addr      = addr;
            ins->Op1.specflag1 = N850F_USEBRACKETS;

            set_opreg(&ins->Op2, r2);

            break;
          }
        }
      }
      if ( ins->itype == NEC850_JMP && r2 == 0 )
      {
        ins->Op1.specflag1 = N850F_USEBRACKETS;
      }
      else
      {
        set_opreg(&ins->Op2, r2);
      }
      break;
    }
    // Format II
    else if ( op <= 0x17 )
    {
      if ( PARSE_R2 == 0 && op == 0x17 && is_v850e2m() )
      {
        // 48-bit Format VI jr/jarl
        // JARL disp32, reg1: 00000010111RRRRR ddddddddddddddd0 DDDDDDDDDDDDDDDD
        // JR  disp32:        0000001011100000 ddddddddddddddd0 DDDDDDDDDDDDDDDD
        uint16 reg = PARSE_R1;
        sval_t addr = fetch_disp32(w, ins);
        if ( (addr & 1) != 0 )
          return false;
        ins->Op1.addr = ins->ip + addr;
        ins->Op1.type = o_near;
        ins->Op1.specflag1 = N850F_VAL32;
        if ( reg == 0 )
        {
          ins->itype = NEC850_JR;
        }
        else
        {
          ins->itype = NEC850_JARL;
          set_opreg(&ins->Op2, reg);
        }
        break;
      }
      // flag used for sign extension
      static const itype_flags_t inst_2[] =
      {
        { NEC850_MOV,    1 }, /* MOV imm5, reg2 */
        { NEC850_SATADD, 1 }, /* SATADD imm5, reg2 */
        { NEC850_ADD,    1 }, /* ADD imm5, reg2 */
        { NEC850_CMP,    1 }, /* CMP imm5, reg2 */
        { NEC850_SHR,    0 }, /* SHR imm5, reg2 */
        { NEC850_SAR,    0 }, /* SAR imm5, reg2 */
        { NEC850_SHL,    0 }, /* SHL imm5, reg2 */
        { NEC850_MULH,   1 }, /* MULH imm5, reg2 */
      };
      op -= 0x10;

      ins->itype = inst_2[op].itype;
      uint16 r2 = PARSE_R2;

      if ( is_v850e() )
      {
        //
        // CALLT
        //
        if ( r2 == 0 && (ins->itype == NEC850_SATADD || ins->itype == NEC850_MOV) )
        {
          ins->itype = NEC850_CALLT;
          set_opimm(&ins->Op1, w & 0x3F, dt_byte);
          if ( g_ctbp_ea != BADADDR )
          {
            // resolve callt addr using ctbp
            ea_t ctp = g_ctbp_ea + (ins->Op1.value << 1);
            ins->Op1.type = o_near;
            ins->Op1.addr = g_ctbp_ea + get_word(ctp);
          }
          break;
        }
      }

      sval_t v = PARSE_R1;
      if ( inst_2[op].flags == 1 )
      {
        SIGN_EXTEND(sval_t, v, 5);
        ins->Op1.specflag1 |= N850F_OUTSIGNED;
      }

      set_opimm(&ins->Op1, v, dt_byte);
      set_opreg(&ins->Op2, r2);

      // ADD imm, reg -> reg = reg + imm
      if ( ins->itype == NEC850_ADD && r2 == rSP )
        ins->auxpref |= N850F_SP;
      break;
    }
    // Format VI
    else if ( op >= 0x30 && op <= 0x37 )
    {
      static const itype_flags_t inst_6[] =
      { // itype         flags (1=signed)
        { NEC850_ADDI,      1 }, /* ADDI imm16, reg1, reg2 */
        { NEC850_MOVEA,     1 }, /* MOVEA imm16, reg1, reg2 */
        { NEC850_MOVHI,     0 }, /* MOVHI imm16, reg1, reg2 */
        { NEC850_SATSUBI,   1 }, /* SATSUBI imm16, reg1, reg2 */
        { NEC850_ORI,       0 }, /* ORI imm16, reg1, reg2 */
        { NEC850_XORI,      0 }, /* XORI imm16, reg1, reg2 */
        { NEC850_ANDI,      0 }, /* ANDI imm16, reg1, reg2 */
        { NEC850_MULHI,     0 }, /* MULHI  imm16, reg1, reg2 */
      };
      op -= 0x30;
      ins->itype = inst_6[op].itype;

      uint16 r1     = PARSE_R1;
      uint16 r2     = PARSE_R2;
      uint32 imm    = w >> 16;

      //
      // V850E instructions
      if ( is_v850e() && r2 == 0 )
      {
        if ( ins->itype == NEC850_MULHI )
        {
          if ( !is_v850e2() )
            return false; // "Do not specify r0 as the destination register reg2."
          if ( ( imm & 1 ) != 0 )
          {
            // RH850: LOOP reg1,disp16
            // 00000110111RRRRR ddddddddddddddd1
            if ( !is_rh850() || r1 == 0 )
              return false; // "Do not specify r0 for reg1."
            ins->itype = NEC850_LOOP;
            set_opreg(&ins->Op1, r1);
            imm ^= 1; // clear bit 0
            sval_t addr = ins->ip - imm;
            ins->Op2.addr = addr;
            ins->Op2.type = o_near;
          }
          else
          {
            // V850E2: jmp disp32 [reg1]
            // 00000110111RRRRR ddddddddddddddd0 DDDDDDDDDDDDDDDD
            sval_t addr = fetch_disp32(w, ins);
            if ( ( addr & 1 ) != 0 )
              return false;
            ins->Op1.addr = addr;
            ins->Op1.type = o_displ;
            ins->Op1.specflag1 = N850F_OUTSIGNED | N850F_VAL32 | N850F_USEBRACKETS;
            ins->Op1.reg = r1;
            ins->itype = NEC850_JMP;
          }
          break;
        }
        // MOV imm32, R
        if ( ins->itype == NEC850_MOVEA )
        {
          imm |= ins->get_next_word() << 16;
          set_opimm(&ins->Op1, imm);
          ins->itype = NEC850_MOV;

          set_opreg(&ins->Op2, r1);
          break;
        }
        // DISPOSE imm5, list12 (reg1 == 0)
        // DISPOSE imm5, list12, [reg1]
        else if ( ins->itype == NEC850_SATSUBI || ins->itype == NEC850_MOVHI )
        {
          r1 = (w >> 16) & 0x1F;
          uint16 L = PARSE_L12;

          ins->auxpref |= N850F_SP; // SP reference

          set_opimm(&ins->Op1, (w & 0x3E) >> 1, dt_byte);

          ins->Op2.value  = L;
          ins->Op2.type   = o_reglist;
          ins->Op2.dtype  = dt_word;

          if ( r1 != 0 )
          {
            set_opreg(&ins->Op3, r1);
            ins->Op3.specflag1 = N850F_USEBRACKETS;

            ins->itype = NEC850_DISPOSE_r;
          }
          else
          {
            ins->itype = NEC850_DISPOSE_r0;
          }
          break;
        }
      }
      bool is_signed = inst_6[op].flags == 1;
      set_opimm(&ins->Op1, is_signed ? sval_t(int16(imm)) : imm);
      ins->Op1.specflag1 |= N850F_OUTSIGNED;

      set_opreg(&ins->Op2, r1);
      set_opreg(&ins->Op3, r2);

      // (ADDI|MOVEA) imm, sp, sp -> sp = sp + imm
      if ( (ins->itype == NEC850_ADDI || ins->itype == NEC850_MOVEA)
        && ((r1 == rSP) && (r2 == rSP)) )
      {
        ins->auxpref |= N850F_SP;
      }
      break;
    }
    // Format VII - LD.x
    else if ( op == 0x38 || op == 0x39 )
    {
      displ_op        = &ins->Op1;
      ins->Op1.type   = o_displ;
      ins->Op1.phrase = PARSE_R1; // R

      set_opreg(&ins->Op2, PARSE_R2);

      uint32 addr;
      // LD.B
      if ( op == 0x38 )
      {
        addr           = w >> 16;
        ins->itype     = NEC850_LD_B;
        ins->Op1.dtype = dt_byte;
      }
      else
      {
        // Bit16 is cleared for LD.H
        if ( (w & (1 << 16)) == 0 )
        {
          ins->itype      = NEC850_LD_H;
          ins->Op1.dtype  = dt_word;
        }
        // LD.W
        else
        {
          ins->itype      = NEC850_LD_W;
          ins->Op1.dtype  = dt_dword;
        }
        addr = ((w & 0xFFFE0000) >> 17) << 1;
      }
      ins->Op1.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      ins->Op1.addr = int16(addr);

      break;
    }
    // Format VII - ST.x
    else if ( op == 0x3A || op == 0x3B )
    {
      // (1) ST.B  reg2, disp16 [reg1]
      // (2) ST.H  reg2, disp16 [reg1]
      // (3) ST.W  reg2, disp16 [reg1]
      set_opreg(&ins->Op1, PARSE_R2);

      ins->Op2.type      = o_displ;
      displ_op           = &ins->Op2;
      ins->Op2.reg       = PARSE_R1;
      ins->Op2.specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      // ST.B
      uint32 addr;
      if ( op == 0x3A )
      {
        addr           = w >> 16;
        ins->itype     = NEC850_ST_B;
        ins->Op2.dtype = dt_byte;
      }
      else
      {
        // Bit16 is cleared for ST.H
        if ( (w & (1 << 16)) == 0 )
        {
          ins->itype      = NEC850_ST_H;
          ins->Op2.dtype  = dt_word;
        }
        else
        {
          ins->itype      = NEC850_ST_W;
          ins->Op2.dtype  = dt_dword;
        }
        addr = ((w & 0xFFFE0000) >> 17) << 1;
      }
      ins->Op2.addr = int16(addr);
      break;
    }
    // Format XIII - PREPARE / LD.BU
    else if ( is_v850e()
           && ((w >> 16) & 0x1) // this bit is important to differentiate between JARL/JR instructions
           && (op == 0x3C || op == 0x3D) )
    {
      uint16 r2 = PARSE_R2;

      uint16 subop = (w >> 16) & 0x1F;
      // PREPARE
      if ( r2 == 0 && (subop == 1 || (subop & 7) == 3) )
      {
        ins->auxpref   |= N850F_SP;
        ins->Op1.value  = PARSE_L12;
        ins->Op1.type   = o_reglist;
        ins->Op1.dtype  = dt_word;

        set_opimm(&ins->Op2, (w & 0x3E) >> 1, dt_byte);

        if ( subop == 1 )
        {
          ins->itype = NEC850_PREPARE_i;
        }
        else
        {
          ins->itype = NEC850_PREPARE_sp;
          uint16 ff = subop >> 3;
          switch ( ff )
          {
            case 0:
              // disassembles as: PREPARE list12, imm5, sp
              // meaning: load sp into ep
              set_opreg(&ins->Op3, rSP);
              break;
              // the other cases disassemble with imm (the 3rd operand) directly processed:
              // f=1->ep=sign_extend(imm16), f=2->ep=imm16 shl 16, f=3->ep=imm32
            case 1:
              //  c:   a8 07 0b 80     prepare {r24}, 20, 0x1
              // 10:   01 00
              set_opimm(&ins->Op3, sval_t(int16(ins->get_next_word())));
              break;
            case 2:
              // 2:   a8 07 13 80     prepare {r24}, 20, 0x10000
              // 6:   01 00
              set_opimm(&ins->Op3, ins->get_next_word() << 16);
              break;
            case 3:
              // 2:   a8 07 1b 80     prepare {r24}, 20, 0x1
              // 6:   01 00 00 00
              set_opimm(&ins->Op3, ins->get_next_dword());
              break;
          }
        }
      }
      else if ( r2 == 0 && is_v850e2m() )
      {
        // disp23 variants (Format XIV)
        // LD.BU disp23 [reg1] , reg3
        // 00000111101RRRRR wwwwwddddddd0101 DDDDDDDDDDDDDDDD
        // LD.HU disp23 [reg1] , reg3
        // 00000111101RRRRR wwwwwdddddd00111 DDDDDDDDDDDDDDDD
        // ST.H reg3, disp23 [reg1]
        // 00000111101RRRRR wwwwwdddddd01101 DDDDDDDDDDDDDDDD
        // ST.H reg3, disp23 [reg1]
        // 00000111101RRRRR wwwwwdddddd01101 DDDDDDDDDDDDDDDD
        // LD.B disp23 [reg1] , reg3
        // 00000111100RRRRR wwwwwddddddd0101 DDDDDDDDDDDDDDDD
        // LD.H disp23 [reg1] , reg3
        // 00000111100RRRRR wwwwwdddddd00111 DDDDDDDDDDDDDDDD
        // LD.W disp23 [reg1] , reg3
        // 00000111100RRRRR wwwwwdddddd01001 DDDDDDDDDDDDDDDD
        // LD.DW disp23[reg1], reg3
        // 00000111101RRRRR wwwwwdddddd01001 DDDDDDDDDDDDDDDD
        // ST.B reg3, disp23 [reg1]
        // 00000111100RRRRR wwwwwddddddd1101 DDDDDDDDDDDDDDDD
        // ST.W reg3, disp23 [reg1]
        // 00000111100RRRRR wwwwwdddddd01111 DDDDDDDDDDDDDDDD
        // ST.DW reg3, disp23[reg1]
        // 00000111101RRRRR wwwwwdddddd01111 DDDDDDDDDDDDDDDD
        // RRRRR = reg1, wwwww = reg3.
        // ddddddd is the lower 7 bits of disp23.
        // DDDDDDDDDDDDDDDD is the higher 16 bits of disp23.
        bool success = false;
        subop = ( w >> 16 ) & 0xF;
        bool sign = ( op & 1 ) == 0;
        uint32 r3 = ( w & 0xF8000000 ) >> 27;
        switch ( subop )
        {
          case 5:
            if ( decode_disp23(w, ins, 0, dt_byte) )
            {
              ins->itype = sign ? NEC850_LD_B : NEC850_LD_BU;
              set_opreg(&ins->Op2, r3);
              success = true;
            }
            break;
          case 7:
            if ( decode_disp23(w, ins, 0, dt_word) )
            {
              ins->itype = sign ? NEC850_LD_H : NEC850_LD_HU;
              set_opreg(&ins->Op2, r3);
              success = true;
            }
            break;
          case 9:
            if ( (is_rh850() || sign) && decode_disp23(w, ins, 0, dt_dword) )
            {
              ins->itype = sign ? NEC850_LD_W : NEC850_LD_DW;
              set_opreg(&ins->Op2, r3);
              success = true;
            }
            break;
          case 13:
            if ( decode_disp23(w, ins, 1, sign ? dt_byte : dt_word) )
            {
              ins->itype = sign ? NEC850_ST_B : NEC850_ST_H;
              set_opreg(&ins->Op1, r3);
              success = true;
            }
            break;
          case 15:
            if ( (is_rh850() || sign) && decode_disp23(w, ins, 1, dt_dword) )
            {
              ins->itype = sign ? NEC850_ST_W : NEC850_ST_DW;
              set_opreg(&ins->Op1, r3);
              success = true;
            }
            break;
        }

        if ( !success )
          return decode_ext_simd(w, ins);
      }
      else
      {
        // LD.BU disp16 [reg1] , reg2
        // rrrrr11110bRRRRR ddddddddddddddd1
        // ddddddddddddddd is the higher 15 bits of disp16, and b is bit 0 of disp16.
        // rrrrr != 00000 ( Do not specify r0 for reg2. )
        if ( r2 == 0 )
          return false;
        uint16 r1 = PARSE_R1;

        ins->itype = NEC850_LD_BU;

        ins->Op1.type       = o_displ;
        displ_op            = &ins->Op1;
        displ_op->reg       = r1;
        displ_op->addr      = int16(((w >> 16) & ~1) | ((w & 0x20) >> 5));
        displ_op->dtype     = dt_byte;
        displ_op->specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;

        set_opreg(&ins->Op2, r2);
      }
      break;
    }
    // Format VIII
    else if ( op == 0x3E )
    {
      // parse sub-opcode (b15..b14)
      op = ((w & 0xC000) >> 14);
      static const int inst_8[] =
      {
        NEC850_SET1, NEC850_NOT1,
        NEC850_CLR1, NEC850_TST1
      };
      ins->itype = inst_8[op];
      set_opimm(&ins->Op1, ((w & 0x3800) >> 11), dt_byte);


      ins->Op2.type       = o_displ;
      displ_op            = &ins->Op2;
      displ_op->addr      = int16(w >> 16);
      displ_op->offb      = 2;
      displ_op->dtype     = dt_byte;
      displ_op->reg       = PARSE_R1; // R
      displ_op->specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
      break;
    }
    //
    // Format IX, X
    //
    else if ( op == 0x3F )
    {
      if ( (w & ( 1 << 16 )) == 0 && ( w & ( 1 << 26 ) ) != 0 )
        // coprocessor insn
        return decode_coprocessor(w, ins);
      //
      // Format X
      //

      // Const opcodes
      if ( w == 0x16087E0 ) // EI
        ins->itype = NEC850_EI;
      else if ( w == 0x16007E0 ) // DI
        ins->itype = NEC850_DI;
      else if ( w == 0x14007E0 ) // RETI
        ins->itype = NEC850_RETI;
      else if ( w == 0x12007E0 ) // HALT
        ins->itype = NEC850_HALT;
      else if ( w == 0xffffffff )
        ins->itype = NEC850_BREAKPOINT;
      else if ( (w >> 5) == 0x8003F ) //lint !e587 predicate always false // TRAP
      {
        ins->itype = NEC850_TRAP;
        set_opimm(&ins->Op1, PARSE_R1, dt_byte);
        break;
      }
      if ( ins->itype != 0 )
        break;
      if ( is_v850e1f() && !is_v850e2m() )
      {
        // E1F opcodes (ref. U16374EJ1V0UM)
        int subop = ( w >> 16 ) & 0x7FF;
        int r3 = ( w & 0xF8000000 ) >> 27;
        switch ( subop )
        {
// Format F:I reg1, reg2, reg3
          case 0x3E0:
            ins->itype = NEC850_DIVF_S;
            goto OPS_FI;
          case 0x3E4:
            ins->itype = NEC850_SUBF_S;
            goto OPS_FI;
          case 0x3E8:
            ins->itype = NEC850_ADDF_S;
            goto OPS_FI;
          case 0x3EC:
            ins->itype = NEC850_MULF_S;
            goto OPS_FI;
          case 0x3F0:
            ins->itype = NEC850_MINF_S;
            goto OPS_FI;
          case 0x3F4:
            ins->itype = NEC850_MAXF_S;
OPS_FI:
            set_opreg(&ins->Op1, PARSE_R1);
            set_opreg(&ins->Op2, PARSE_R2);
            set_opreg(&ins->Op3, r3);
            break;
// Format F:II reg2, reg3
          case 0x360:
            ins->itype = NEC850_CVT_SW;
OPS_FII:
            set_opreg(&ins->Op1, PARSE_R2);
            set_opreg(&ins->Op2, r3);
            break;
          case 0x368:
            ins->itype = NEC850_TRNC_SW;
            goto OPS_FII;
          case 0x370:
            ins->itype = NEC850_CVT_WS;
            goto OPS_FII;
          case 0x3F8:
            ins->itype = NEC850_NEGF_S;
            goto OPS_FII;
          case 0x3FC:
            ins->itype = NEC850_ABSF_S;
            goto OPS_FII;

// Format F:IV reg2 or reg3
          case 0x378:
            if ( r3 != 0 )
            {
              // STFF EFG,reg2
              ins->itype = NEC850_STFF;
              set_opreg(&ins->Op1, EFG);
              set_opreg(&ins->Op2, r3);
            }
            else
            {
              ins->itype = NEC850_TRFF;
              // no operands
            }
            break;
          case 0x37C:
            // STFC ECT,reg2
            ins->itype = NEC850_STFC;
            set_opreg(&ins->Op1, ECT);
            set_opreg(&ins->Op2, r3);
            break;

          case 0x37A:
            if ( r3 == 0 )
            {
              // LDFF reg2,EFG
              ins->itype = NEC850_LDFF;
              set_opreg(&ins->Op1, PARSE_R2);
              set_opreg(&ins->Op2, EFG);
            }
            break;

          case 0x37E:
            if ( r3 == 0 )
            {
              // LDFC reg2,ECT
              ins->itype = NEC850_LDFC;
              set_opreg(&ins->Op1, PARSE_R2);
              set_opreg(&ins->Op2, ECT);
            }
            break;

        }
        if ( ins->itype != 0 )
          break;
      }
      // Still in format 10 (op = 0x3F)
      if ( is_v850e() )
      {
        if ( is_v850e2m() )
        {
          if ( w == 0x14807E0 )
            ins->itype = NEC850_EIRET;
          else if ( w == 0x14a07E0 )
            ins->itype = NEC850_FERET;
          else if ( ( w & 0xc7ffffe0 ) == 0x0160d7e0 )
          {
            ins->itype = NEC850_SYSCALL;
            int v8 = (w & 0x1f) | ((w >> (27 - 5)) & 0xe0);
            set_opimm(&ins->Op1, v8);
          }
          else if ( is_rh850() )
          {
            int subop = ( w >> 16 ) & 0x7FF;
            switch ( subop )
            {
              case 0x8:
                ins->itype = NEC850_CLIP_B;
                set_opreg(&ins->Op1, PARSE_R1, dt_byte);
                set_opreg(&ins->Op2, PARSE_R2, dt_word);
                break;
              case 0xA:
                ins->itype = NEC850_CLIP_BU;
                set_opreg(&ins->Op1, PARSE_R1, dt_byte);
                set_opreg(&ins->Op2, PARSE_R2, dt_word);
                break;
              case 0xC:
                ins->itype = NEC850_CLIP_H;
                set_opreg(&ins->Op1, PARSE_R1, dt_dword);
                set_opreg(&ins->Op2, PARSE_R2, dt_word);
                break;
              case 0xE:
                ins->itype = NEC850_CLIP_HU;
                set_opreg(&ins->Op1, PARSE_R1, dt_dword);
                set_opreg(&ins->Op2, PARSE_R2, dt_word);
                break;
              case 0x20:
              case 0x40:
                {
                  // LDSR reg2, regID, selID
                  // rrrrr111111RRRRR sssss00000100000
                  // rrrrr: regID, sssss: selID, RRRRR: reg2
                  // STSR regID, reg2, selID
                  // rrrrr111111RRRRR sssss00001000000
                  // rrrrr: regID, sssss: selID, RRRRR: reg2
                  bool is_ld = subop == 0x20;
                  ins->itype = is_ld ? NEC850_LDSR : NEC850_STSR;
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  uint32 regid = PARSE_R1;
                  uint32 r2 = PARSE_R2;
                  if ( is_ld )
                  {
                    // In this instruction, general-purpose register reg2 is used as the source register, but, for
                    // mnemonic description convenience, the general - purpose register reg1 field is used in the
                    // opcode.The meanings of the register specifications in the mnemonic descriptions and
                    // opcode therefore differ from those of other instructions.
                    set_opreg(&ins->Op1, regid);
                    set_opreg(&ins->Op2, r2 + rSR0);
                  }
                  else
                  {
                    set_opreg(&ins->Op1, regid + rSR0);
                    set_opreg(&ins->Op2, r2);
                  }
                  if ( selid != 0 )
                    set_opimm(&ins->Op3, selid);
                }
                break;

              case 0x30:
              case 0x50:
                {
                  bool is_ld = subop == 0x30;
                  if ( is_ld )
                  {
                    ins->itype = NEC850_LDTC_SR;
                    set_opreg(&ins->Op1, PARSE_R1);
                    set_opimm(&ins->Op2, PARSE_R2);
                  }
                  else
                  {
                    ins->itype = NEC850_STTC_SR;
                    set_opimm(&ins->Op1, PARSE_R1);
                    set_opreg(&ins->Op2, PARSE_R2);
                  }
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  set_opimm(&ins->Op3, selid);
                }
                break;

              case 0x32:
              case 0x52:
                {
                  bool is_ld = subop == 0x32;
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  switch ( selid )
                  {
                    case 0:
                      ins->itype = is_ld ? NEC850_LDTC_GR: NEC850_STTC_GR;
                      set_opreg(&ins->Op2, PARSE_R2);
                      set_opreg(&ins->Op1, PARSE_R1);
                      break;
                    case 1:
                      ins->itype = is_ld ? NEC850_LDTC_VR : NEC850_STTC_VR;
                      set_opreg(&ins->Op1, is_ld ? PARSE_R2 : PARSE_R1);
                      set_opreg(&ins->Op2, is_ld ? PARSE_R1 : PARSE_R2);
                      break;
                    case 31:
                      ins->itype = is_ld ? NEC850_LDTC_PC : NEC850_STTC_PC;
                      set_opreg(&ins->Op1, is_ld ? PARSE_R1 : PARSE_R2);
                      break;
                    default:
                      break;
                  }
                }
                break;

              case 0x34:
              case 0x54:
                {
                  bool is_ld = subop == 0x34;
                  if ( is_ld )
                  {
                    ins->itype = NEC850_LDVC_SR;
                    set_opreg(&ins->Op1, PARSE_R1);
                    set_opimm(&ins->Op2, PARSE_R2);
                  }
                  else
                  {
                    ins->itype = NEC850_STVC_SR;
                    set_opimm(&ins->Op1, PARSE_R1);
                    set_opreg(&ins->Op2, PARSE_R2);

                  }
                  uint32 selid = ( w & 0xF8000000 ) >> 27;
                  set_opimm(&ins->Op3, selid);
                }
                break;

              case 0xC4:
              case 0xC6:
                {
                  // ROTL imm5, reg2, reg3
                  // rrrrr111111iiiii wwwww00011000100
                  // ROTL reg1, reg2, reg3
                  // rrrrr111111RRRRR wwwww00011000110
                  ins->itype = NEC850_ROTL;
                  uint32 r1 = PARSE_R1;
                  uint32 r2 = PARSE_R2;
                  uint32 r3 = (w & 0xF8000000) >> 27;
                  if ( subop == 0xC4 )
                  {
                    set_opimm(&ins->Op1, r1);
                  }
                  else
                  {
                    set_opreg(&ins->Op1, r1);
                  }
                  set_opreg(&ins->Op2, r2);
                  set_opreg(&ins->Op3, r3);
                }
                break;

              case 0x110:
                ins->itype = NEC850_HVTRAP;
                set_opimm(&ins->Op1, PARSE_R1, dt_byte);
                break;

              case 0x132:
                ins->itype = NEC850_EST;
                break;

              case 0x134:
                ins->itype = NEC850_DST;
                break;
              case 0x164:
                {
                  // stm.mp:
                  // STM.MP eh-et, [reg1]
                  //
                  // rrrrr111111RRRRR wwwww00101100100
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  ins->itype = NEC850_STM_MP;
                  ins->Op1.type = o_regrange;
                  ins->Op1.regrange_high = PARSE_R2;
                  ins->Op1.regrange_low = r3;
                  ins->Op1.dtype = dt_word;

                  ins->Op2.specflag1 = N850F_USEBRACKETS;
                  set_opreg(&ins->Op2, PARSE_R1, dt_word);
                  break;
                }
              case 0x166:
                {
                  // ldm.mp:
                  // LDM.MP [reg1], eh-et
                  //
                  // rrrrr111111RRRRR wwwww00101100110
                  uint32 r3 = (w & 0xF8000000) >> 27;
                  ins->itype = NEC850_LDM_MP;

                  ins->Op1.specflag1 = N850F_USEBRACKETS;
                  set_opreg(&ins->Op1, PARSE_R1, dt_word);

                  ins->Op2.type = o_regrange;
                  ins->Op2.regrange_high = PARSE_R2;
                  ins->Op2.regrange_low = r3;
                  ins->Op2.dtype = dt_word;
                  break;
                }
              case 0x370:
                {
                  uint32 r2 = PARSE_R2;
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  set_opreg(&ins->Op1, PARSE_R1, dt_byte);
                  ins->Op1.specflag1 = N850F_USEBRACKETS;

                  if ( r2 != 1 )
                  {
                    // ld.bu:
                    // (3) LD.BU [reg1]+, reg3
                    // (4) LD.BU [reg1]-, reg3
                    //
                    // (3) 00011111111RRRRR wwwww01101110000
                    // (4) 00101111111RRRRR wwwww01101110000
                    ins->itype = NEC850_LD_BU;

                    switch ( r2 )
                    {
                      case 0x3:
                        ins->Op1.specflag1 |= N850F_POST_INCREMENT;
                        break;
                      case 0x5:
                        ins->Op1.specflag1 |= N850F_POST_DECREMENT;
                        break;
                      default:
                        break;
                    }
                    set_opreg(&ins->Op2, r3, dt_byte);
                  }
                  else
                  {
                    // LDL.BU [reg1], reg3
                    // 00001111111RRRRR wwwww01101110000
                    ins->itype = NEC850_LDL_BU;
                  }

                  set_opreg(&ins->Op2, r3, dt_byte);
                  break;
                }
              case 0x372:
                {
                  // st.b
                  // (3) ST.B reg3, [reg1]+
                  // (4) ST.B reg3, [reg1]-
                  //
                  // (3) 00010111111RRRRR wwwww01101110010
                  // (4) 00100111111RRRRR wwwww01101110010

                  uint32 r2 = PARSE_R2;
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  // stc.b
                  // 00000111111RRRRR wwwww01101110010
                  if ( r2 == 0 )
                  {
                    ins->itype = NEC850_STC_B;

                    set_opreg(&ins->Op1, r3, dt_byte);

                    ins->Op2.specflag1 = N850F_USEBRACKETS;
                    set_opreg(&ins->Op2, PARSE_R1, dt_byte);
                  }
                  else
                  {
                    ins->itype = NEC850_ST_B;
                    set_opreg(&ins->Op1, r3, dt_byte);

                    ins->Op2.specflag1 = N850F_USEBRACKETS;
                    switch ( r2 )
                    {
                      case 0x2:
                        ins->Op2.specflag1 |= N850F_POST_INCREMENT;
                        break;
                      case 0x4:
                        ins->Op2.specflag1 |= N850F_POST_DECREMENT;
                        break;
                      default:
                        break;
                    }

                    set_opreg(&ins->Op2, PARSE_R1, dt_byte);
                  }

                  break;
                }
              case 0x374:
                {
                  // LDL.HU [reg1], reg3
                  // 00001111111RRRRR wwwww01101110100
                  ins->itype = NEC850_LDL_HU;
                  uint32 r3 = (w & 0xF8000000) >> 27;

                  set_opreg(&ins->Op1, PARSE_R1, dt_byte);
                  ins->Op1.specflag1 = N850F_USEBRACKETS;

                  set_opreg(&ins->Op2, r3, dt_word);
                  break;
                }
              case 0x376:
                {
                  // stc.h
                  // 00000111111RRRRR wwwww01101110110
                  ins->itype = NEC850_STC_H;

                  uint32 r3 = (w & 0xF8000000) >> 27;
                  set_opreg(&ins->Op1, r3, dt_word);

                  ins->Op2.specflag1 = N850F_USEBRACKETS;
                  set_opreg(&ins->Op2, PARSE_R1, dt_word);
                  break;
                }
              case 0x378:
                {
                  // LDL.W [reg1], reg3
                  // 00000111111RRRRR wwwww01101111000
                  ins->itype = NEC850_LDL_W;
                  uint32 r3 = ( w & 0xF8000000 ) >> 27;
                  set_opreg(&ins->Op1, PARSE_R1);
                  ins->Op1.specflag1 = N850F_USEBRACKETS;
                  set_opreg(&ins->Op2, r3);
                  break;
                }

              case 0x37A:
                {
                  // STC.W reg3, [reg1]
                  // 00000111111RRRRR wwwww01101111010
                  ins->itype = NEC850_STC_W;
                  uint32 r3 = ( w & 0xF8000000 ) >> 27;
                  set_opreg(&ins->Op1, r3);
                  set_opreg(&ins->Op2, PARSE_R1);
                  ins->Op2.specflag1 = N850F_USEBRACKETS;
                  break;
                }
              case 0x160:
                {
                  uint32 r1 = PARSE_R1;
                  uint32 r2 = PARSE_R2;
                  uint32 r3 = ( w & 0xF8000000 ) >> 27;
                  int w1 = w >> 16;
                  switch ( r2 )
                  {
                    case 0:
                      if ( w1 == 0x8160 )
                        ins->itype = NEC850_RESBANK;
                      break;
                    case 8:   // pushsp
                    case 0xB: // dbpush
                    case 0xC: // popsp
                      {
                        // PUSHSP rh-rt
                        // 01000111111RRRRR wwwww00101100000
                        // POPSP rh-rt
                        // 01100111111RRRRR wwwww00101100000
                        // RRRRR indicates rh. wwwww indicates rt.
                        ins->itype = r2 == 8 ? NEC850_PUSHSP
                          : r2 == 0xB ? NEC850_DBPUSH
                          : NEC850_POPSP;
                        ins->Op1.type = o_regrange;
                        ins->Op1.regrange_high = r1;
                        ins->Op1.regrange_low = r3;
                      }
                      break;
                    case 0x10:
                      switch ( w1 )
                      {
                        case 0x8960:
                          ins->itype = NEC850_TLBAI;
                          break;
                        case 0x8160:
                          ins->itype = NEC850_TLBVI;
                          break;
                        case 0xC160:
                          ins->itype = NEC850_TLBS;
                          break;
                        case 0xE960:
                          ins->itype = NEC850_TLBR;
                          break;
                        case 0xE160:
                          ins->itype = NEC850_TLBW;
                          break;
                      }
                      break;

                    case 0x18:
                      {
                        // JARL [reg1], reg3
                        // 11000111111RRRRR WWWWW00101100000
                        set_opreg(&ins->Op1, r1);
                        ins->Op1.specflag1 = N850F_USEBRACKETS;
                        set_opreg(&ins->Op2, r3);
                        ins->itype = NEC850_JARL;
                      }
                      break;

                    case 0x19:
                      {
                        ins->itype = NEC850_DBTAG;
                        int v8 = (w & 0x1f) | ((w1 >> 6) & 0xe0);
                        set_opimm(&ins->Op1, v8);
                      }
                      break;

                    case 0x1A:
                      {
                        ins->itype = NEC850_HVCALL;
                        int v8 = (w & 0x1f) | ((w1 >> 6) & 0xe0);
                        set_opimm(&ins->Op1, v8);
                      }
                      break;

                    case 0x1B:
                      {
                        // PREF prefop, [reg1]
                        // 11011111111RRRRR PPPPP00101100000
                        // PPPPP indicates prefop
                        ins->itype = NEC850_PREF;
                        set_opimm(&ins->Op1, r3);
                        set_opreg(&ins->Op2, r1);
                      }
                      break;

                    case 0x1Cu:
                    case 0x1Du:
                    case 0x1Eu:
                    case 0x1Fu:
                      {
                        // CACHE cacheop, [reg1]
                        // 111pp111111RRRRR PPPPP00101100000
                        // ppPPPPP indicates cacheop

                        int cacheop = ( ( r2 & 3 ) << 5 ) | r3;
                        if ( r1 == 0x1f && cacheop == 0x7E )
                        {
                          ins->itype = NEC850_CLL;
                        }
                        else
                        {
                          ins->itype = NEC850_CACHE;
                          set_opimm(&ins->Op1, cacheop);
                          set_opreg(&ins->Op2, r1);
                        }
                      }
                      break;
                  }
                }
                break;
              default:
                if ( w == 0x1200FE0 )
                  ins->itype = NEC850_SNOOZE;
                else if ( (w&0x10000) == 0 )
                {
                  uint o0 = ( w >> 20 ) & 0x7F;
                  if ( o0 == 9 || o0 == 11 || o0 == 13 )
                  {
                    // BINS reg1, pos, width, reg2

                    // rrrrr111111RRRRR MMMMK 0001001 LLL0 msb >= 16, lsb >= 16
                    // rrrrr111111RRRRR MMMMK 0001011 LLL0 msb >= 16, lsb < 16
                    // rrrrr111111RRRRR MMMMK 0001101 LLL0 msb < 16, lsb < 16
                    // Most significant bit of field to be updated : msb = pos + width - 1
                    // Least significant bit of field to be updated : lsb = pos
                    // MMMM = lower 4 bits of msb, KLLL = lower 4 bits of lsb
                    uint16 whi = w >> 16;
                    uint lsb = ( whi >> 1 ) & 7;
                    lsb |= ( whi >> 8 ) & 8;
                    uint msb = ( whi >> 12 ) & 0xF;
                    if ( o0 == 9 || o0 == 11 )
                      msb += 16;
                    if ( o0 == 9 )
                      lsb += 16;
                    uint width = msb - lsb + 1;

                    ins->itype = NEC850_BINS;
                    set_opreg(&ins->Op1, PARSE_R1);
                    set_opimm(&ins->Op2, lsb);
                    set_opimm(&ins->Op3, width);
                    set_opreg(&ins->Op4, PARSE_R2);
                  }
                }
                break;

            }
            if ( ins->itype != 0 )
              break;
          }

          if ( ins->itype != 0 )
            break;
        }
        if ( w == 0x14607E0 )
        {
          ins->itype = NEC850_DBRET;
          break;
        }
        else if ( w == 0x14407E0 )
        {
          ins->itype = NEC850_CTRET;
          break;
        }
        else if ( (w >> 16) & 0x1 )
        {
          int r2 = PARSE_R2;
          int r1 = PARSE_R1;
          if ( r2 != 0 )
          {
            // V850E: LD.HU disp16 [reg1], reg2
            // rrrrr111111RRRRR ddddddddddddddd1
            ins->itype = NEC850_LD_HU;
            ins->Op1.type = o_displ;
            displ_op = &ins->Op1;
            displ_op->reg = r1;
            displ_op->addr = uint32(( w >> 17 ) << 1);
            displ_op->dtype = dt_word;
            displ_op->specflag1 = N850F_USEBRACKETS | N850F_OUTSIGNED;
            set_opreg(&ins->Op2, r2);
          }
          else if ( is_rh850() )
          {
            // RH850: Bcond disp17
            // 00000111111DCCCC ddddddddddddddd1
            sval_t dest = uint32(( w >> 17 ) << 1);
            if ( (w & 0x10) != 0 )
              dest += 0x10000; // D
            SIGN_EXTEND(sval_t, dest, 17);
            ins->itype = bcond_map[w & 0xF];
            ins->Op1.dtype = dt_word;
            ins->Op1.type = o_near;
            ins->Op1.addr = ea_t(dest + ins->ip);
          }
          break;
        }
        //
        // XI Group match (reg1, reg2, reg3)
        //
        uint32 r1 = PARSE_R1;
        uint32 r2 = PARSE_R2;
        uint32 r3 = ( w & 0xF8000000 ) >> 27;

        op = (w & 0x7FF0000) >> 16;
        if ( op == 0x220 )
          ins->itype = NEC850_MUL;
        else if ( op == 0x222 )
          ins->itype = NEC850_MULU;
        else if ( op == 0x280 )
          ins->itype = NEC850_DIVH_r3;
        else if ( op == 0x282 )
          ins->itype = NEC850_DIVHU;
        else if ( op == 0x2C0 )
          ins->itype = NEC850_DIV;
        else if ( op == 0x2C2 )
          ins->itype = NEC850_DIVU;
        else if ( is_v850e2() )
        {
          if ( ( op & 1 ) == 0 )
          {
            if ( ( op >> 5 ) == 0x1D )
            {
              // ADF
              int cc = ( op >> 1 ) & 0xF;
              if ( cc == CC_SAT )
              {
                ins->itype = NEC850_SATADD;
              }
              else
              {
                ins->itype = NEC850_ADF;
                set_opcond(&ins->Op1, cc);
                set_opreg(&ins->Op2, r1);
                set_opreg(&ins->Op3, r2);
                set_opreg(&ins->Op4, r3);
                break;
              }
            }
            else if ( ( op >> 5 ) == 0x1C )
            {
              // SBF
              int cc = ( op >> 1 ) & 0xF;
              if ( cc == CC_SAT )
              {
                ins->itype = NEC850_SATSUB;
              }
              else
              {
                ins->itype = NEC850_SBF;
                set_opcond(&ins->Op1, cc);
                set_opreg(&ins->Op2, r1);
                set_opreg(&ins->Op3, r2);
                set_opreg(&ins->Op4, r3);
                break;
              }
            }
            else if ( ( op >> 6 ) == 0xF )
            {
              // MAC  rrrrr111111RRRRR wwww0011110mmmm0
              // MACU rrrrr111111RRRRR wwww0011111mmmm0
              ins->itype = ( op & 0x20 ) ? NEC850_MACU : NEC850_MAC;
              int r4 = op & 0x1F;
              set_opreg(&ins->Op1, r1);
              set_opreg(&ins->Op2, r2);
              set_opreg(&ins->Op3, r3);
              set_opreg(&ins->Op4, r4);
              break;
            }
          }
          switch ( op )
          {
            case 0x82:
              ins->itype = NEC850_SHR;
              break;
            case 0xa2:
              ins->itype = NEC850_SAR;
              break;
            case 0xc2:
              ins->itype = NEC850_SHL;
              break;
            case 0xEE:
              ins->itype = NEC850_CAXI;
              ins->Op1.specflag1 |= N850F_USEBRACKETS;
              break;
            case 0x2FE:
              ins->itype = NEC850_DIVQU;
              break;
            case 0x2FC:
              ins->itype = NEC850_DIVQ;
              break;
          }
        }
        // process the match
        if ( ins->itype != 0 )
        {
          set_opreg(&ins->Op1, r1);
          set_opreg(&ins->Op2, r2);
          set_opreg(&ins->Op3, r3);
          break;
        }

        //
        // XII/IX Group match (reg2, reg3)
        //
        if ( op == 0x340 )
          ins->itype = NEC850_BSW;
        else if ( op == 0x342 )
          ins->itype = NEC850_BSH;
        else if ( op == 0x344 )
          ins->itype = NEC850_HSW;
        else if ( is_v850e2() )
        {
          switch ( op )
          {
            case 0x346:
              ins->itype = NEC850_HSH;
              break;
            case 0x360:
              ins->itype = NEC850_SCH0R;
              break;
            case 0x362:
              ins->itype = NEC850_SCH1R;
              break;
            case 0x364:
              ins->itype = NEC850_SCH0L;
              break;
            case 0x366:
              ins->itype = NEC850_SCH1L;
              break;
          }
        }
            // process the match
        if ( ins->itype != 0 )
        {
          set_opreg(&ins->Op1, r2);
          set_opreg(&ins->Op2, r3);
          break;
        }

        //
        // match CMOV
        //
        op = w >> 16;
        op = ((op & 0x7E0) >> 4) | (op & 0x1);
        if ( op == 0x30 || op == 0x32 )
        {
          uint32 cc = (w & 0x1E0000) >> 17;
          ins->itype = NEC850_CMOV;
          set_opcond(&ins->Op1, cc);

          r1 = PARSE_R1;
          r2 = PARSE_R2;
          r3 = (w & 0xF8000000) >> 27;

          if ( op == 0x32 ) // CMOV cc, reg1, reg2, reg3
          {
            set_opreg(&ins->Op2, r1);
          }
          else
          {
            // CMOV cc, imm5, reg2, reg3
            sval_t v = r1;
            SIGN_EXTEND(sval_t, v, 5);
            set_opimm(&ins->Op2, v, dt_byte);
            ins->Op2.specflag1 |= N850F_OUTSIGNED;
          }
          set_opreg(&ins->Op3, r2);
          set_opreg(&ins->Op4, r3);
          break;
        }
        //
        // match MUL[U]_i9
        //
        op = w >> 16;
        op = ((op & 0x7C0) >> 4) | (op & 0x3);
        if ( op == 0x24 || op == 0x26 )
        {
          sval_t imm = (((w & 0x3C0000) >> 18) << 5) | (w & 0x1F);
          if ( op == 0x24 )
          {
            ins->itype = NEC850_MUL;
            SIGN_EXTEND(sval_t, imm, 9);
            ins->Op1.specflag1 |= N850F_OUTSIGNED;
          }
          else
            ins->itype = NEC850_MULU;

          set_opimm(&ins->Op1, imm);
          set_opreg(&ins->Op2, PARSE_R2);
          set_opreg(&ins->Op3, (w & 0xF8000000) >> 27);
          break;
        }
      }

      //
      // Format IX
      //
      op = w >> 16; // take 2nd half-word as the opcode
      uint32 reg1 = PARSE_R1;
      uint32 reg2 = PARSE_R2;
      // SETF
      if ( op == 0 )
      {
        if ( ( w & 0x10 ) == 0 )
        {
          ins->itype = NEC850_SETF;
          set_opcond(&ins->Op1, w & 0xF);
          set_opreg(&ins->Op2, reg2);
        }
        else if ( is_v850e2m() )
        {
          ins->itype = NEC850_RIE;
          uint imm5 = ( w >> 11 ) & 0x1F;
          uint imm4 = w & 0xF;
          set_opimm(&ins->Op1, imm5);
          set_opimm(&ins->Op2, imm4);
        }
        break;
      }

      switch ( op )
      {
        case 0x20: // LDSR
          ins->itype = NEC850_LDSR;
          ins->Op2.reg = rSR0; // designate system register
          break;
        case 0x40: // STSR
          ins->itype = NEC850_STSR;
          ins->Op1.reg = rSR0; // designate system register
          break;
        case 0x80: // SHR
          ins->itype = NEC850_SHR;
          break;
        case 0xA0: // SAR
          ins->itype = NEC850_SAR;
          break;
        case 0xC0: // SHL
          ins->itype = NEC850_SHL;
          break;
      }

      if ( ins->itype != 0 )
      {
        // Common stuff for the rest of Format 9 instructions
        ins->Op1.dtype = ins->Op2.dtype = dt_dword;
        ins->Op1.type  = ins->Op2.type  = o_reg;
        ins->Op1.reg  += reg1;
        ins->Op2.reg  += reg2;
        break;
      }

      // -> ins.itype == 0
      //
      // No match? Try V850E
      if ( is_v850e() )
      {
        // SASF
        if ( op == 0x200 )
        {
          ins->itype = NEC850_SASF;
          set_opcond(&ins->Op1, w & 0xF);
          set_opreg(&ins->Op2, reg2);
          break;
        }

        switch ( op )
        {
          case 0xE0: // NOT1
            ins->itype = NEC850_SET1;
            break;
          case 0xE2: // NOT1
            ins->itype = NEC850_NOT1;
            break;
          case 0xE4: // CLR1
            ins->itype = NEC850_CLR1;
            break;
          case 0xE6: // TST1
            ins->itype = NEC850_TST1;
            break;
          default:
            return 0; // No match!
        }
        // Common
        set_opreg(&ins->Op1, reg2, dt_byte);

        ins->Op2.dtype      = dt_byte;
        displ_op            = &ins->Op2;
        displ_op->type      = o_displ;
        displ_op->addr      = 0;
        displ_op->reg       = reg1;
        displ_op->specflag1 = N850F_USEBRACKETS;
      }

      if ( ins->itype == 0 )
        return 0; // unknown instruction

      break;
    } // Format end

    //
    // Format V
    //
    op = (w & 0x780) >> 6; // Take bit6->bit10
    // JARL and JR
    if ( op == 0x1E )
    {
      uint32 reg  = PARSE_R2;
      sval_t addr = uint32((((w & 0x3F) << 15) | ((w & 0xFFFE0000) >> 17)) << 1);
      SIGN_EXTEND(sval_t, addr, 22);

      ins->Op1.addr = ins->ip + addr;
      ins->Op1.type = o_near;
      // per the docs, if reg is zero then JARL turns to JR
      if ( reg == 0 )
      {
        ins->itype = NEC850_JR;
      }
      else
      {
        ins->itype = NEC850_JARL;
        set_opreg(&ins->Op2, reg);
      }
      break;
    }

    //
    // Format III
    //
    op = (w & 0x780) >> 7; // Take bit7->bit10
    // assert: op in [0, 0xF]
    // Bcond disp9
    if ( op == 0xB )
    {
      sval_t dest = ( ((w & 0x70) >> 4) | ((w & 0xF800) >> 8) ) << 1;
      SIGN_EXTEND(sval_t, dest, 9);

      ins->itype     = bcond_map[w & 0xF];
      ins->Op1.dtype = dt_word;
      ins->Op1.type  = o_near;
      ins->Op1.addr  = ea_t(dest + ins->ip);
      break;
    }
    //
    // Format IV
    //
    else if ( op >= 6 )
    {
      uint32 reg2 = PARSE_R2;
      uint32 addr = (w & 0x7F); // zero extended
      int idx_d(-1), idx_r(-1);
      char dtyp_d(-1);

      // SLD.B
      if ( op == 6 )
      {
        ins->itype = NEC850_SLD_B;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_byte;
      }
      // SLD.H
      else if ( op == 8 )
      {
        ins->itype = NEC850_SLD_H;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_word;
        addr <<= 1;
      }
      // SLD.W
      else if ( op == 10 && ((w & 1) == 0) )
      {
        ins->itype = NEC850_SLD_W;
        idx_d = 0;
        idx_r = 1;
        dtyp_d = dt_dword;
        addr <<= 1;
      }
      // SST.B
      else if ( op == 7 )
      {
        ins->itype = NEC850_SST_B;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_byte;
      }
      // SST.H
      else if ( op == 9 )
      {
        ins->itype = NEC850_SST_H;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_byte;
        // bit0 is already cleared, so the 7bit addr we read
        // can be shifted by one to transform it to 8bit
        addr <<= 1;
      }
      // SST.W
      else if ( op == 10 && ((w & 1) == 1) )
      {
        ins->itype = NEC850_SST_W;
        idx_d = 1;
        idx_r = 0;
        dtyp_d = dt_dword;
        // clear lower bit because it is set, and shift by one
        // bit 15             0
        //     rrrrr1010dddddd1
        addr = (addr & ~1) << 1;
      }
      if ( idx_d == -1 || idx_r == -1 || dtyp_d == -1 )
        return false; // could not decode

      set_opreg(&ins->ops[idx_r], reg2);

      ins->ops[idx_d].type      = o_displ;
      displ_op                  = &ins->ops[idx_d];
      ins->ops[idx_d].reg       = rEP;
      ins->ops[idx_d].addr      = addr;
      ins->ops[idx_d].dtype     = dtyp_d;
      ins->ops[idx_d].specflag1 = N850F_USEBRACKETS;
      break;
    }
    // Unknown instructions
    ins->itype = NEC850_NULL;
  } while ( false );

  // special cases when we have memory access through displacement
  if ( displ_op != nullptr )
  {
    // A displacement with GP and GP is set?
    if ( displ_op->reg == rGP && g_gp_ea != BADADDR )
    {
      displ_op->type = o_mem;
      if ( ins->itype == NEC850_SLD_BU || ins->itype == NEC850_LD_BU
        || ins->itype == NEC850_SLD_HU || ins->itype == NEC850_LD_HU )
      {
        displ_op->addr = short(displ_op->addr) + g_gp_ea;
      }
      else
      {
        displ_op->addr += g_gp_ea;
      }
    }
    // register zero access?
    else if ( displ_op->reg == rZERO )
    {
      // since r0 is always 0, we can replace the operand by the complete address
      displ_op->type = o_mem;
      displ_op->specflag1 &= ~N850F_OUTSIGNED;
      if ( ins->itype == NEC850_LD_BU || ins->itype == NEC850_LD_HU )
        displ_op->addr = short(displ_op->addr);
    }
#ifdef __EA64__
    if ( displ_op->type == o_mem )
    {
      // truncate address to 32 bits if needed
      segment_t *s = getseg(displ_op->addr);
      if ( s == nullptr || !s->is_64bit() )
        displ_op->addr = uint32(displ_op->addr);
    }
#endif
  }
  return ins->itype != 0;
}

//------------------------------------------------------------------------
struct nec850_macro_ctr_t : public macro_constructor_t
{
  nec850_t &proc_module;
  uint32 w;

  nec850_macro_ctr_t(nec850_t &_proc_module, uint32 _w) : proc_module(_proc_module), w(_w) {}

  bool idaapi build_macro(insn_t *insn, bool may_go_forward) override
  {
    return proc_module.build_macro(insn, may_go_forward, w);
  }
};

//------------------------------------------------------------------------
static bool is_st_bit_insn(uint16_t itype)
{
  switch ( itype )
  {
    case NEC850_ST_B:
    case NEC850_ST_H:
    case NEC850_ST_W:
    case NEC850_ST_DW:

    case NEC850_TST1:
    case NEC850_SET1:
    case NEC850_CLR1:
      return true;
  }

  return false;
}

//------------------------------------------------------------------------
static bool is_ld_st_insn(uint16_t itype)
{
  switch ( itype )
  {
    case NEC850_LD_B:
    case NEC850_LD_H:
    case NEC850_LD_W:
    case NEC850_LD_BU:
    case NEC850_LD_HU:
    case NEC850_LD_DW:
      return true;
  }

  return is_st_bit_insn(itype);
}

//------------------------------------------------------------------------
static uint32 sign_extended_val(uint32 high, uint32 low)
{
  uint32 low16 = static_cast<uint16>(low);
  SIGN_EXTEND(int32, low16, 16);
  return (high << 16) + static_cast<uint32>(low16);
}

//------------------------------------------------------------------------
static bool is_reg_used_after_ea(ea_t ea, uint16_t reg)
{
  const char *reg_name = RegNames[reg];

  range_t search_range(ea, inf_get_max_ea());
  func_t *func = get_func(search_range.start_ea);
  if ( func )
    search_range.end_ea = func->end_ea;

  reg_access_t access;
  ea_t access_ea = find_reg_access(&access, search_range.start_ea, search_range.end_ea, reg_name, SEARCH_NEXT | SEARCH_DOWN | SEARCH_BRK | SEARCH_USE);
  if ( access_ea != BADADDR )
    return true;

  return false;
}

//------------------------------------------------------------------------
// Handles cases where there is a movhi directly above a load/store instruction
// movhi hi1(label), reg1, r1
// ld.w lo(label)[r1], reg2
// ->
// ld.w label, reg2
bool nec850_t::ld_case(insn_t *insn, const insn_t &one_more_insn)
{
  if ( !is_ld_st_insn(one_more_insn.itype) )
    return false;

  bool swapped_ops = is_st_bit_insn(one_more_insn.itype);
  const op_t &displ_op = swapped_ops ? one_more_insn.Op2 : one_more_insn.Op1;
  op_t &new_displ_op = swapped_ops ? insn->Op2 : insn->Op1;
  if ( !insn->Op3.is_reg(displ_op.reg) )
    return false;

  range_t search_range(one_more_insn.ea, inf_get_max_ea());
  func_t *func = get_func(search_range.start_ea);
  if ( func )
    search_range.end_ea = func->end_ea;

  if ( one_more_insn.Op1.reg != one_more_insn.Op2.reg && is_reg_used_after_ea(one_more_insn.ea, insn->Op3.reg) )
    return false;

  uint32 addr = sign_extended_val(insn->Op1.value, displ_op.addr);
  insn->itype = one_more_insn.itype;

  new_displ_op.type = o_mem;
  new_displ_op.addr = addr;
  new_displ_op.dtype = displ_op.dtype;
  new_displ_op.reg = insn->Op2.reg;
  new_displ_op.specflag1 |= N850F_VAL32;

  if ( swapped_ops )
    insn->Op1 = one_more_insn.Op1;
  else
    insn->Op2 = one_more_insn.Op2;

  insn->Op3.type = o_void;

  insn->size += one_more_insn.size;
  return true;
}

//------------------------------------------------------------------------
// Handles cases where there is no movhi directly above or multiple loads and stores in series e.g.
// 1.
// movhi hi1(label), reg1, r1
// ...
// ld.w lo(label)[r1], reg2
// ->
// ld.w label, reg2
//
// 2.
// movhi hi1(label), reg1, r1
// ...
// ld.w lo(label)[r1], reg2
// ...
// st.w reg2, lo(label)[r1]
// ->
// ld.w label, reg2
// ...
// st.w reg2, label
bool nec850_t::basereg_ld_case(insn_t *insn)
{
  if ( !is_ld_st_insn(insn->itype) )
    return false;

  bool insn_has_swapped_ops = is_st_bit_insn(insn->itype);
  op_t &displ_op = insn_has_swapped_ops ? insn->Op2 : insn->Op1;

  ea_t offset_ea = insn->ea - 0x8;
  insn_t possible_movhi;
  if ( decode_insn(&possible_movhi, offset_ea) > 0 && possible_movhi.itype == NEC850_MOVHI )
  {
    insn_t possible_pattern;
    if ( decode_insn(&possible_pattern, possible_movhi.ea + possible_movhi.size) > 0
      && ld_case(&possible_movhi, possible_pattern) )
    {
      bool possible_has_swapped_ops = is_st_bit_insn(possible_pattern.itype);
      op_t &possible_non_displ_op = possible_has_swapped_ops ? possible_pattern.Op1 : possible_pattern.Op2;

      if ( possible_non_displ_op.reg == displ_op.reg )
        return false;
    }
  }

  reg_value_info_t info;
  if ( !find_reg_value_info(&info, insn->ea, displ_op.reg, 1) )
    return false;

  uint16 def_itype = info.get_def_itype();
  if ( def_itype != NEC850_MOVHI )
    return false;

  insn_t movhi_insn;
  if ( decode_insn(&movhi_insn, info.get_def_ea()) <= 0 )
    return false;

  insn_t below_movhi_insn;
  if ( decode_insn(&below_movhi_insn, movhi_insn.ea + movhi_insn.size) <= 0 )
    return false;

  bool is_ld = is_ld_st_insn(below_movhi_insn.itype);
  op_t &below_movhi_non_disp_op = is_st_bit_insn(below_movhi_insn.itype) ? below_movhi_insn.Op1 : below_movhi_insn.Op2;
  bool is_same_reg = displ_op.reg == below_movhi_non_disp_op.reg;
  if ( is_ld && is_same_reg )
    return false;

  uint32 addr = sign_extended_val(movhi_insn.Op1.value, displ_op.addr);
  displ_op.type = o_mem;
  displ_op.addr = addr;
  displ_op.reg = movhi_insn.Op2.reg;
  displ_op.specflag1 |= N850F_VAL32;

  return true;
}

//------------------------------------------------------------------------
// Merges imm32 add cases where there is only a high part
// movhi hi1(imm32), r0, r1
// add r1, reg (low bits are 0)
// ->
// add imm32, reg
bool nec850_t::add_imm32_low_case(insn_t *insn, const insn_t &one_more_insn)
{
  if ( !insn->Op2.is_reg(rZERO) || !insn->Op3.is_reg(rR1) )
    return false;

  if ( one_more_insn.itype != NEC850_ADD || !one_more_insn.Op1.is_reg(rR1) )
    return false;

  uint32_t new_value = insn->Op1.value << 16;
  insn->itype = one_more_insn.itype;
  for ( size_t i = 0; i < 3; ++i )
    insn->ops[i] = one_more_insn.ops[i];

  set_opimm(&insn->Op1, new_value);
  insn->Op1.specflag1 |= N850F_VAL32;

  insn->size += one_more_insn.size;
  return true;
}

//------------------------------------------------------------------------
// Merges imm32 mov case, where there is a low and high part
// movhi hi1(imm32), r0, reg
// movea lo(imm32), reg, reg
// ->
// mov imm32, reg
bool nec850_t::movhi_movea_imm32_case(insn_t *insn, const insn_t &one_more_insn)
{
  if ( !insn->Op2.is_reg(rZERO) || !one_more_insn.Op2.is_reg(insn->Op3.reg) || !one_more_insn.Op3.is_reg(insn->Op3.reg) )
    return false;

  if ( one_more_insn.itype != NEC850_MOVEA )
    return false;

  uint32_t new_value = sign_extended_val(insn->Op1.value, one_more_insn.Op1.value);

  insn->itype = NEC850_MOV;
  set_opimm(&insn->Op1, new_value);
  insn->Op1.specflag1 |= N850F_VAL32;

  set_opreg(&insn->Op2, insn->Op3.reg, insn->Op3.dtype);
  insn->Op3 = {};

  insn->size += one_more_insn.size;
  return true;
}

//------------------------------------------------------------------------
bool nec850_t::build_macro(insn_t *insn, bool may_go_forward, uint32 insn_w)
{
  qnotused(insn_w);

  if ( !may_go_forward )
    return false;

  insn_t one_more_insn;
  if ( decode_insn(&one_more_insn, insn->ea + insn->size) <= 0 )
    return false;

  if ( basereg_ld_case(insn) )
    return false;

  if ( insn->itype == NEC850_MOVHI )
  {
    // ld, st, tst1, set1, clr1:
    // ld.w label[reg1], reg2 -> movhi hi1(label), reg1, r1; ld.w lo(label)[r1], reg2
    if ( ld_case(insn, one_more_insn) )
      return true;

    // add imm32, reg -> movhi hi1(imm32), r0, r1; add r1, reg (low bits are 0)
    if ( add_imm32_low_case(insn, one_more_insn) )
      return true;

    // mov imm32, reg; -> movhi hi1(imm32), r0, reg; movea lo(imm32), reg, reg;
    if ( movhi_movea_imm32_case(insn, one_more_insn) )
      return true;
  }

  return false;
}

//------------------------------------------------------------------------
// Analyze one instruction and fill 'insn' structure.
// insn.ea contains address of instruction to analyze.
// Return length of the instruction in bytes, 0 if instruction can't be decoded.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
int nec850_t::nec850_ana(insn_t *pinsn)
{
  if ( pinsn->ea & 0x1 )
    return 0;

  uint32 w;
  fetch_instruction(&w, pinsn);
  if ( decode_instruction(w, pinsn) )
  {
    nec850_macro_ctr_t insn_macro(*this, w);
    insn_macro.construct_macro(pinsn, inf_macros_enabled());
    return pinsn->size;
  }

  return 0;
}
