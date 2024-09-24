
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "cr16.hpp"

//----------------------------------------------------------------------
static uchar Rproc(uchar code)
{
  switch ( code )
  {
    case 0x1:
      return rPSR;
    case 0x3:
      return rINTBASE;
    case 0x4:
      return rINTBASEH;
    case 0x5:
      return rCFG;
    case 0x7:
      return rDSR;
    case 0x9:
      return rDCR;
    case 0xB:
      return rISP;
    case 0xD:
      return rCARL;
    case 0xE:
      return rCARH;
  }
  return 0;
}

//----------------------------------------------------------------------
// immediate operands
static void SetImmData(op_t &op, int32 code, int bits)
{
  // extend sign
  if ( code & (1 << bits) )
    code -= 1 << (bits + 1);
  op.type = o_imm;
  // always in the second byte
  op.offb = 1;
  // data size
  op.dtype = bits > 8 ? (bits > 16 ? dt_dword : dt_word) : dt_byte;
  // value
  op.addr = op.value = code;
}

//----------------------------------------------------------------------
// register operand
static void SetReg(op_t &op, uchar reg_n)
{
  op.type  = o_reg;
  op.reg   = reg_n;
  op.dtype = dt_word;
}


//----------------------------------------------------------------------
// relative jump
static void SetRelative(op_t &op, int32 disp, int bits, const insn_t &insn)
{
  op.type  = o_near;
  op.dtype = dt_word;
  op.offb  = 0;
  // sign extend
  if ( disp & (1 << bits) )
    disp -= 1 << (bits + 1);
  op.addr = insn.ip + disp;
}

//----------------------------------------------------------------------
static ushort GetWord(insn_t &insn)
{
  ushort wrd = insn.get_next_byte();
  wrd |= ((ushort) insn.get_next_byte()) << 8;
  return wrd;
}

//----------------------------------------------------------------------
// store/load operands
static void SetSL(insn_t &insn, op_t &op, ushort code)
{
  op.reg = rR0 + ((code >> 1) & 0x0F);
  op.dtype = (code & 0x2000) ? dt_word : dt_byte;
  if ( code & 1 )
  {
    if ( code & 0x1000 )
    {
      if ( code & 0x800 )
      {
        if ( (code & 0x1F) == 0x1F )
        {
          // absolute addr
          op.type = o_mem;
          op.addr = op.value = GetWord(insn) | (((uint32) code & 0x600) << 11);
        }
        else
        {                       // reg pair
          op.type = o_displ;
          op.addr = op.value = GetWord(insn) | (((uint32) code & 0x600) << 11);
          op.specflag1 |= URR_PAIR;
        }
      }
      else
      {                         // reg base
        op.type = o_displ;
        op.addr = op.value = GetWord(insn) | (((uint32) code & 0x600) << 11);
      }
    }
    else
    {                           // Offset
      op.type = o_displ;
      op.addr = op.value = ((code >> 8) & 0x1E) | 1;
    }
  }
  else
  {
    op.type = o_displ;
    op.addr = op.value = (code >> 8) & 0x1E;
  }
}

//----------------------------------------------------------------------
#define EXTOPS uint16(-2)
static const uint16 Ops[16] =
{
  CR16_addb,  CR16_addub, EXTOPS,    CR16_mulb,
  CR16_ashub, CR16_lshb,  CR16_xorb, CR16_cmpb,
  CR16_andb,  CR16_addcb, CR16_br,   CR16_tbit,
  CR16_movb,  CR16_subcb, CR16_orb,  CR16_subb,
};

static const uint16 ExtOps[16] =
{
  CR16_cbitb, CR16_sbitb, CR16_tbitb, CR16_storb,
};

// extended instructions
// register-relative with no displacement:
// 54 3 2109 8   76     5  4321        d
// 01 i 0010 bs1 ex-op bs0 bit-num/Imm 1
// register-relative with 16-bit displacement:
// 54 3 2109 8   76     5  4321        d
// 00 i 0010 bs1 ex-op bs0 bit-num/Imm 1
// 18-bit absolute memory:
// 54 3 2109 8   76     5  4321        d
// 00 i 0010 bs1 ex-op bs0 bit-num/Imm 0
static void SetExtOp(insn_t &insn, ushort code)
{
  if ( code & 1 )
  {
    // Register-relative
    insn.Op2.reg   = rR0 + ((code >> 5) & 9);
    insn.Op2.type  = o_displ;
    insn.Op2.dtype = (code & 0x2000) ? dt_word : dt_byte;
    if ( (code >> 14) & 1 )
    {
      // no displacement
      insn.Op2.addr = 0;
    }
    else
    {
      insn.Op2.addr = GetWord(insn);
    }
  }
  else
  {
    // 18-bit absolute memory
    insn.Op2.type = o_mem;
    insn.Op2.dtype = (code & 0x2000) ? dt_word : dt_byte;
    int adext = ((code >> 7) & 2) | ((code >> 5) & 1);
    insn.Op2.addr = GetWord(insn) | (adext<<16);
  }
  insn.Op1.type = o_imm;
  insn.Op1.value = (code >> 1) & 0xF;
}

//----------------------------------------------------------------------
// analyzer
int idaapi CR16_ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;
  if ( insn.ip & 1 )
    return 0;

  // get instruction word
  ushort code = GetWord(insn);

  uchar WordFlg = (code >> 13) & 1;
  uchar OpCode = (code >> 9) & 0x0F;
  uchar Oper1 = (code >> 5) & 0x0F;
  uchar Oper2 = (code >> 1) & 0x0F;


  switch ( (code >> 14) & 3 )
  {
    // register-register op and special OP
    case 0x01:
      if ( code & 1 )
      {
        // 01xxxxxxxxxxxxx1
        insn.itype = Ops[OpCode];
        switch ( insn.itype )
        {
          case 0:
            return 0;
          case EXTOPS:
            {
              int exop = (Oper1 >> 1) & 3;
              insn.itype = ExtOps[exop] + WordFlg;
              SetExtOp(insn, code);
            }
            break;
            // branch's
          case CR16_br:
            if ( WordFlg )
            {
              insn.itype = CR16_jal;
              SetReg(insn.Op1, rR0 + Oper1);
              SetReg(insn.Op2, rR0 + Oper2);
            }
            else
            {
              insn.itype = CR16_jeq + Oper1;
              SetReg(insn.Op1, rR0 + Oper2);
            }
            break;
            // Special tbit
          case CR16_tbit:
            if ( WordFlg == 0 )
              return 0;
            insn.itype--;
            // fallthrough
            // all other cmds
          default:             // fix word operations
            if ( WordFlg )
              insn.itype++;
            // Setup register OP
            SetReg(insn.Op2, rR0 + Oper1);
            // Setup register OP
            SetReg(insn.Op1, rR0 + Oper2);
            break;
        }
      }
      else
      {                         // 01xxxxxxxxxxxxx0
        if ( WordFlg )
        {
          // 011xxxxxxxxxxxx0
          static const uchar SCmd[16] =
          {
            CR16_mulsb, CR16_mulsw, CR16_movd, CR16_movd,
            CR16_movxb, CR16_movzb, CR16_push, CR16_seq,
            CR16_lpr,   CR16_spr,   CR16_beq,  CR16_bal,
            CR16_retx,  CR16_excp,  CR16_di,   CR16_wait
          };
          insn.itype = SCmd[OpCode];
          switch ( insn.itype )
          {
            case 0:
              return 0;

            case CR16_beq:
              {
                // 01 1 1010    cond   d16,d19-d17 0
                insn.itype = CR16_beq + Oper1;
                int disp = GetWord(insn);
                disp |= (Oper2 & 8) << (16-3);
                disp |= (Oper2 & 7) << 17;
                SetRelative(insn.Op1, disp, 20, insn);
              }
              break;

            case CR16_push:
              {
                static const uchar PQ[4] =
                {
                  CR16_push,   CR16_pop,
                  CR16_popret, CR16_popret
                };
                insn.itype = PQ[Oper1 >> 2];
                SetReg(insn.Op2, rR0 + Oper2);
                SetImmData(insn.Op1, (Oper1 & 3) + 1, 4);
                break;
              }

            case CR16_mulsw:
              SetReg(insn.Op2, rR0 + Oper1);
              SetReg(insn.Op1, rR0 + Oper2);
              insn.Op2.specflag1 |= URR_PAIR;
              break;

            case CR16_movd:
              SetReg(insn.Op2, rR0 + Oper2);
              insn.Op2.specflag1 |= URR_PAIR;
              // !!!! ADD HIIIII ?!?!?!?
              SetImmData(insn.Op1, GetWord(insn), 20);
              break;
            case CR16_excp:
              if ( Oper1 != 0x0F )
                return 0;
              SetImmData(insn.Op1, Oper2, 4);
              break;

            case CR16_retx:
              if ( Oper1 != 0x0F )
                return 0;
              if ( Oper2 != 0x0F )
                return 0;
              break;

            case CR16_wait:
              if ( Oper1 == 0x0F )
              {
                if ( Oper2 == 0x0F )
                  break;
                if ( Oper2 == 0x03 )
                {
                  insn.itype = CR16_eiwait;
                  break;
                }
              }
              if ( (code & 0x19E) == 0x84 )
              {
                insn.itype = CR16_storm;
                SetImmData(insn.Op1, (Oper2 & 3) + 1, 8);
                break;
              }
              if ( (code & 0x19E) == 0x04 )
              {
                insn.itype = CR16_loadm;
                SetImmData(insn.Op1, (Oper2 & 3) + 1, 8);
                break;
              }
              if ( (Oper2 & 0x6) == 0 )
              {
                insn.itype = CR16_muluw;
                SetReg(insn.Op2, rR0 + Oper1);
                SetReg(insn.Op1, rR0 + Oper2);
                insn.Op2.specflag1 |= URR_PAIR;
                break;
              }

              return 0;

            case CR16_di:
              if ( Oper2 != 0x0F )
                return 0;
              switch ( Oper1 )
              {
                case 0x0F:
                  insn.itype = CR16_ei;
                case 0x0E:
                  break;
                default:
                  return 0;
              }
              break;

            case CR16_seq:
              SetReg(insn.Op1, rR0 + Oper2);
              if ( Oper1 > 0x0D )
                return 0;
              insn.itype = CR16_seq + Oper1;
              break;

            case CR16_lpr:
              SetReg(insn.Op1, rR0 + Oper2);
              Oper1 = Rproc(Oper1);
              if ( Oper1 == 0 )
                return 0;
              SetReg(insn.Op2, Oper1);
              break;

            case CR16_spr:
              SetReg(insn.Op2, rR0 + Oper2);
              Oper1 = Rproc(Oper1);
              if ( Oper1 == 0 )
                return 0;
              SetReg(insn.Op1, Oper1);
              break;

            case CR16_bal:
              {
                // 01 1 1011 lnk-pair  d16,d19-d17 0
                SetReg(insn.Op1, rR0 + Oper1);
                insn.Op1.specflag1 |= URR_PAIR;
                int disp = GetWord(insn);
                disp |= (Oper2 & 8) << (16-3);
                disp |= (Oper2 & 7) << 17;
                SetRelative(insn.Op2, disp, 20, insn);
              }
              break;

            default:
              SetReg(insn.Op2, rR0 + Oper1);
              SetReg(insn.Op1, rR0 + Oper2);
              break;
          }
        }
        else
        {                       // jump's
          // 010xxxxxxxxxxxx0
          insn.itype = CR16_beq + Oper1;
          SetRelative(insn.Op1, (code & 0x1E) | (OpCode << 5), 8, insn);
        }
      }
      break;

      // short immediate-register (two word)
    case 0x00:
      insn.itype = Ops[OpCode];
      switch ( insn.itype )
      {
        case 0:
          return 0;
          // branch's
        case CR16_br:
          if ( code & 1 )
          {
            static const uchar BQ[4] =
            {
              CR16_beq0b, CR16_beq1b,
              CR16_bne0b, CR16_bne1b
            };
            insn.itype = BQ[(Oper1 >> 1) & 3];
            if ( WordFlg )
              insn.itype++;
            SetReg(insn.Op1, rR0 + (Oper1 & 0x9));
            SetRelative(insn.Op1, code & 0x1E, 5, insn);
          }
          else if ( WordFlg )
          {
            insn.itype = CR16_bal;
            SetReg(insn.Op1, rR0 + Oper1);
            if ( (code & 0x0F) == 0x0E )
            {
              SetRelative(insn.Op2,
                          GetWord(insn) | (((uint32) code & 0x10) << 12), 16, insn);
              insn.Op2.addr = insn.Op2.value = insn.Op2.addr & 0x1FFFF;
            }
            else
              SetRelative(insn.Op2, code & 0x1F, 4, insn);
          }
          else
          {
            insn.itype = CR16_beq + Oper1;
            if ( (code & 0x0F) == 0x0E )
            {
              SetRelative(insn.Op1,
                          GetWord(insn) | (((uint32) code & 0x10) << 12), 16, insn);
              insn.Op1.addr = insn.Op1.value = insn.Op2.addr & 0x1FFFF;
            }
            else
            {
              SetRelative(insn.Op1, code & 0x1F, 4, insn);
            }
          }
          break;

        case EXTOPS:
          {
            // 54 3 2109 8   76     5  4321        d
            // 00 i 0010 bs1 ex-op bs0 bit-num/Imm d
            int exop = (Oper1 >> 1) & 3;
            insn.itype = ExtOps[exop] + WordFlg;
            SetExtOp(insn, code);
          }
          break;

          // Special tbit
        case CR16_tbit:
          if ( WordFlg == 0 )
          {
            // jcond large format
            // 00 0 1011 cond target-pair 1
            // jal large format
            // 00 0 1011 link-pair target-pair 0
            if ( code & 1 )
            {
              insn.itype = CR16_jeq + Oper1;
              SetReg(insn.Op1, rR0 + Oper2);
              insn.Op1.specflag1 |= URR_PAIR;
            }
            else
            {
              insn.itype = CR16_jal;
              SetReg(insn.Op1, rR0 + Oper1);
              insn.Op1.specflag1 |= URR_PAIR;
              SetReg(insn.Op2, rR0 + Oper2);
              insn.Op2.specflag1 |= URR_PAIR;
            }
            break;
          }
          insn.itype--;
          // fallthrough

          // all other cmds
        default:
          if ( code == 0x200 )
          {
            insn.itype = CR16_nop;
            break;
          }
          if ( WordFlg ) // fix word operations
            insn.itype++;
          // Setup register OP
          SetReg(insn.Op2, rR0 + Oper1);
          // Setup immediate
          if ( (code & 0x1F) == 0x11 )
            SetImmData(insn.Op1, GetWord(insn), 15);
          else
            SetImmData(insn.Op1, code & 0x1F, 4);
          break;
      }
      break;

      // LOADi
    case 0x02:
      insn.itype = WordFlg ? CR16_loadw : CR16_loadb;
      SetReg(insn.Op2, rR0 + Oper1);
      SetSL(insn, insn.Op1, code);
      break;
      // STORi
    case 0x3:
      insn.itype = WordFlg ? CR16_storw : CR16_storb;
      SetReg(insn.Op1, rR0 + Oper1);
      SetSL(insn, insn.Op2, code);
      break;
  }
  return insn.size;
}
