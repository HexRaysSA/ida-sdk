/*
 *  Interactive disassembler (IDA).
 *  Zilog Z8 module
 *
 */

#include "z8.hpp"


//----------------------------------------------------------------------
static int adjust_reg_alias(int reg_no, uint16 rp, bool mem)
{
  // special case for Tycoint
  // we use the third nibble to map the registers to alternative names in 1000:2000
  // aliases for regs in the same WRG are placed next to each other in 256-byte blocks
  // e.g.
  // 1400-140F first alias group for regs 40-4F
  // 1410-141F second alias group for regs 40-4F
  // 1420-142F third alias group for regs 40-4F
  // ... etc
  int subbank_no = ((rp & 0xF00) >> 8) - 1;
  // assert: subbank_no in [-1, 0xE]
  if ( subbank_no >= 0 )
  {
    int wrg_no;
    if ( mem )
    {
      // WRG is the high nibble of the register number
      wrg_no = (reg_no & 0xF0) >> 4;
      if ( wrg_no < 0xF )
        reg_no &= 0xF;
    }
    else
    {
      // WRG is the high nibble of the RP
      wrg_no = (rp & 0xF0) >> 4;
    }
    if ( wrg_no < 0xF ) // don't alias system registers (F0-FF)
      reg_no += 0x1000 + wrg_no * 256 + subbank_no * 16;
  }
  return reg_no;
}

//----------------------------------------------------------------------
static void work_reg(const insn_t &insn, op_t &op, int reg_no, int dbl_reg = 0, int indir = 0 )
{
  if ( dbl_reg )
    op.dtype = dt_word;

  // do we have RP set?
  uint16 rp = get_rp(insn.ea);
  if ( rp == 0 )
  {
    // nope; use default working group (0)
    op.reg  = (dbl_reg ? rRR0 : rR0) + reg_no;
    op.type = indir ? o_ind_reg : o_reg;
  }
  else
  {
    // use memory operand
    if ( (rp & 0xF) == 0 && (rp & 0xF00) != 0 )
    {
      reg_no = adjust_reg_alias(reg_no, rp, false);
    }
    else
    {
      // high nibble of rp is the working group (bank), low nibble is the extended register file
      reg_no += rp & 0xF0;
      reg_no += (rp & 0xF) << 8;
    }
    op.addr = reg_no;
    op.type = indir ? o_ind_mem : o_mem;
  }
}

//----------------------------------------------------------------------
static void dir_reg(insn_t &insn, op_t &op, int dbl_reg = 0, int indir = 0)
{
  uint tmp = insn.get_next_byte();
  if ( (tmp & 0xF0 ) == 0xE0 )   // Ex - special reg bank
  {
    work_reg(insn, op, tmp & 0xF, dbl_reg, indir);
  }
  else
  {
    // use memory operand
    uint16 rp = get_rp(insn.ea);
    if ( (rp & 0xF) == 0 && (rp & 0xF00) != 0 )
      tmp = adjust_reg_alias(tmp, rp, true);
    op.addr = tmp;
    op.type = indir ? o_ind_mem : o_mem;
    if ( dbl_reg )
      op.dtype = dt_word;
  }
}

//----------------------------------------------------------------------

int z8_t::z8_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;

  insn.Op1.dtype = dt_byte;
  insn.Op2.dtype = dt_byte;

  uint16 code = insn.get_next_byte();

  uint16 nibble0 = (code & 0xF);
  uint16 nibble1 = (code >> 4);

  char offc;
  uint16 tmp;

  if ( nibble0 == 0xF )      // xF
  {
    static const char cmdxF[] =
    {
      Z8_null, Z8_null, Z8_null, Z8_null,
      Z8_null, Z8_null, Z8_stop, Z8_halt,
      Z8_di,   Z8_ei,   Z8_ret,  Z8_iret,
      Z8_rcf,  Z8_scf,  Z8_ccf,  Z8_nop
    };

    insn.itype = cmdxF[nibble1];
  }
  else if ( nibble0 >= 8 )   // x8..xE
  {
    static const char cmdx8E[] =
    {
      Z8_ld, Z8_ld, Z8_djnz, Z8_jrcond, Z8_ld, Z8_jpcond, Z8_inc
    };

    insn.itype = cmdx8E[nibble0-8];

    if ( nibble0 == 8 || nibble0 == 0xA || nibble0 == 0xC || nibble0 == 0xE )
    {
      work_reg(insn, insn.Op1, nibble1);
    }

    if ( nibble0 == 0xB || nibble0 == 0xD )
    {
      insn.Op1.type   = o_phrase;
      insn.Op1.phrase = nibble1;
    }

    switch ( nibble0 )
    {
      case 0x8:     // ld r1,R2
        dir_reg(insn, insn.Op2);
        break;

      case 0x9:     // ld r2,R1
        dir_reg(insn, insn.Op1);
        work_reg(insn, insn.Op2, nibble1);
        break;

      case 0xA:     // djnz r1,RA
      case 0xB:     // jr cc,RA
        offc = insn.get_next_byte();
        insn.Op2.addr  = ushort(insn.ip + insn.size + offc);  // signed addition
        insn.Op2.dtype = dt_word;
        insn.Op2.type  = o_near;
        break;

      case 0xC:     // ld r1,#im
        insn.Op2.value = insn.get_next_byte();
        insn.Op2.type  = o_imm;
        break;

      case 0xD:     // jp cc,DA
        insn.Op2.addr  = insn.get_next_word();
        insn.Op2.dtype = dt_word;
        insn.Op2.type  = o_near;
    }

    if ( (nibble0 == 0xB || nibble0 == 0xD)
      && (nibble1 == 0   || nibble1 == 8) )
      switch ( nibble1 )
      {
        case 0:                     // never true - seems as 2-byte NOP
          insn.Op1.type = o_void;
          insn.itype    = Z8_nop;
          insn.Op2.type = o_void;
          break;

        case 8:
          insn.Op1 = insn.Op2;
          insn.itype--;              // Z8_jpcond -> Z8_jp, Z8_jrcond -> Z8_jr
          insn.Op2.type = o_void;
      }
  }
  else if ( nibble0 >= 2 )   // x2..x7
  {
    static const char cmdx2[] =
    {
      Z8_add,  Z8_adc,  Z8_sub, Z8_sbc,
      Z8_or,   Z8_and,  Z8_tcm, Z8_tm,
      Z8_null, Z8_null, Z8_cp,  Z8_xor,
      Z8_null, Z8_null, Z8_ld,  Z8_null
    };

    switch ( code )
    {
      case 0xD6:
      case 0xD4:
        insn.itype     = Z8_call;
        insn.Op1.dtype = dt_word;

        if ( code == 0xD6 )
        {
          insn.Op1.addr = insn.get_next_word();
          insn.Op1.type = o_near;
        }
        else  // D4 - call @RR
        {
          dir_reg(insn, insn.Op1, 1, 1);
        }
        break;

      case 0xC7:
        tmp = insn.get_next_byte();
        work_reg(insn, insn.Op1, tmp >> 4);
        insn.Op2.reg   = tmp & 0xF;
        insn.Op2.type  = o_displ;
        insn.Op2.addr  = insn.get_next_byte();
        insn.itype     = Z8_ld;
        break;

      case 0xD7:
        tmp = insn.get_next_byte();
        work_reg(insn, insn.Op2, tmp >> 4);
        insn.Op1.reg   = tmp & 0xF;
        insn.Op1.type  = o_displ;
        insn.Op1.addr  = insn.get_next_byte();
        insn.itype     = Z8_ld;
        break;

      case 0x82: case 0x83: case 0x92: case 0x93:
        tmp = insn.get_next_byte();
        insn.itype = (nibble0 == 2) ? Z8_lde : Z8_ldei;
        if ( nibble1 == 8 )
        {
          // r dst, lrr src
          work_reg(insn, insn.Op1, tmp >> 4,  0, nibble0 != 2);
          work_reg(insn, insn.Op2, tmp & 0xF, 1, 1);
        }
        else
        {
          // lrr dst, r src
          work_reg(insn, insn.Op1, tmp & 0xF, 1, 1);
          work_reg(insn, insn.Op2, tmp >> 4,  0, nibble0 != 2);
        }
        break;

      case 0xC2: case 0xC3: case 0xD2: case 0xD3:
        tmp = insn.get_next_byte();
        insn.itype = (nibble0 == 2) ? Z8_ldc : Z8_ldci;
        if ( nibble1 == 0xC )
        {
          work_reg(insn, insn.Op1, tmp >> 4,  0, nibble0 != 2);
          work_reg(insn, insn.Op2, tmp & 0xF, 1, 1);
        }
        else
        {
          work_reg(insn, insn.Op1, tmp & 0xF, 1, 1);
          work_reg(insn, insn.Op2, tmp >> 4,  0, nibble0 != 2);
        }
        break;

      default:
        insn.itype = cmdx2[nibble1];

        switch ( nibble0 )
        {
          case 2:     // r1,r2
          case 3:     // r1,Ir2
            tmp = insn.get_next_byte();
            work_reg(insn, insn.Op1, tmp >> 4);
            work_reg(insn, insn.Op2, tmp & 0xF, 0, nibble0 != 2);
            break;

          case 4:     // R2,R1
          case 5:     // IR2,R1
            dir_reg(insn, insn.Op2, 0, nibble0 == 5);
            dir_reg(insn, insn.Op1);
            break;

          case 6:     // R1,IM
          case 7:     // IR1,IM
            dir_reg(insn, insn.Op1, 0, nibble0 == 7);
            insn.Op2.value = insn.get_next_byte();
            insn.Op2.type  = o_imm;
        }

        switch ( nibble1 )
        {
          case 0xF:   // ld
            switch ( nibble0 )
            {
              case 3: // ld Ir1,r2
                insn.Op2.type = o_reg;
                insn.Op1.type = o_ind_reg;
                insn.itype    = Z8_ld;
                break;

              case 5: // ld R2,IR1
                {
                  op_t tmp_op = insn.Op1;
                  insn.Op1     = insn.Op2;
                  insn.Op2     = tmp_op;
                  insn.itype   = Z8_ld;
                }
            }
            break;

          case 0xE:   // ld
            if ( nibble0 != 2 )
              insn.itype = Z8_ld;
        }
    }
  }
  else                      // x0..x1
  {                                                    /*Z8_srp*/
    static const char cmdx01[] =
    {
      Z8_dec,  Z8_rlc, Z8_inc,  Z8_jp,
      Z8_da,   Z8_pop, Z8_com,  Z8_push,
      Z8_decw, Z8_rl,  Z8_incw, Z8_clr,
      Z8_rrc,  Z8_sra, Z8_rr,   Z8_swap
    };

    insn.itype = cmdx01[nibble1];
    switch ( code )
    {
      case 0x30:    // jp @intmem
        dir_reg(insn, insn.Op1, 1, 1);
        break;

      case 0x31:    // srp #xx
        insn.itype     = Z8_srp;
        insn.Op1.type  = o_imm;
        insn.Op1.value = insn.get_next_byte();
        insn.Op1.flags |= OF_NUMBER;
        break;

      default:
        dir_reg(insn, insn.Op1, (code == 0x80) || (code == 0xA0), nibble0);
    }
  }

  if ( insn.itype == Z8_null )
    return 0;   // unknown command
  return insn.size;
}
