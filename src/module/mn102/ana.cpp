/*
 *      Panasonic MN102 (PanaXSeries) processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "pan.hpp"

//---------------------------------------------------------------------------
// internal use only
static uint32 LoadData(insn_t &insn, int bytes)
{
  uint32 dt = 0;
  // load data
  for ( int i=0; i < bytes; i++ )
  {
    uint32 nb = insn.get_next_byte();
    dt |= nb << (8*i);
  }
  return dt;
}

//---------------------------------------------------------------------------
// load a label's address
static void SetLabel(insn_t &insn, op_t &op, int bytes)
{
  uint32 off;
  op.type = o_near;
  // load the data
  off = LoadData(insn, bytes);
  // sign extend
  switch ( bytes )
  {
    // 1 byte
    case 1:
      if ( off&0x000080 )
        off |= ~0x00007F;
      break;

    // 2 bytes
    case 2:
      if ( off&0x008000 )
        off |= ~0x007FFF;
      break;

    // 3 bytes
    case 3:
      if ( off&0x800000 )
        off |= ~0x7FFFFF;
      break;
  }
//  sprintf(cc,"%lx",off);
//  msg(cc);
  op.addr = op.value = (off+(uint32)insn.size+insn.ea) & 0xFFFFFF;
//  sprintf(cc,"==%lx",op.value);
//  msg(cc);
//  sprintf(cc,"==%lx",insn.ea);
//  msg(cc);
//  msg("\n");
}

//---------------------------------------------------------------------------
// set immediate operand, only numbers
static void SetImm(insn_t &insn, op_t &op, int bytes)
{
  op.type = o_imm;                        // immediate
  op.dtype = dt_dword;
  op.addr = op.value = LoadData(insn, bytes);   // number value
}

//---------------------------------------------------------------------------
static void SetImmC(op_t &op, int Val)
{
  op.type = o_imm;                        // immediate
  op.dtype = dt_dword;
  op.flags |= OF_NUMBER;                  // number only
  op.addr = op.value = Val;                // value
}

//---------------------------------------------------------------------------
// registe addressing
static void SetReg(op_t &op, uchar Reg)
{
  op.type = o_reg;
  op.reg = Reg;
  op.addr = op.value = 0;
}

//---------------------------------------------------------------------------
// indirect addressing
static void SetRReg(op_t &op, uchar Reg)
{
  op.type = o_reg;
  op.reg = Reg|0x80;        // indirect
  op.addr = op.value = 0;
}

//---------------------------------------------------------------------------
// indirect addressing with a displacement
static void SetDisplI(op_t &op, uchar Reg, uchar RegI)
{
  op.type = o_reg;
  op.reg = (Reg&0x0F)|0x90|((RegI&3)<<5);
  op.addr = op.value = 0;
}

//---------------------------------------------------------------------------
// indirect addressing with a displacement
static void SetDispl(insn_t &insn, op_t &op, uchar Reg, int OffSize)
{
  op.type = o_displ;
  op.dtype = dt_dword;
  op.reg = Reg;
  op.addr = op.value = LoadData(insn, OffSize);
}

//---------------------------------------------------------------------------
// memory addressing
static void SetMem(insn_t &insn, op_t &op, int AddrSize, uchar DataSize)
{
  op.type = o_mem;
  op.addr = op.value = LoadData(insn, AddrSize);
  op.dtype = DataSize;
}

//---------------------------------------------------------------------------
// analyzer
int idaapi mn102_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  uchar R1, R2;
  // read first byte
  uchar code = insn.get_next_byte();
  // analyze high bits
  R1 = code&3;
  R2 = (code>>2)&3;
  insn.Op1.specflag1 = 0;
  insn.Op2.specflag1 = 0;
  switch ( code>>4 )
  {
    // mov  Dm, (An)
    case 0x00:
      insn.itype = mn102_mov;
      SetReg(insn.Op1,R1+rD0);
      SetRReg(insn.Op2,R2+rA0);
      break;

    // movb Dm, (An)
    case 0x01:
      insn.itype = mn102_movb;
      SetReg(insn.Op1,R1+rD0);
      SetRReg(insn.Op2,R2+rA0);
      break;

    // mov (An), Dm
    case 0x02:
      insn.itype = mn102_mov;
      SetReg(insn.Op2,R1+rD0);
      SetRReg(insn.Op1,R2+rA0);
      break;

    // movbu (An), Dm
    case 0x03:
      insn.itype = mn102_movbu;
      SetReg(insn.Op2,R1+rD0);
      SetRReg(insn.Op1,R2+rA0);
      break;

    // mov  Dm, (d8,An)
    case 0x04:
      insn.itype = mn102_mov;
      SetReg(insn.Op1,R1+rD0);
      SetDispl(insn, insn.Op2,R2+rA0,1);
      break;

    // mov  An, (d8,An);
    case 0x05:
      insn.itype = mn102_mov;
      SetReg(insn.Op1,R1+rA0);
      SetDispl(insn, insn.Op2,R2+rA0,1);
      break;

    // mov (d8,An), Dm
    case 0x06:
      insn.itype = mn102_mov;
      SetReg(insn.Op2,R1+rD0);
      SetDispl(insn, insn.Op1,R2+rA0,1);
      break;

    // mov  (d8,An), Am
    case 0x07:
      insn.itype = mn102_mov;
      SetReg(insn.Op2,R1+rA0);
      SetDispl(insn, insn.Op1,R2+rA0,1);
      break;

    // mov Dn, Dm or mov imm8,Dn
    case 0x08:
      insn.itype = mn102_mov;
      if ( (code&3) == ((code>>2)&3) )
      {
        // mov imm, Dn
        SetImm(insn, insn.Op1,1);
        SetReg(insn.Op2,R1+rD0);
      }
      else
      {
        SetReg(insn.Op1,R2+rD0);
        SetReg(insn.Op2,R1+rD0);
      }
      break;

    // add Dn, Dm
    case 0x09:
      insn.itype = mn102_add;
      SetReg(insn.Op1,R2+rD0);
      SetReg(insn.Op2,R1+rD0);
      break;

    // Sub Dn,Dm
    case 0x0A:
      insn.itype = mn102_sub;
      SetReg(insn.Op1,R2+rD0);
      SetReg(insn.Op2,R1+rD0);
      break;

    // Extx* Dn
    case 0x0B:
      switch ( code&0xC )
      {
        // extx
        case 0x00:
          insn.itype = mn102_extx;
          break;
        case 0x04:
          insn.itype = mn102_extxu;
          break;
        case 0x08:
          insn.itype = mn102_extxb;
          break;
        case 0x0C:
          insn.itype = mn102_extxbu;
          break;
      }
      SetReg(insn.Op1,R1+rD0);
      break;

    // mov* Dn, (mem)
    case 0x0C:
      switch ( code&0xC )
      {
        // mov Dn, (abs)
        case 0x00:
          insn.itype = mn102_mov;
          SetReg(insn.Op1,R1+rD0);
          SetMem(insn, insn.Op2, 2, dt_word);
          break;

        // movb Dn, (abs)
        case 0x04:
          insn.itype = mn102_movb;
          SetReg(insn.Op1,R1+rD0);
          SetMem(insn, insn.Op2, 2, dt_byte);
          break;

        // mov (abs), Dn
        case 0x08:
          insn.itype = mn102_mov;
          SetReg(insn.Op2,R1+rD0);
          SetMem(insn, insn.Op1, 2, dt_word);
          break;

        // movbu (abs), Dn
        case 0x0C:
          insn.itype = mn102_movbu;
          SetReg(insn.Op2,R1+rD0);
          SetMem(insn, insn.Op1, 2, dt_byte);
          break;
      }
      break;
    // add/cmp,mov
    case 0x0D:
      switch ( code&0xC )
      {
        // add imm8, An
        case 0x00:
          SetReg(insn.Op2,R1+rA0);
          insn.itype = mn102_add;
          SetImm(insn, insn.Op1, 1);
          break;

        // add imm8, Dn
        case 0x04:
          SetReg(insn.Op2,R1+rD0);
          insn.itype = mn102_add;
          SetImm(insn, insn.Op1, 1);
          break;

        //  cmp imm8, Dn
        case 0x08:
          SetReg(insn.Op2,R1+rD0);
          insn.itype = mn102_cmp;
          SetImm(insn, insn.Op1, 1);
          break;

        // mov  imm16, An
        case 0x0c:
          SetReg(insn.Op2,R1+rA0);
          insn.itype = mn102_mov;
          SetImm(insn, insn.Op1, 2);
          insn.Op1.specflag1 = URB_ADDR;
          break;
      }
      break;

    // Jmps
    case 0x0E:
      {
        static const uchar Cmd[16] =
        {
          mn102_blt,mn102_bgt,mn102_bge,mn102_ble,
          mn102_bcs,mn102_bhi,mn102_bcc,mn102_bls,
          mn102_beq,mn102_bne,mn102_bra,mn102_rti,
          mn102_cmp,mn102_cmp,mn102_cmp,mn102_cmp
        };
        insn.itype = Cmd[code&0xF];
        switch ( insn.itype )
        {
          // rti
          case mn102_rti:
            break;
          // cmp imm16, An
          case mn102_cmp:
            SetReg(insn.Op2,R1+rA0);
            SetImm(insn, insn.Op1, 2);
            break;
          // jmps
          default:
            SetLabel(insn, insn.Op1,1);
            break;
        }
        break;
      }
    // ExtCodes
    case 0x0F:
      switch ( code & 0xF )
      {
        // F0 set
        case 0x00:
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;
          switch ( code&0xC0 )
          {
            // complex set
            case 0x00:
              switch ( code&0x30 )
              {
                // one more set
                case 0x00:
                  if ( code & 2 )
                    return 0;
                  SetRReg(insn.Op1,R2+rA0);
                  if ( code & 1 )
                    insn.itype = mn102_jsr;
                  else
                    insn.itype = mn102_jmp;
                  break;
                case 0x10:
                  return 0;
                case 0x20:
                  insn.itype = mn102_bset;
                  SetReg(insn.Op1,R1+rD0);
                  SetRReg(insn.Op2,R2+rA0);
                  break;
                case 0x30:
                  insn.itype = mn102_bclr;
                  SetReg(insn.Op1,R1+rD0);
                  SetRReg(insn.Op2,R2+rA0);
                  break;
              }
              break;

            // movb (Di,An), Dm
            case 0x40:
              insn.itype = mn102_movb;
              SetReg(insn.Op2,R1+rD0);
              SetDisplI(insn.Op1,R2+rA0,code>>4);
              break;
            // movbu (Di,An), Dm
            case 0x80:
              insn.itype = mn102_movbu;
              SetReg(insn.Op2,R1+rD0);
              SetDisplI(insn.Op1,R2+rA0,code>>4);
              break;
            // movb Dm, (Di, An)
            case 0xC0:
              insn.itype = mn102_movb;
              SetReg(insn.Op1,R1+rD0);
              SetDisplI(insn.Op2,R2+rA0,code>>4);
              break;
          }
          break;
        // F1 set
        case 0x01:
          insn.itype = mn102_mov;
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;
          switch ( code&0xC0 )
          {
            // mov (Di, An), Am
            case 0x00:
              SetReg(insn.Op2,R1+rA0);
              SetDisplI(insn.Op1,R2+rA0, code>>4);
              break;

            // mov (Di,An), Dm
            case 0x40:
              SetReg(insn.Op2,R1+rD0);
              SetDisplI(insn.Op1,R2+rA0, code>>4);
              break;

            // mov Am, (Di, An)
            case 0x80:
              SetReg(insn.Op1,R1+rD0);
              SetDisplI(insn.Op2,R2+rA0, code>>4);
              break;

            // mov Dm, (Di, An);
            case 0xC0:
              SetReg(insn.Op1,R1+rD0);
              SetDisplI(insn.Op2,R2+rA0, code>>4);
              break;
          }
          break;
        // F2 set
        case 0x02:
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;
          {
            static const uchar Cmd[16] =
            {
              mn102_add,  mn102_sub,  mn102_cmp, mn102_mov,
              mn102_add,  mn102_sub,  mn102_cmp, mn102_mov,
              mn102_addc, mn102_subc, 0,         0,
              mn102_add,  mn102_sub,  mn102_cmp, mn102_mov
            };
            insn.itype = Cmd[code>>4];
            if ( insn.itype == 0 )
              return 0;
            switch ( code&0xC0 )
            {
              case 0x00:
                SetReg(insn.Op1,R2+rD0);
                SetReg(insn.Op2,R1+rA0);
                break;

              case 0x40:
                SetReg(insn.Op1,R2+rA0);
                SetReg(insn.Op2,R1+rA0);
                break;

              case 0x80:
                SetReg(insn.Op1,R2+rD0);
                SetReg(insn.Op2,R1+rD0);
                break;

              case 0xC0:
                SetReg(insn.Op1,R2+rA0);
                SetReg(insn.Op2,R1+rD0);
                break;
            }
          }
          break;
        // F3 set
        case 0x03:
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;
          SetReg(insn.Op1,R2+rD0);
          SetReg(insn.Op2,R1+rD0);
          {
            static const uchar Cmd[16] =
            {
              mn102_and, mn102_or,   mn102_xor,  mn102_rol,
              mn102_mul, mn102_mulu, mn102_divu, 0,
              0,         mn102_cmp,  0,          0,
              mn102_ext, mn102_mov,  mn102_not,  255
            };
            insn.itype = Cmd[code>>4];
            switch ( insn.itype )
            {
              // bad opcode
              case 0:
                return 0;
              // shifts
              case mn102_rol:
                SetReg(insn.Op1,R1+rD0);
                insn.Op2.type = o_void;
                {
                  static const uchar Cmd2[4] =
                  {
                    mn102_rol,mn102_ror,mn102_asr,mn102_lsr
                  };
                  insn.itype = Cmd2[(code>>2)&3];
                }
                break;
              case mn102_ext:
                if ( code & 2 )
                  return 0;
                if ( code & 1 )
                {
                  insn.Op2.type = o_void;
                }
                else
                {
                  insn.itype = mn102_mov;
                  SetReg(insn.Op2,rMDR);
                }
                break;

              case mn102_mov:
                if ( R1 != 0 )
                  return 0;
                SetReg(insn.Op2,rPSW);
                break;

              case mn102_not:
                switch ( R2 )
                {
                  case 0:
                    insn.itype = mn102_mov;
                    SetReg(insn.Op1,rMDR);
                    break;
                  case 1:
                    insn.Op2.type = o_void;
                    SetReg(insn.Op1,R1+rD0);
                    break;
                  default:
                    return 0;
                }
                break;

              case 255:
                switch ( R2 )
                {
                  case 0:
                    insn.itype = mn102_mov;
                    SetReg(insn.Op1,rPSW);
                    break;
                  case 3:
                    insn.Op2.type = insn.Op1.type = o_void;
                    switch ( R1 )
                    {
                      case 0:
                        insn.itype = mn102_pxst;
                        break;
                      // F3, FE
                      case 2:
                        {
                          static const uchar lCmd[4] =
                          {
                            mn102_tbz, mn102_tbnz, mn102_bset, mn102_bclr
                          };
                          code = insn.get_next_byte();
                          if ( code < 0xC0 || code >= 0xE0 )
                            return 0;
                          insn.itype = lCmd[(code>>3)&3];
                          SetImmC(insn.Op1,1<<(code&7));
                          SetMem(insn, insn.Op2, 3, dt_byte);
                          // if jump, use label
                          if ( (code&0xF0) == 0xC0 )
                            SetLabel(insn, insn.Op3, 1);
                        }
                        break;
                      // F3, FF
                      case 3:
                        {
                          static const uchar lCmd[4] =
                          {
                            mn102_tbz, mn102_bset, mn102_tbnz, mn102_bclr
                          };
                          code = insn.get_next_byte();
                          if ( code < 0x80 || code >= 0xC0 )
                            return 0;
                          insn.itype = lCmd[(code>>4)&3];
                          SetImmC(insn.Op1,1<<(code&7));
                          SetDispl(insn, insn.Op2,(code&0x8)?rA3:rA2, 1);
                          insn.Op3.dtype = dt_byte;
                          // if jump, use label
                          if ( (code & 0x10) == 0 )
                            SetLabel(insn, insn.Op3, 1);
                        }
                        break;
                      default:
                        return 0;
                    }
                    break;
                  default:
                    return 0;
                }
                break;
              // the rest does not need processing
              default:
                break;
            }
          }
          break;

        // F4 set - 5 bytes
        case 0x04:
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;

          switch ( code&0xF0 )
          {
            // mov Dm, (D24,An)
            case 0x00:
              insn.itype = mn102_mov;
              SetReg(insn.Op1,R1+rD0);
              SetDispl(insn, insn.Op2,R2+rA0,3);
              break;

            case 0x10:
              insn.itype = mn102_mov;
              SetReg(insn.Op1,R1+rA0);
              SetDispl(insn, insn.Op2,R2+rA0,3);
              break;

            case 0x20:
              insn.itype = mn102_movb;
              SetReg(insn.Op1,R1+rD0);
              SetDispl(insn, insn.Op2,R2+rA0,3);
              break;

            case 0x30:
              insn.itype = mn102_movx;
              SetReg(insn.Op1,R1+rD0);
              SetDispl(insn, insn.Op2,R2+rA0,3);
              break;

            case 0x40:
              switch ( R2 )
              {
                case 0:
                  insn.itype = mn102_mov;
                  SetMem(insn, insn.Op2,3,dt_dword);
                  SetReg(insn.Op1,R1+rD0);
                  break;

                case 1:
                  insn.itype = mn102_movb;
                  SetMem(insn, insn.Op2,3,dt_byte);
                  SetReg(insn.Op1,R1+rD0);
                  break;

                default:
                  if ( code != 0x4B && code != 0x4F )
                    return 0;
                  insn.itype = code == 0x4B ? mn102_bset : mn102_bclr;
                  SetMem(insn, insn.Op2,3,dt_byte);
                  SetImm(insn, insn.Op1,1);
                  break;
              }
              break;

            case 0x50:
              if ( R2 != 0 )
                return 0;
              insn.itype = mn102_mov;
              SetReg(insn.Op1,R1+rA0);
              SetMem(insn, insn.Op1,3,dt_tbyte);
              break;

            case 0x60:
              SetImm(insn, insn.Op1,3);
              SetReg(insn.Op2, R1+((R2&1)?rA0:rD0));
              insn.itype = (R2&2)?mn102_sub:mn102_add;
              break;

            case 0x70:
              SetImm(insn, insn.Op1,3);
              insn.Op1.specflag1 = URB_ADDR;
              SetReg(insn.Op2,R1+((R2&1)?rA0:rD0));
              insn.itype = (R2&2)?mn102_cmp:mn102_mov;
              break;

            case 0x80:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op1,R2+rA0,3);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0x90:
              insn.itype = mn102_movbu;
              SetDispl(insn, insn.Op1,R2+rA0,3);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0xA0:
              insn.itype = mn102_movb;
              SetDispl(insn, insn.Op1,R2+rA0,3);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0xB0:
              insn.itype = mn102_movx;
              SetDispl(insn, insn.Op1,R2+rA0,3);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0xC0:
              SetReg(insn.Op2,R1+rD0);
              switch ( R2 )
              {
                case 0:
                  insn.itype = mn102_mov;
                  SetMem(insn, insn.Op1,3,dt_word);
                  break;

                case 1:
                  insn.itype = mn102_movb;
                  SetMem(insn, insn.Op1,3,dt_byte);
                  break;

                case 2:
                  insn.itype = mn102_movbu;
                  SetMem(insn, insn.Op1,3,dt_byte);
                  break;

                default:
                  return 0;
              }
              break;

            case 0xD0:
              if ( R2 != 0 )
                return 0;
              insn.itype = mn102_mov;
              SetMem(insn, insn.Op1,3,dt_tbyte);
              SetReg(insn.Op2,R1+rA0);
              break;

            case 0xE0:
              switch ( code )
              {
                case 0xE0:
                  insn.itype = mn102_jmp;
                  SetLabel(insn, insn.Op1,3);
                  break;

                case 0xE1:
                  insn.itype = mn102_jsr;
                  SetLabel(insn, insn.Op1,3);
                  break;

                case 0xE3:
                case 0xE7:
                  insn.itype = (code == 0xE3) ? mn102_bset : mn102_bclr;
                  SetMem(insn, insn.Op2,2,dt_byte);
                  SetImmC(insn.Op1,1);
                  break;

                default:
                  if ( code < 0xE8 )
                    return 0;
                  insn.itype = (code&0x4)?mn102_bclr:mn102_bset;
                  SetImmC(insn.Op1,1);
                  SetDispl(insn, insn.Op2,rA0+(code&3),1);
                  break;
              }
              break;

            case 0xF0:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op1,R2+rA0,3);
              SetReg(insn.Op2,R1+rA0);
              break;
          }
          break;
        // F5 set
        case 0x05:
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;
          switch ( code&0xF0 )
          {
            case 0x00:
              {
                static const uchar Cmd[4] =
                {
                  mn102_and, mn102_btst, mn102_or, mn102_addnf
                };
                SetImm(insn, insn.Op1,1);
                SetReg(insn.Op2,R1+rD0);
                insn.itype = Cmd[R2];
              }
              break;
            // movb Dm,(d8,An)
            case 0x10:
              insn.itype = mn102_movb;
              SetReg(insn.Op1,R1+rD0);
              SetDispl(insn, insn.Op2,R2+rA0,1);
              break;

            // movb (d8,An), Dm
            case 0x20:
              insn.itype = mn102_movb;
              SetReg(insn.Op2,R1+rD0);
              SetDispl(insn, insn.Op1,R2+rA0,1);
              break;

            // movbu (d8,An), Dm
            case 0x30:
              insn.itype = mn102_movbu;
              SetReg(insn.Op2,R1+rD0);
              SetDispl(insn, insn.Op1,R2+rA0,1);
              break;

            // mulql dn, dm
            case 0x40:
              code = insn.get_next_byte();
              if ( code > 1 )
                return 0;
              insn.itype = (code == 0) ? mn102_mulql : mn102_mulqh;
              SetReg(insn.Op1,R2+rD0);
              SetReg(insn.Op2,R1+rD0);
              break;

            // movx Dm, (d8,An)
            case 0x50:
              insn.itype = mn102_movx;
              SetReg(insn.Op1,R1+rD0);
              SetDispl(insn, insn.Op2,R2+rA0,1);
              break;

            // mulq dn, dm
            case 0x60:
              code = insn.get_next_byte();
              if ( code != 0x10 )
                return 0;
              insn.itype = mn102_mulq;
              SetReg(insn.Op1,R2+rD0);
              SetReg(insn.Op2,R1+rD0);
              break;

            // movx (d8,An), Dm
            case 0x70:
              insn.itype = mn102_movx;
              SetDispl(insn, insn.Op1,R2+rA0,1);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0x80:
            case 0x90:
            case 0xA0:
            case 0xB0:
              {
                static const uchar Cmd[4] =
                {
                  mn102_tbz, mn102_bset, mn102_tbnz, mn102_bclr
                };
                insn.itype = Cmd[(code>>4)&3];
                SetImmC(insn.Op1,1<<(code&7));
                SetDispl(insn, insn.Op2,(code&0x8)?rA1:rA0,1);
                if ( (code & 0x10) == 0 )
                  SetLabel(insn, insn.Op3, 1);
              }
              break;
            case 0xC0:
            case 0xD0:
              {
                static const uchar Cmd[4] =
                {
                  mn102_tbz, mn102_tbnz, mn102_bset, mn102_bclr
                };
                insn.itype = Cmd[(code>>3)&3];
                SetImmC(insn.Op1,1<<(code&7));
                SetMem(insn, insn.Op2,2,dt_byte);
                if ( (code & 0x10) == 0 )
                  SetLabel(insn, insn.Op3, 1);
              }
              break;

            case 0xE0:
              {
                static const uchar Cmd[16] =
                {
                  mn102_bltx,mn102_bgtx,mn102_bgex,mn102_blex,
                  mn102_bcsx,mn102_bhix,mn102_bccx,mn102_blsx,
                  mn102_beqx,mn102_bnex,0,0,
                  mn102_bvcx,mn102_bvsx,mn102_bncx,mn102_bnsx
                };
                insn.itype = Cmd[code&0xF];
                if ( insn.itype == 0 )
                  return 0;
                SetLabel(insn, insn.Op1,1);
              }
              break;
            case 0xF0:
              if ( code < 0xFC && code > 0xF8 )
                return 0;
              if ( code >= 0xFC )
              {
                static const uchar Cmd[4] =
                {
                  mn102_bvc, mn102_bvs, mn102_bnc, mn102_bns
                };
                insn.itype = Cmd[R1];
                SetLabel(insn, insn.Op1, 1);
              }
              else
              {
                code = insn.get_next_byte();
                switch ( code )
                {
                  case 0x4:
                    insn.itype = mn102_mulql;
                    SetImm(insn, insn.Op1,1);
                    SetReg(insn.Op2,R1+rD0);
                    break;
                  case 0x5:
                    insn.itype = mn102_mulqh;
                    SetImm(insn, insn.Op1,1);
                    SetReg(insn.Op2,R1+rD0);
                    break;
                  case 0x8:
                    insn.itype = mn102_mulql;
                    SetImm(insn, insn.Op1,2);
                    SetReg(insn.Op2,R1+rD0);
                    break;
                  case 0x9:
                    insn.itype = mn102_mulqh;
                    SetImm(insn, insn.Op1,2);
                    SetReg(insn.Op2,R1+rD0);
                    break;
                  default:
                    return 0;
                }
              }
              break;
            default:
              return 0;
          }
          break;

        // NOP
        case 0x06:
          insn.itype = mn102_nop;
          break;

        // F7 set
        case 0x07:
          code = insn.get_next_byte();
          R1 = (code&3);
          R2 = (code>>2)&3;
          switch ( code&0xF0 )
          {
            case 0x00:
              {
                static const uchar Cmd[4] =
                {
                  mn102_and, mn102_btst, mn102_add, mn102_sub
                };

                SetImm(insn, insn.Op1,2);
                SetReg(insn.Op2,R1+((R2&2)?rA0:rD0));
                insn.itype = Cmd[R2];
              }
              break;

            case 0x10:
              switch ( R2 )
              {
                case 0:
                  if ( R1 != 0 )
                    return 0;
                  insn.itype = mn102_and;
                  SetReg(insn.Op2,rPSW);
                  break;

                case 1:
                  if ( R1 != 0 )
                    return 0;
                  insn.itype = mn102_or;
                  SetReg(insn.Op2,rPSW);
                  break;

                case 2:
                  insn.itype = mn102_add;
                  SetReg(insn.Op2,R1+rD0);
                  break;

                case 3:
                  insn.itype = mn102_sub;
                  SetReg(insn.Op2,R1+rD0);
                  break;
              }
              SetImm(insn, insn.Op1,2);
              break;

            case 0x20:
              if ( R2 != 0 )
                return 0;
              insn.itype = mn102_mov;
              SetReg(insn.Op1,R1+rA0);
              SetMem(insn, insn.Op2,2,dt_tbyte);
              break;

            case 0x30:
              if ( R2 != 0 )
                return 0;
              insn.itype = mn102_mov;
              SetReg(insn.Op2,R1+rA0);
              SetMem(insn, insn.Op1,2,dt_tbyte);
              break;

            case 0x40:
              {
                static const uchar Cmd[4] =
                {
                  mn102_or, 0, mn102_cmp, mn102_xor
                };
                insn.itype = Cmd[R2];
                if ( insn.itype == 0 )
                  return 0;
                SetImm(insn, insn.Op1,2);
                SetReg(insn.Op2,R1+rD0);
              }
              break;

            case 0x50:
              insn.itype = mn102_movbu;
              SetDispl(insn, insn.Op1,R2+rA0,2);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0x60:
              insn.itype = mn102_movx;
              SetDispl(insn, insn.Op2,R2+rA0,2);
              SetReg(insn.Op1,R1+rD0);
              break;

            case 0x70:
              insn.itype = mn102_movx;
              SetDispl(insn, insn.Op1,R2+rA0,2);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0x80:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op2,R2+rA0,2);
              SetReg(insn.Op1,R1+rD0);
              break;

            case 0x90:
              insn.itype = mn102_movb;
              SetDispl(insn, insn.Op2,R2+rA0,2);
              SetReg(insn.Op1,R1+rD0);
              break;

            case 0xA0:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op2,R2+rA0,2);
              SetReg(insn.Op1,R1+rA0);
              break;

            case 0xB0:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op1,R2+rA0,2);
              SetReg(insn.Op2,R1+rA0);
              break;

            case 0xC0:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op1,R2+rA0,2);
              SetReg(insn.Op2,R1+rD0);
              break;

            case 0xD0:
              insn.itype = mn102_mov;
              SetDispl(insn, insn.Op1,R2+rA0,2);
              SetReg(insn.Op2,R1+rD0);
              break;

            default:
              return 0;
          }
          break;

        // mov imm16, Dn
        case 0x08:
        case 0x09:
        case 0x0A:
        case 0x0B:
          SetReg(insn.Op2,R1+rD0);
          SetImm(insn, insn.Op1, 2);
          insn.itype = mn102_mov;
          break;

        // jmp label16
        case 0x0C:
          insn.itype = mn102_jmp;
          SetLabel(insn, insn.Op1,2);
          break;

        // jsr label16
        case 0x0D:
          insn.itype = mn102_jsr;
          SetLabel(insn, insn.Op1,2);
          break;

        // rts
        case 0x0E:
          insn.itype = mn102_rts;
          break;

        // illegal code
        case 0x0F:
          return 0;
      }
      break;
  }
  return insn.size;
}
