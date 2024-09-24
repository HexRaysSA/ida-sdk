/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *      Microchip's PIC
 *
 */

#include "pic.hpp"
#include <segregs.hpp>

#define PIC18_IP_RANGE 0x1FFFFF

//-------------------------------------------------------------------------
// it can replace one instruction with another without changing its size
void pic_t::simplify(insn_t &insn) const
{
  switch ( insn.itype )
  {
    // movfw   macro   f       ; Move Contents of File Reg to W
    //      movf    f,0
    //      endm
    // tstf    macro   f       ; Test Contents of File Register
    //      movf    f,1
    //      endm
    case PIC_movf:
      insn.itype = (insn.Op2.reg == W) ? PIC_movfw : PIC_tstf;
      insn.Op2.type = o_void;
      break;

    // b       macro   k       ; Branch to Address
    //      goto    k
    //      endm
    case PIC_goto:
      insn.itype = PIC_b;
      break;

    // clrc    macro           ; Clear Carry
    //      bcf     3,0
    //      endm
    // clrdc   macro           ; Clear Digit Carry
    //      bcf     3,1
    //      endm
    // clrz    macro           ; Clear Zero
    //      bcf     3,2
    //      endm
    case PIC_bcf:
      if ( is_bank(insn) ) switch ( insn.Op2.value )
      {
        case 0: insn.itype = PIC_clrc;  goto NOOP;
        case 1: insn.itype = PIC_clrdc; goto NOOP;
        case 2: insn.itype = PIC_clrz;  goto NOOP;
NOOP:
          insn.Op1.type = o_void;
          insn.Op2.type = o_void;
          break;
      }
      break;

    // setc    macro           ; Set Carry
    //      bsf     3,0
    //      endm
    // setdc   macro           ; Set Digit Carry
    //      bsf     3,1
    //      endm
    // setz    macro           ; Set Zero
    //      bcf     3,2
    //      endm
    case PIC_bsf:
      if ( is_bank(insn) ) switch ( insn.Op2.value )
      {
        case 0: insn.itype = PIC_setc;  goto NOOP;
        case 1: insn.itype = PIC_setdc; goto NOOP;
        case 2: insn.itype = PIC_setz;  goto NOOP;
      }
      break;

    // skpnc   macro           ; Skip on No Carry
    //      btfsc   3,0
    //      endm
    // skpndc  macro           ; Skip on No Digit Carry
    //      btfsc   3,1
    //      endm
    // skpnz   macro           ; Skip on No Zero
    //      btfsc   3,2
    //      endm
    case PIC_btfsc:
      if ( is_bank(insn) ) switch ( insn.Op2.value )
      {
        case 0: insn.itype = PIC_skpnc;  goto NOOP;
        case 1: insn.itype = PIC_skpndc; goto NOOP;
        case 2: insn.itype = PIC_skpnz;  goto NOOP;
      }
      break;

    // skpc    macro           ; Skip on Carry
    //      btfss   3,0
    //      endm
    // skpdc   macro           ; Skip on Digit Carry
    //      btfss   3,1
    //      endm
    // skpz    macro           ; Skip on Zero
    //      btfss   3,2
    //      endm
    case PIC_btfss:
      if ( is_bank(insn) ) switch ( insn.Op2.value )
      {
        case 0: insn.itype = PIC_skpc;  goto NOOP;
        case 1: insn.itype = PIC_skpdc; goto NOOP;
        case 2: insn.itype = PIC_skpz;  goto NOOP;
      }
      break;
  }
}

//-------------------------------------------------------------------------
// it returns true if the size of the instruction is changed
// INSN must be simplified
bool pic_t::build_macro(insn_t &insn, bool may_go_forward)
{
  if ( !may_go_forward )
    return false;
  switch ( insn.itype )
  {
    // negf    macro   f,d     ; Negate File Register Contents
    //      comf    f,1
    //      incf    f,d
    //      endm
    case PIC_comf:
      if ( insn.Op2.reg == F )
      {
        insn_t incf;
        if ( decode_insn(&incf, insn.ea + insn.size) > 0
          && incf.itype == PIC_incf
          && incf.Op1.type == o_mem
          && incf.Op1.addr == insn.Op1.addr )
        {
          insn.itype = PIC_negf;
          insn.Op2.reg = incf.Op2.reg;
          insn.size += incf.size;
          return true;
        }
      }
      break;

    // bnc     macro   k       ; Branch on No Carry to k
    //      skpc
    //      goto    k
    //      endm
    // bndc    macro   k       ; Branch on No Digit Carry to k
    //      skpdc
    //      goto    k
    //      endm
    // bnz     macro   k       ; Branch on No Zero to Address
    //      skpz
    //      goto    k
    //      endm
    // bc      macro   k       ; Branch on Carry to Address k
    //      skpnc
    //      goto    k
    //      endm
    // bdc     macro   k       ; Branch on Digit Carry to k
    //      skpndc
    //      goto    k
    //      endm
    // bz      macro   k       ; Branch on Zero to Address k
    //      skpnz
    //      goto    k
    //      endm
    // addcf   macro   f,d     ; Add Carry to File Register
    //      skpnc
    //      incf    f,d
    //      endm
    // adddcf  macro   f,d     ; Add Digit to File Register
    //      skpndc
    //      incf    f,d
    //      endm
    // subcf   macro   f,d     ; Subtract Carry from File Reg
    //      skpnc
    //      decf    f,d
    //      endm
    case PIC_skpnc:
    case PIC_skpndc:
    case PIC_skpnz:
    case PIC_skpc:
    case PIC_skpdc:
    case PIC_skpz:
      {
        insn_t ins2;
        if ( decode_insn(&ins2, insn.ea + insn.size) == 0 )
          break;
        if ( ins2.itype == PIC_b )
        {
          insn.itype = insn.itype == PIC_skpc   ? PIC_bnc
                     : insn.itype == PIC_skpdc  ? PIC_bndc
                     : insn.itype == PIC_skpz   ? PIC_bnz
                     : insn.itype == PIC_skpnc  ? PIC_bc
                     : insn.itype == PIC_skpndc ? PIC_bdc
                     :                            PIC_bz;
          insn.Op1  = ins2.Op1;
          insn.size += ins2.size;
          return true;
        }
        if ( ins2.itype == PIC_incf || ins2.itype == PIC_decf )
        {
          if ( insn.itype == PIC_skpnc && ins2.itype == PIC_incf )
            insn.itype = PIC_addcf;
          else if ( insn.itype == PIC_skpndc && ins2.itype == PIC_incf )
            insn.itype = PIC_adddcf;
          else if ( insn.itype == PIC_skpnc && ins2.itype == PIC_decf )
            insn.itype = PIC_subcf;
          else
            break;
          insn.Op1 = ins2.Op1;
          insn.Op2 = ins2.Op2;
          insn.size += ins2.size;
          return true;
        }
      }
      break;
  }
  return false;
}

//--------------------------------------------------------------------------
struct pic_mctr_t : public macro_constructor_t
{
  pic_t &pm;
  pic_mctr_t(pic_t &_pm) : pm(_pm) {}
  bool idaapi build_macro(insn_t *insn, bool may_go_forward) override
  {
    return pm.build_macro(*insn, may_go_forward);
  }
};

//--------------------------------------------------------------------------
int pic_t::ana(insn_t *_insn)
{
  if ( _insn == nullptr )
    return 0;
  insn_t &insn = *_insn;
  int len = basic_ana(insn);
  if ( len == 0 )
    return len;

  if ( dosimple() )
    simplify(insn);

  pic_mctr_t mctr(*this);
  mctr.construct_macro(&insn, ph.supports_macros() && inf_macros_enabled());

  // if the instruction is too long, recreate it:
  /*if ( insn.size == 1 && is_tail(get_flags(insn.ea+1)) )
  {
    auto_make_code(insn.ea);
    auto_make_code(insn.ea+1);
    ea_t saved = insn.ea;
    del_items(insn.ea, DELIT_SIMPLE);    // destroys insn.ea
    insn.ea = saved;
  }*/
  return insn.size;
}

//--------------------------------------------------------------------------
static void opf12(insn_t &insn, int code)
{
  insn.Op1.type = o_mem;
  insn.Op1.dtype = dt_byte;
  sel_t v = get_sreg(insn.ea, BANK);
  if ( v == BADSEL )
    v = 0;
  insn.Op1.addr = (code & 0x1F) | (v << 5);
}

//--------------------------------------------------------------------------
static void opf14(insn_t &insn, int code)
{
  insn.Op1.type = o_mem;
  insn.Op1.dtype = dt_byte;
  sel_t v = get_sreg(insn.ea, BANK);
  if ( v == BADSEL )
    v = 0;
  insn.Op1.addr = (code & 0x7F) | (v << 7);
}

//--------------------------------------------------------------------------
static void opfa16(insn_t &insn, int code)
{
  insn.Op1.type = o_mem;
  insn.Op1.dtype = dt_byte;
  if ( code & 0x0100 ) // if a == 1 (BSR)
  {
    sel_t v = get_sreg(insn.ea, BANK);
    if ( v == BADSEL )
      v = 0;
    insn.Op1.addr = (v << 8) | (code & 0xFF);
  }
  else                 // if a == 0 (access bank)
  {
    insn.Op1.addr = code & 0xFF;
    // The first 128 bytes are General Purpose
    // RAM(from Bank 0).
    // The second 128 bytes are Special
    // Function Registers(from Bank 15).
    if ( insn.Op1.addr >= 128 )
      insn.Op1.addr = (15<<8) + insn.Op1.addr;
  }
}

//--------------------------------------------------------------------------
static void basic_ana12(insn_t &insn, int code)
{
  int b4;

  switch ( code >> 10 )
  {
    case 0:
// 0000 0100 0000 CLRW                   Clear W
// 0000 0000 0000 NOP                    No Operation
// 0000 0000 0100 CLRWDT                 Clear Watchdog Timer
// 0000 0000 0010 OPTION                 Load OPTION register
// 0000 0000 0011 SLEEP                  Go into standby mode
      if ( code == 0x040 )
        insn.itype = PIC_clrw;
      else if ( code == 0x000 )
        insn.itype = PIC_nop;
      else if ( code == 0x004 )
        insn.itype = PIC_clrwdt;
      else if ( code == 0x002 )
        insn.itype = PIC_option;
      else if ( code == 0x003 )
        insn.itype = PIC_sleep;
      else if ( ( code & 0xFF8 ) == 0 )
      {
// 0000 0000 0fff TRIS    f (4<f<8)      Load TRIS Register
        insn.itype = PIC_tris;
        opf12(insn, code);
      }
      else if ( ( code & 0xF80 ) == 0 )
// 0000 001f ffff MOVWF   f              Move W to f
// 0000 011f ffff CLRF    f              Clear f
      {
        static const ushort codes[4] =
        {
          PIC_null, PIC_movwf, PIC_null, PIC_clrf
        };
        insn.itype = codes[(code>>5)&3];
        opf12(insn, code);
      }
      else
      {
// 0000 10df ffff SUBWF   f, d           Subtract W from f
// 0000 11df ffff DECF    f, d           Decrement f
// 0001 00df ffff IORWF   f, d           Inclusive OR W with f
// 0001 01df ffff ANDWF   f, d           AND W with f
// 0001 10df ffff XORWF   f, d           Exclusive OR W with f
// 0001 11df ffff ADDWF   f, d           Add W and f
// 0010 00df ffff MOVF    f, d           Move f
// 0010 01df ffff COMF    f, d           Complement f
// 0010 10df ffff INCF    f, d           Increment f
// 0010 11df ffff DECFSZ  f, d           Decrement f, Skip if 0
// 0011 00df ffff RRF     f, d           Rotate Right f through Carry
// 0011 01df ffff RLF     f, d           Rotate Left f through Carry
// 0011 10df ffff SWAPF   f, d           Swap nibbles in f
// 0011 11df ffff INCFSZ  f, d           Increment f, Skip if 0
        b4 = code >> 6;
        static const ushort codes[16] =
        {
          PIC_null,  PIC_null,  PIC_subwf, PIC_decf,
          PIC_iorwf, PIC_andwf, PIC_xorwf, PIC_addwf,
          PIC_movf,  PIC_comf,  PIC_incf,  PIC_decfsz,
          PIC_rrf,   PIC_rlf,   PIC_swapf, PIC_incfsz
        };
        insn.itype = codes[b4];
        opf12(insn, code);
        insn.Op2.type = o_reg;
        insn.Op2.reg = (code & 0x20) ? F : W;
        insn.Op2.dtype = dt_byte;
      }
      break;
    case 1:
// 0100 bbbf ffff BCF     f, b           Bit Clear f
// 0101 bbbf ffff BSF     f, b           Bit Set f
// 0110 bbbf ffff BTFSC   f, b           Bit Test f, Skip if Clear
// 0111 bbbf ffff BTFSS   f, b           Bit Test f, Skip if Set
      {
        static const ushort codes[4] =
        {
          PIC_bcf, PIC_bsf, PIC_btfsc, PIC_btfss
        };
        insn.itype = codes[(code>>8)&3];
        opf12(insn, code);
        insn.Op2.type  = o_imm;
        insn.Op2.value = (code >> 5) & 7;
        insn.Op2.dtype = dt_byte;
      }
      break;
    case 2:
      b4 = (code >> 8) & 0x3;
      switch ( b4 )
      {
        case 0:
// 1000 kkkk kkkk RETLW   k              Return with literal in W
          insn.itype = PIC_retlw;
          insn.Op1.type  = o_imm;
          insn.Op1.value = code & 0xFF;
          insn.Op1.dtype = dt_byte;
          break;
        case 1:
// 1001 kkkk kkkk CALL    k              Call subroutine
          {
            // old databases used status reg (PCLATH) for hight bit of the address
            // new code uses BANK for that
            // so we get both and try to guess
            sel_t status = get_sreg(insn.ea, PCLATH);
            sel_t bank = get_sreg(insn.ea, BANK);
            if ( (status != BADSEL && status != 0) && (bank == BADSEL || bank == 0) )
              bank = (status >> 5) & 3;
            insn.itype = PIC_call;
            insn.Op1.type = o_near;
            insn.Op1.addr = (bank << 9) | (code & 0xFF);
            insn.Op1.dtype = dt_code;
          }
          break;
        default:
// 101k kkkk kkkk GOTO    k              Go to address
          {
            sel_t status = get_sreg(insn.ea, PCLATH);
            sel_t bank = get_sreg(insn.ea, BANK);
            if ( (status != BADSEL && status != 0) && (bank == BADSEL || bank == 0) )
              bank = (status >> 5) & 3;
            insn.itype = PIC_goto;
            insn.Op1.type = o_near;
            insn.Op1.addr = (bank << 9) | (code & 0x1FF);
            insn.Op1.dtype = dt_code;
          }
          break;
      }
      break;
    case 3:
// 1100 kkkk kkkk MOVLW   k              Move literal to W
// 1101 kkkk kkkk IORLW   k              Inclusive OR literal with W
// 1110 kkkk kkkk ANDLW   k              AND literal with W
// 1111 kkkk kkkk XORLW   k              Exclusive OR literal with W
      {
        static const ushort codes[4] =
        {
          PIC_movlw, PIC_iorlw, PIC_andlw, PIC_xorlw
        };
        insn.itype = codes[(code>>8)&3];
        insn.Op1.type  = o_imm;
        insn.Op1.value = (uchar)code;
        insn.Op1.dtype = dt_byte;
      }
      break;
  }
}

//--------------------------------------------------------------------------
int32 get_signed(int32 byte, uint32 mask)
{
  uint32 bits = mask >> 1;
  uint32 sign = bits + 1;
  if ( (byte & sign) != 0 ) // byte < 0
    byte = (byte & bits) - sign;
  else                      // byte >= 0
    byte = byte & mask;
  return byte;
}

//--------------------------------------------------------------------------
static void basic_ana14(insn_t &insn, int code)
{
  int b4 = (code >> 8) & 0xF;

  switch ( code >> 12 )
  {
    //  00 xxxx xxxx xxxx
    case 0:
      if ( b4 == 0 )  //  00 0000 xxxx xxxx
      {
        // 00 0000 1fff ffff MOVWF   f           Move W to f
        if ( (code & 0x80) != 0 )
        {
          insn.itype = PIC_movwf;
          opf14(insn, code);
          break;
        }

        //  00 0000 0001 0nmm MOVIW             Move INDFn to W
        //  00 0000 0001 1nmm MOVWI             Move W to INDFn
        if ( (code >> 4) == 1 )
        {
          insn.itype = ((code >> 3) & 1) == 0 ? PIC_moviw : PIC_movwi;
          insn.Op1.type = o_reg;
          insn.Op1.reg = ((code & 0x4) == 0) ? FSR0 : FSR1;
          insn.Op1.specflag1 = (code & 3) + 1;
          insn.Op1.dtype = dt_byte;
          break;
        }


        //  00 0000 001k kkkk MOVLB  k          Move literal to BSR
        if ( (code >> 5) == 1 )
        {
          insn.itype = PIC_movlb;
          insn.Op1.type = o_imm;
          insn.Op1.value = code & 0x1F;
          insn.Op1.dtype = dt_byte;
          break;
        }


        // 00 0000 0000 0000 NOP                 No Operation
        // 00 0000 0000 0001 RESET               Software device Reset
        // 00 0000 0000 1000 RETURN              Return from Subroutine
        // 00 0000 0000 1001 RETFIE              Return from interrupt
        // 00 0000 0000 1010 CALLW               Call Subroutine with W
        // 00 0000 0000 1011 BRW                 Relative Branch with W
        // 00 0000 0110 0010 OPTION              Load OPTION register
        // 00 0000 0110 0011 SLEEP               Go into standby mode
        // 00 0000 0110 0100 CLRWDT              Clear Watchdog Timer
        // 00 0000 0110 0fff TRIS   f (4<f<8)    Load TRIS Register
        if ( code == 0x0 )
        {
          insn.itype = PIC_nop;
        }
        else if ( code == 0x0001 )
        {
          insn.itype = PIC_reset;
        }
        else if ( code == 0x0008 )
        {
          insn.itype = PIC_return;
        }
        else if ( code == 0x000A )
        {
          insn.itype = PIC_callw;
        }
        else if ( code == 0x0009 )
        {
          insn.itype = PIC_retfie;
        }
        else if ( code == 0x000B )
        {
          insn.itype = PIC_brw;
          sel_t w = get_sreg(insn.ea, W);
          insn.Op1.type = o_near;
          insn.Op1.value = insn.ea + w + 1; // PC + W + 1
          insn.Op1.dtype = dt_code;
        }
        else if ( code == 0x0062 )
        {
          insn.itype = PIC_option;
        }
        else if ( code == 0x0063 )
        {
          insn.itype = PIC_sleep;
        }
        else if ( code == 0x0064 )
        {
          insn.itype = PIC_clrwdt;
        }
        else if ( code >= 0x0065 && code <= 0x0067 )
        {
          insn.itype = PIC_tris;
          insn.Op1.type = o_imm;
          insn.Op1.dtype = dt_byte;
          insn.Op1.value = code & 7;
        }
      }
      else if ( b4 == 1 ) // 00 0001 xxxx xxxx
      {
        // 00 0001 1fff ffff CLRF    f           Clear f
        if ( code & 0x80 )
        {
          insn.itype = PIC_clrf;
          opf14(insn, code);
        }
        // 00 0001 0xxx xxxx CLRW                Clear W
        else
        {
          insn.itype = PIC_clrw;
        }
      }
      else
      {
        // 00 0010 dfff ffff SUBWF   f, d        Subtract W from f
        // 00 0011 dfff ffff DECF    f, d        Decrement f
        // 00 0100 dfff ffff IORWF   f, d        Inclusive OR W with f
        // 00 0101 dfff ffff ANDWF   f, d        AND W with f
        // 00 0110 dfff ffff XORWF   f, d        Exclusive OR W with f
        // 00 0111 dfff ffff ADDWF   f, d        Add W and f
        // 00 1000 dfff ffff MOVF    f, d        Move f
        // 00 1001 dfff ffff COMF    f, d        Complement f
        // 00 1010 dfff ffff INCF    f, d        Increment f
        // 00 1011 dfff ffff DECFSZ  f, d        Decrement f, Skip if 0
        // 00 1100 dfff ffff RRF     f, d        Rotate Right f through Carry
        // 00 1101 dfff ffff RLF     f, d        Rotate Left f through Carry
        // 00 1110 dfff ffff SWAPF   f, d        Swap nibbles in f
        // 00 1111 dfff ffff INCFSZ  f, d        Increment f, Skip if 0
        static const ushort codes[16] =
        {
          PIC_null,  PIC_null,  PIC_subwf, PIC_decf,
          PIC_iorwf, PIC_andwf, PIC_xorwf, PIC_addwf,
          PIC_movf,  PIC_comf,  PIC_incf,  PIC_decfsz,
          PIC_rrf,   PIC_rlf,   PIC_swapf, PIC_incfsz
        };
        insn.itype = codes[b4];
        opf14(insn, code);
        insn.Op2.type = o_reg;
        insn.Op2.reg = (code & 0x80) ? F : W;
        insn.Op2.dtype = dt_byte;
      }
      break;

      // 01 xxxx xxxx xxxx
    case 1:
      // 01 00bb bfff ffff BCF     f, b        Bit Clear f
      // 01 01bb bfff ffff BSF     f, b        Bit Set f
      // 01 10bb bfff ffff BTFSC   f, b        Bit Test f, Skip if Clear
      // 01 11bb bfff ffff BTFSS   f, b        Bit Test f, Skip if Set
      {
        static const ushort codes[4] =
        {
          PIC_bcf, PIC_bsf, PIC_btfsc, PIC_btfss
        };
        insn.itype = codes[(code >> 10) & 3];
        opf14(insn, code);
        insn.Op2.type = o_imm;
        insn.Op2.value = (code >> 7) & 7;
        insn.Op2.dtype = dt_byte;
      }
      break;

    // 10 xxxx xxxx xxxx
    case 2:
      // 10 0kkk kkkk kkkk CALL    k           Call subroutine
      // 10 1kkk kkkk kkkk GOTO    k           Go to address
      {
        // Get the content of PCLATH segment register. We use a mask to keep only bits 3 et 4. (The upper bits of PC are loaded from PCLATH<4:3>.)
        sel_t pclath = get_sreg(insn.ea, PCLATH) & 0x18; // & 00011000b
        insn.itype = (code & 0x800) ? PIC_goto : PIC_call;
        insn.Op1.type = o_near;

        // We have 000x x000 for pclath and 10 1kkk kkkk kkkk for code
        // Operation :  000x x000 0000 0000 | 00 0kkk kkkk kkkk
        // Result :     000x xkkk kkkk kkkk
        insn.Op1.addr = (pclath << (11 - 3)) | (code & 0x7FF);
        insn.Op1.dtype = dt_code;
      }
      break;

    // 11 xxxx xxxx xxxx
    case 3:
      // 11 00xx kkkk kkkk MOVLW   k           Move literal to W
      // 11 0001 1kkk kkkk MOVLP   k           Move literal to PCLATH
      // 11 0001 0nkk kkkk ADDFSR  n, k        Add Literal to FSRn
      // 11 001k kkkk kkkk BRA     k           Relative Branch
      // 11 01xx kkkk kkkk RETLW   k           Return with literal in W
      // 11 0111 dfff ffff ASRF    f, d        Arithmetic Right Shift
      // 11 0101 dfff ffff LSLF    f, d        Logical Left Shift
      // 11 0110 dfff ffff LSRF    f, d        Logical Right Shift
      // 11 1000 kkkk kkkk IORLW   k           Inclusive OR literal with W
      // 11 1001 kkkk kkkk ANDLW   k           AND literal with W
      // 11 1010 kkkk kkkk XORLW   k           Exclusive OR literal with W
      // 11 1011 dfff ffff SUBWFB  f, d        Subtract W from f with Borrow
      // 11 1100 kkkk kkkk SUBLW   k           Subtract W from literal
      // 11 1101 dfff ffff ADDWFC  f, d        Add with Carry W and f
      // 11 111x kkkk kkkk ADDLW   k           Add literal and W
      // 11 1111 0nkk kkkk MOVIW   ??          Move INDFn to W
      // 11 1111 1nkk kkkk MOVWI   ??          Move W to INDFn
      {
        static const ushort codes[16] =
        {
          PIC_movlw,  PIC_movlp, PIC_bra,   PIC_bra,
          PIC_retlw,  PIC_lslf,  PIC_lsrf,  PIC_asrf,
          PIC_iorlw,  PIC_andlw, PIC_xorlw, PIC_subwfb,
          PIC_sublw, PIC_addwfc, PIC_addlw, PIC_moviw
        };
        insn.itype = codes[b4];
        switch ( insn.itype )
        {
          case PIC_movlp:
            if ( ((code >> 7) & 1) == 0 ) // 11 0001 0nkk kkkk ADDFSR
            {
              insn.itype = PIC_addfsr;
              insn.Op1.type = o_reg;
              insn.Op1.reg = ((code & 0x40) == 0) ? FSR0 : FSR1;
              insn.Op1.dtype = dt_byte;

              insn.Op2.type = o_imm;
              insn.Op2.value = get_signed(code, 0x3F);
              insn.Op2.dtype = dt_byte;
            }
            else                          // 11 0001 1kkk kkkk MOVLP
            {
              insn.itype = PIC_movlp;
              insn.Op1.type = o_imm;
              insn.Op1.value = code & 0x7F;
              insn.Op1.dtype = dt_byte;
            }
            break;

          case PIC_bra:
            insn.Op1.type = o_near;
            insn.Op1.addr = insn.ea + 1 + get_signed(code, 0x01FF); // PC + 1 + operand value
            insn.Op1.dtype = dt_code;
            break;

          case PIC_addwfc:
          case PIC_asrf:
          case PIC_lslf:
          case PIC_lsrf:
          case PIC_subwfb:
            opf14(insn, code);
            insn.Op2.type = o_reg;
            insn.Op2.reg = ( (code & 0x80) != 0) ? F : W;
            insn.Op2.dtype = dt_byte;
            break;

          case PIC_moviw:
            if ( ((code >> 7) & 1) == 0 ) // 11 1111 0nkk kkkk MOVIW
              insn.itype = PIC_moviw;
            else                          // 11 1111 1nkk kkkk MOVWI
              insn.itype = PIC_movwi;

            insn.Op1.type = o_displ;
            insn.Op1.phrase = ((code & 0x40) == 0) ? FSR0 : FSR1;
            insn.Op1.addr = get_signed(code, 0x3F);
            insn.Op1.dtype = dt_byte;
            break;

          default:
            insn.Op1.type = o_imm;
            insn.Op1.value = code & 0xFF;
            insn.Op1.dtype = dt_byte;
            break;
        }
      }
      break;
  }
}

//--------------------------------------------------------------------------
static void basic_ana16(insn_t &insn, int code)
{
  if ( ( code >> 12 ) == 0 )
  {
    int b3 = code >> 4;
    if ( b3 == 0 )
    {
// 0000 0000 0000 0000 NOP               No Operation
// 0000 0000 0000 0011 SLEEP             Go into standby mode
// 0000 0000 0000 0100 CLRWDT            Clear Watchdog Timer
// 0000 0000 0000 0101 PUSH              Push top of return stack
// 0000 0000 0000 0110 POP               Pop top of return stack
// 0000 0000 0000 0111 DAW               Decimal Adjust W
// 0000 0000 0000 1000 TBLRD*            Table Read
// 0000 0000 0000 1001 TBLRD*+           Table Read with post-increment
// 0000 0000 0000 1010 TBLRD*-           Table Read with post-decrement
// 0000 0000 0000 1011 TBLRD+*           Table Read with pre-increment
// 0000 0000 0000 1100 TBLWT*            Table Write
// 0000 0000 0000 1101 TBLWT*+           Table Write with post-increment
// 0000 0000 0000 1110 TBLWT*-           Table Write with post-decrement
// 0000 0000 0000 1111 TBLWT+*           Table Write with pre-increment
      static const ushort codes[16] =
      {
        PIC_nop,    PIC_null,    PIC_null,    PIC_sleep,
        PIC_clrwdt, PIC_push0,   PIC_pop0,    PIC_daw0,
        PIC_tblrd0, PIC_tblrd0p, PIC_tblrd0m, PIC_tblrdp0,
        PIC_tblwt0, PIC_tblwt0p, PIC_tblwt0m, PIC_tblwtp0
      };
      insn.itype = codes[code & 15];
    }
    else if ( b3 < 0x80 )
    {
      if ( ( code & 0xFFFC ) == 0x0010 )
      {
// 0000 0000 0001 000s RETFIE s          Return from interrupt enable
// 0000 0000 0001 001s RETURN s          Return from Subroutine
        insn.itype = (code & 0x2) ? PIC_return1 : PIC_retfie1;
        if ( code & 1 )
        {
          insn.Op1.type  = o_reg;
          insn.Op1.reg   = FAST;
        }
        else
        {
          insn.Op1.type  = o_imm;
          insn.Op1.value = 0;
        }
        insn.Op1.dtype = dt_byte;
      }
      else if ( code == 0x00FF )
      {
// 0000 0000 1111 1111 RESET             Software device Reset
        insn.itype = PIC_reset0;
      }
      else if ( ( code & 0xFFF0 ) == 0x0100 )
      {
// 0000 0001 0000 kkkk MOVLB  k          Move literal to BSR
        insn.itype = PIC_movlb1;
        insn.Op1.type  = o_imm;
        insn.Op1.value = code & 0xF;
        insn.Op1.dtype = dt_byte;
      }
      else if ( ( code & 0xFE00 ) == 0x0200 )
      {
// 0000 001a ffff ffff MULWF  f, a       Multiply W with f
        insn.itype = PIC_mulwf2;
        opfa16(insn, code);
        insn.Op2.type = o_reg;
        insn.Op2.reg = (code & 0x100) ? BANKED : ACCESS;
        insn.Op2.dtype = dt_byte;
      }
      else if ( ( code & 0xFC00 ) == 0x0400 )
      {
// 0000 01da ffff ffff DECF   f, d, a    Decrement f
        insn.itype = PIC_decf3;
        opfa16(insn, code);
        insn.Op2.type = o_reg;
        insn.Op2.reg = (code & 0x200) ? F : W;
        insn.Op2.dtype = dt_byte;
        insn.Op3.type = o_reg;
        insn.Op3.reg = (code & 0x100) ? BANKED : ACCESS;
        insn.Op3.dtype = dt_byte;
      }
      else
      {
        insn.itype = PIC_null;
      }
    }
    else
    {
// 0000 1000 kkkk kkkk SUBLW  k          Subtract W from literal
// 0000 1001 kkkk kkkk IORLW  k          Inclusive OR literal with W
// 0000 1010 kkkk kkkk XORLW  k          Exclusive OR literal with W
// 0000 1011 kkkk kkkk ANDLW  k          AND literal with W
// 0000 1100 kkkk kkkk RETLW  k          Return with literal in W
// 0000 1101 kkkk kkkk MULLW  k          Multiply literal with W
// 0000 1110 kkkk kkkk MOVLW  k          Move literal to W
// 0000 1111 kkkk kkkk ADDLW  k          Add literal and W
      static const ushort codes[16] =
      {
        PIC_sublw, PIC_iorlw,  PIC_xorlw, PIC_andlw,
        PIC_retlw, PIC_mullw1, PIC_movlw, PIC_addlw
      };
      insn.itype = codes[(code>>8)&7];
      insn.Op1.type  = o_imm;
      insn.Op1.value = (char)code;
      insn.Op1.dtype = dt_byte;
    }
  }
  else if ( ( code >> 14 ) <= 2 )
  {
    int b1 = code >> 12;
    if ( b1 <= 5 )
    {
// 0001 00da ffff ffff IORWF  f, d, a    Inclusive OR W with f
// 0001 01da ffff ffff ANDWF  f, d, a    AND W with f
// 0001 10da ffff ffff XORWF  f, d, a    Exclusive OR W with f
// 0001 11da ffff ffff COMF   f, d, a    Complement f
// 0010 00da ffff ffff ADDWFC f, d, a    Add W and Carry to f
// 0010 01da ffff ffff ADDWF  f, d, a    Add W and f
// 0010 10da ffff ffff INCF   f, d, a    Increment f
// 0010 11da ffff ffff DECFSZ f, d, a    Decrement f, Skip if 0
// 0011 00da ffff ffff RRCF   f, d, a    Rotate Right f through Carry
// 0011 01da ffff ffff RLCF   f, d, a    Rotate Left f through Carry
// 0011 10da ffff ffff SWAPF  f, d, a    Swap nibbles in f
// 0011 11da ffff ffff INCFSZ f, d, a    Increment f, Skip if 0
// 0100 00da ffff ffff RRNCF  f, d, a    Rotate Right f
// 0100 01da ffff ffff RLNCF  f, d, a    Rotate Left f
// 0100 10da ffff ffff INFSNZ f, d, a    Increment f, Skip if not 0
// 0100 11da ffff ffff DCFSNZ f, d, a    Decrement f, Skip if not 0
// 0101 00da ffff ffff MOVF   f, d, a    Move f
// 0101 01da ffff ffff SUBFWB f, d, a    Substract f from W with borrow
// 0101 10da ffff ffff SUBWFB f, d, a    Substract W from f with borrow
// 0101 11da ffff ffff SUBWF  f, d, a    Substract W from f
      static const ushort codes[24] =
      {
        PIC_null,    PIC_null,    PIC_null,    PIC_null,
        PIC_iorwf3,  PIC_andwf3,  PIC_xorwf3,  PIC_comf3,
        PIC_addwfc3, PIC_addwf3,  PIC_incf3,   PIC_decfsz3,
        PIC_rrcf3,   PIC_rlcf3,   PIC_swapf3,  PIC_incfsz,
        PIC_rrncf3,  PIC_rlncf3,  PIC_infsnz3, PIC_dcfsnz3,
        PIC_movf3,   PIC_subfwb3, PIC_subwfb3, PIC_subwf3,
      };
      QASSERT(10097, (code>>10) < 24);
      insn.itype = codes[code>>10];
      opfa16(insn, code);
      insn.Op2.type = o_reg;
      insn.Op2.reg = (code & 0x200) ? F : W;
      insn.Op2.dtype = dt_byte;
      insn.Op3.type = o_reg;
      insn.Op3.reg = (code & 0x100) ? BANKED : ACCESS;
      insn.Op3.dtype = dt_byte;
    }
    else if ( b1 == 6 )
    {
// 0110 000a ffff ffff CPFSLT f, a       Compare f with W, Skip if <
// 0110 001a ffff ffff CPFSEQ f, a       Compare f with W, Skip if ==
// 0110 010a ffff ffff CPFSGT f, a       Compare f with W, Skip if >
// 0110 011a ffff ffff TSTFSZ f, a       Test f, Skip if 0
// 0110 100a ffff ffff SETF   f, a       Set f
// 0110 101a ffff ffff CLRF   f, a       Clear f
// 0110 110a ffff ffff NEGF   f, a       Negate f
// 0110 111a ffff ffff MOVWF  f, a       Move W to f
      static const ushort codes[8] =
      {
        PIC_cpfslt2, PIC_cpfseq2, PIC_cpfsgt2, PIC_tstfsz2,
        PIC_setf2,   PIC_clrf2,   PIC_negf2,   PIC_movwf2,
      };
      insn.itype = codes[(code>>9)&7];
      opfa16(insn, code);
      insn.Op2.type = o_reg;
      insn.Op2.reg = (code & 0x100) ? BANKED : ACCESS;
      insn.Op2.dtype = dt_byte;
    }
    else
    {
// 0111 bbba ffff ffff BTG    f, b, a    Bit Toggle f
// 1000 bbba ffff ffff BSF    f, b, a    Bit Set f
// 1001 bbba ffff ffff BCF    f, b, a    Bit Clear f
// 1010 bbba ffff ffff BTFSS  f, b, a    Bit Test f, Skip if Set
// 1011 bbba ffff ffff BTFSC  f, b, a    Bit Test f, Skip if Clear
      static const ushort codes[5] =
      {
        PIC_btg3, PIC_bsf3, PIC_bcf3, PIC_btfss3, PIC_btfsc3
      };
      QASSERT(10098, (b1-7) < 5);
      insn.itype = codes[b1-7];
      opfa16(insn, code);
      insn.Op2.type  = o_imm;
      insn.Op2.value = (code >> 9) & 7;
      insn.Op2.dtype = dt_byte;
      insn.Op3.type = o_reg;
      insn.Op3.reg = (code & 0x100) ? BANKED : ACCESS;
      insn.Op3.dtype = dt_byte;
    }
  }
  else
  {
    int b2 = ( code >> 12 ) & 3;
    int b3 = ( code >> 8 ) & 0x0F;
    switch ( b2 )
    {
      case 0:
// 1100 ffff ffff ffff 1111 ffff ffff ffff MOVFF fs, fd  Move fs to fd
        insn.itype = PIC_movff2;
        insn.Op1.type = o_mem;
        insn.Op1.dtype = dt_byte;
        insn.Op1.addr = code & 0xFFF;
        insn.Op2.type = o_mem;
        insn.Op2.dtype = dt_byte;
        insn.Op2.addr = insn.get_next_word() & 0xFFF;
        break;
      case 1:
// 1101 0nnn nnnn nnnn BRA    n          Branch unconditionally
// 1101 1nnn nnnn nnnn RCALL  n          Relative Call subroutine
        insn.itype = (code & 0x800) ? PIC_rcall1 : PIC_bra1;
        insn.Op1.type = o_near;
        insn.Op1.addr = (insn.ea + 2 + 2 * get_signed(code,0x07FF)) & PIC18_IP_RANGE;
        insn.Op1.dtype = dt_code;
        break;
      case 2:
        if ( b3 <= 7 )
        {
// 1110 0000 nnnn nnnn BZ     n          Branch if Zero
// 1110 0001 nnnn nnnn BNZ    n          Branch if not Zero
// 1110 0010 nnnn nnnn BC     n          Branch if Carry
// 1110 0011 nnnn nnnn BNC    n          Branch if not Carry
// 1110 0100 nnnn nnnn BOV    n          Branch if Overflow
// 1110 0101 nnnn nnnn BNOV   n          Branch if not Overflow
// 1110 0110 nnnn nnnn BN     n          Branch if Negative
// 1110 0111 nnnn nnnn BNN    n          Branch if not Negative
          static const ushort codes[8] =
          {
            PIC_bz1,  PIC_bnz1,  PIC_bc1, PIC_bnc1,
            PIC_bov1, PIC_bnov1, PIC_bn1, PIC_bnn1
          };
          insn.itype = codes[(code>>8)&7];
          insn.Op1.type = o_near;
          insn.Op1.addr = (insn.ea + 2 + 2 * get_signed(code,0x00FF)) & PIC18_IP_RANGE;
          insn.Op1.dtype = dt_code;
        }
        else if ( b3 == 0xC || b3 == 0xD || b3 == 0xF )
        {
// 1110 110s kkkk kkkk 1111 kkkk kkkk kkkk CALL n, s     Call subroutine
// 1110 1111 kkkk kkkk 1111 kkkk kkkk kkkk GOTO n        Go to address
          static const ushort codes[4] =
          {
            PIC_call2, PIC_call2, PIC_null, PIC_goto
          };
          insn.itype = codes[(code>>8)&3];
          insn.Op1.type = o_near;
          insn.Op1.addr = ((insn.get_next_word() & 0xFFF) << 9) | ((code & 0x00FF) << 1);
          insn.Op1.dtype = dt_code;
          if ( insn.itype == PIC_call2 )
          {
            if ( code & 0x0100 )
            {
              insn.Op2.type  = o_reg;
              insn.Op2.reg   = FAST;
            }
            else
            {
              insn.Op2.type  = o_imm;
              insn.Op2.value = 0;
            }
            insn.Op2.dtype = dt_byte;
          }
        }
        else if ( ( code & 0xFFC0 ) == 0xEE00 )
        {
// 1110 1110 00ff kkkk 1111 0000 kkkk kkkk LFSR f, k     Move literal to FSR
          insn.itype = PIC_lfsr2;
          insn.Op1.type  = o_reg;
          insn.Op1.reg   = FSR0 + ((code >> 4) & 3);
          insn.Op1.dtype = dt_byte;
          insn.Op2.type = o_imm;
          insn.Op2.value = ((code&0xF) << 8 ) | (insn.get_next_word() & 0xFF);
          insn.Op2.dtype = dt_word;
        }
        else
        {
          insn.itype = PIC_null;
        }
        break;
      case 3:
// 1111 xxxx xxxx xxxx NOP               No Operation
        insn.itype = PIC_nop;
        break;
    }
  }
}

//--------------------------------------------------------------------------
int pic_t::basic_ana(insn_t &insn)
{
  int code;

  switch ( ptype )
  {
    case PIC12:
      code = get_wide_byte(insn.ea); insn.size = 1;
      basic_ana12(insn, code);
      break;
    case PIC14:
      code = get_wide_byte(insn.ea); insn.size = 1;
      basic_ana14(insn, code);
      break;
    case PIC16:
      code = insn.get_next_word();
      basic_ana16(insn, code);
      break;
    default:
      error("interr: ana");
  }
  if ( insn.itype == PIC_null )
    return 0;
  return insn.size;
}
