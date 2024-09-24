/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2000 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 */

#include "st20.hpp"

//--------------------------------------------------------------------------
// ST20/C2-C4
static const ushort primary4[] =
{
/* 00 */ ST20_j,
/* 01 */ ST20_ldlp,
/* 02 */ ST20_pfix,
/* 03 */ ST20_ldnl,
/* 04 */ ST20_ldc,
/* 05 */ ST20_ldnlp,
/* 06 */ ST20_nfix,
/* 07 */ ST20_ldl,
/* 08 */ ST20_adc,
/* 09 */ ST20_call,
/* 0A */ ST20_cj,
/* 0B */ ST20_ajw,
/* 0C */ ST20_eqc,
/* 0D */ ST20_stl,
/* 0E */ ST20_stnl,
/* 0F */ ST20_opr,
};

static const ushort secondary4_negative[] =
{
/*~00 */ ST20_swapqueue,        // swap scheduler queue
/*~01 */ ST20_swaptimer,        // swap timer queue
/*~02 */ ST20_insertqueue,      // insert at front of scheduler queue
/*~03 */ ST20_timeslice,        // timeslice
/*~04 */ ST20_signal,           // signal
/*~05 */ ST20_wait,             // wait
/*~06 */ ST20_trapdis,          // trap disable
/*~07 */ ST20_trapenb,          // trap enable
/*~08 */ ST20_null,
/*~09 */ ST20_null,
/*~0A */ ST20_null,
/*~0B */ ST20_tret,             // trap return
/*~0C */ ST20_ldshadow,         // load shadow registers
/*~0D */ ST20_stshadow,         // store shadow registers
/*~0E */ ST20_null,
/*~0F */ ST20_null,
/*~10 */ ST20_null,
/*~11 */ ST20_null,
/*~12 */ ST20_null,
/*~13 */ ST20_null,
/*~14 */ ST20_null,
/*~15 */ ST20_null,
/*~16 */ ST20_null,
/*~17 */ ST20_null,
/*~18 */ ST20_null,
/*~19 */ ST20_null,
/*~1A */ ST20_null,
/*~1B */ ST20_null,
/*~1C */ ST20_null,
/*~1D */ ST20_null,
/*~1E */ ST20_null,
/*~1F */ ST20_iret,             // interrupt return
/*~20 */ ST20_null,
/*~21 */ ST20_null,
/*~22 */ ST20_null,
/*~23 */ ST20_null,
/*~24 */ ST20_devmove,          // device move
/*~25 */ ST20_null,
/*~26 */ ST20_null,
/*~27 */ ST20_null,
/*~28 */ ST20_null,
/*~29 */ ST20_null,
/*~2A */ ST20_null,
/*~2B */ ST20_null,
/*~2C */ ST20_null,
/*~2D */ ST20_null,
/*~2E */ ST20_restart,          // restart
/*~2F */ ST20_causeerror,       // cause error
/*~30 */ ST20_nop,              // no operation
/*~31 */ ST20_null,
/*~32 */ ST20_null,
/*~33 */ ST20_null,
/*~34 */ ST20_null,
/*~35 */ ST20_null,
/*~36 */ ST20_null,
/*~37 */ ST20_null,
/*~38 */ ST20_null,
/*~39 */ ST20_null,
/*~3A */ ST20_null,
/*~3B */ ST20_null,
/*~3C */ ST20_null,
/*~3D */ ST20_null,
/*~3E */ ST20_null,
/*~3F */ ST20_null,
/*~40 */ ST20_null,
/*~41 */ ST20_null,
/*~42 */ ST20_null,
/*~43 */ ST20_null,
/*~44 */ ST20_null,
/*~45 */ ST20_null,
/*~46 */ ST20_null,
/*~47 */ ST20_null,
/*~48 */ ST20_null,
/*~49 */ ST20_null,
/*~4A */ ST20_null,
/*~4B */ ST20_null,
/*~4C */ ST20_stclock,          // store clock register
/*~4D */ ST20_ldclock,          // load clock
/*~4E */ ST20_clockdis,         // clock disable
/*~4F */ ST20_clockenb,         // clock enable
/*~50 */ ST20_null,
/*~51 */ ST20_null,
/*~52 */ ST20_null,
/*~53 */ ST20_null,
/*~54 */ ST20_null,
/*~55 */ ST20_null,
/*~56 */ ST20_null,
/*~57 */ ST20_null,
/*~58 */ ST20_null,
/*~59 */ ST20_null,
/*~5A */ ST20_null,
/*~5B */ ST20_null,
/*~5C */ ST20_null,
/*~5D */ ST20_null,
/*~5E */ ST20_null,
/*~5F */ ST20_null,
/*~60 */ ST20_null,
/*~61 */ ST20_null,
/*~62 */ ST20_null,
/*~63 */ ST20_null,
/*~64 */ ST20_null,
/*~65 */ ST20_null,
/*~66 */ ST20_null,
/*~67 */ ST20_null,
/*~68 */ ST20_null,
/*~69 */ ST20_null,
/*~6A */ ST20_null,
/*~6B */ ST20_null,
/*~6C */ ST20_null,
/*~6D */ ST20_null,
/*~6E */ ST20_null,
/*~6F */ ST20_null,
/*~70 */ ST20_null,
/*~71 */ ST20_null,
/*~72 */ ST20_null,
/*~73 */ ST20_null,
/*~74 */ ST20_null,
/*~75 */ ST20_null,
/*~76 */ ST20_null,
/*~77 */ ST20_null,
/*~78 */ ST20_null,
/*~79 */ ST20_null,
/*~7A */ ST20_null,
/*~7B */ ST20_null,
/*~7C */ ST20_null,
/*~7D */ ST20_null,
/*~7E */ ST20_null,
/*~7F */ ST20_null,
/*~80 */ ST20_null,
/*~81 */ ST20_null,
/*~82 */ ST20_null,
/*~83 */ ST20_null,
/*~84 */ ST20_null,
/*~85 */ ST20_null,
/*~86 */ ST20_null,
/*~87 */ ST20_null,
/*~88 */ ST20_null,
/*~89 */ ST20_null,
/*~8A */ ST20_null,
/*~8B */ ST20_null,
/*~8C */ ST20_ldprodid,         // load product identity
/*~8D */ ST20_reboot,           // reboot
/*~8E */ ST20_null,
/*~8F */ ST20_null,
};

static const ushort secondary4[] =
{
/* 00 */ ST20_rev,              // ---------------------------------------------
/* 01 */ ST20_lb,               // load byte
/* 02 */ ST20_bsub,             // byte subscript
/* 03 */ ST20_endp,             // end process
/* 04 */ ST20_diff,             // difference
/* 05 */ ST20_add,
/* 06 */ ST20_gcall,            // general call
/* 07 */ ST20_in,               // input message
/* 08 */ ST20_prod,             // product
/* 09 */ ST20_gt,               // greater than
/* 0A */ ST20_wsub,             // word subscript
/* 0B */ ST20_out,              // output message
/* 0C */ ST20_sub,              // subtract
/* 0D */ ST20_startp,           // start process
/* 0E */ ST20_outbyte,          // output byte
/* 0F */ ST20_outword,          // output word
/* 10 */ ST20_seterr,           // set error flags
/* 11 */ ST20_null,
/* 12 */ ST20_resetch,          // reset channel
/* 13 */ ST20_csub0,            // check subscript from 0
/* 14 */ ST20_null,
/* 15 */ ST20_stopp,            // stop process
/* 16 */ ST20_ladd,             // long add
/* 17 */ ST20_stlb,             // store low priority back pointer
/* 18 */ ST20_sthf,             // store high priority front pointer
/* 19 */ ST20_norm,             // normalize
/* 1A */ ST20_ldiv,             // long divide
/* 1B */ ST20_ldpi,             // load pointer to instruction
/* 1C */ ST20_stlf,             // store low priority front pointer
/* 1D */ ST20_xdble,            // extend to double
/* 1E */ ST20_ldpri,            // load current priority
/* 1F */ ST20_rem,              // remainder
/* 20 */ ST20_ret,              // return
/* 21 */ ST20_lend,             // loop end
/* 22 */ ST20_ldtimer,          // load timer
/* 23 */ ST20_null,
/* 24 */ ST20_null,
/* 25 */ ST20_null,
/* 26 */ ST20_null,
/* 27 */ ST20_null,
/* 28 */ ST20_null,
/* 29 */ ST20_testerr,          // test error flag
/* 2A */ ST20_testpranal,       // test processor analysing
/* 2B */ ST20_tin,              // timer input
/* 2C */ ST20_div,              // divide
/* 2D */ ST20_null,
/* 2E */ ST20_dist,             // disable timer
/* 2F */ ST20_disc,             // disable channel
/* 30 */ ST20_diss,             // disable skip
/* 31 */ ST20_lmul,             // long multiply
/* 32 */ ST20_not,              // not
/* 33 */ ST20_xor,              // exclusize or
/* 34 */ ST20_bcnt,             // byte count
/* 35 */ ST20_lshr,             // long shift right
/* 36 */ ST20_lshl,             // long shift left
/* 37 */ ST20_lsum,             // long sum
/* 38 */ ST20_lsub,             // long subtract
/* 39 */ ST20_runp,             // run process
/* 3A */ ST20_xword,            // extend word
/* 3B */ ST20_sb,               // store byte
/* 3C */ ST20_gajw,             // general adjust workspace
/* 3D */ ST20_savel,            // save low priority queue registers
/* 3E */ ST20_saveh,            // save high priority queue registers
/* 3F */ ST20_wcnt,             // word count
/* 40 */ ST20_shr,              // shift right
/* 41 */ ST20_shl,              // shift left
/* 42 */ ST20_mint,             // minimum integer
/* 43 */ ST20_alt,              // alt start
/* 44 */ ST20_altwt,            // alt wait
/* 45 */ ST20_altend,           // alt end
/* 46 */ ST20_and,
/* 47 */ ST20_enbt,             // enable timer
/* 48 */ ST20_enbc,             // enable channel
/* 49 */ ST20_enbs,             // enable skip
/* 4A */ ST20_move,             // move message
/* 4B */ ST20_or,               // or
/* 4C */ ST20_csngl,            // check single
/* 4D */ ST20_ccnt1,            // check count from 1
/* 4E */ ST20_talt,             // timer alt start
/* 4F */ ST20_ldiff,            // long diff
/* 50 */ ST20_sthb,             // store high priority back pointer
/* 51 */ ST20_taltwt,           // timer alt wait
/* 52 */ ST20_sum,              // sum
/* 53 */ ST20_mul,              // multiply
/* 54 */ ST20_sttimer,          // store timer
/* 55 */ ST20_stoperr,          // stop on error
/* 56 */ ST20_cword,            // check word
/* 57 */ ST20_clrhalterr,       // clear halt-on error flag
/* 58 */ ST20_sethalterr,       // set halt-on error flag
/* 59 */ ST20_testhalterr,      // test halt-on error flag
/* 5A */ ST20_dup,              // duplicate top of stack
/* 5B */ ST20_move2dinit,       // initialize data for 2D block move
/* 5C */ ST20_move2dall,        // 2D block copy
/* 5D */ ST20_move2dnonzero,    // 2D block copy non-zero bytes
/* 5E */ ST20_move2dzero,       // 2D block copy zero bytes
/* 5F */ ST20_gtu,              // greater than unsigned
/* 60 */ ST20_null,
/* 61 */ ST20_null,
/* 62 */ ST20_null,
/* 63 */ ST20_unpacksn,         // unpack single length fp number
/* 64 */ ST20_slmul,            // signed long multiply
/* 65 */ ST20_sulmul,           // signed timer unsigned long multiply
/* 66 */ ST20_null,
/* 67 */ ST20_null,
/* 68 */ ST20_satadd,           // saturating add
/* 69 */ ST20_satsub,           // saturating subtract
/* 6A */ ST20_satmul,           // saturating multiply
/* 6B */ ST20_null,
/* 6C */ ST20_postnormsn,       // post-normalize correction of single length fp number
/* 6D */ ST20_roundsn,          // round single length floating point number
/* 6E */ ST20_ldtraph,          // load trap handler
/* 6F */ ST20_sttraph,          // store trap handler
/* 70 */ ST20_null,
/* 71 */ ST20_ldinf,            // load infinity
/* 72 */ ST20_fmul,             // fractional multiply
/* 73 */ ST20_cflerr,           // check floating point error
/* 74 */ ST20_crcword,          // calculate CRC on word
/* 75 */ ST20_crcbyte,          // calculate CRC on byte
/* 76 */ ST20_bitcnt,           // count bits set in word
/* 77 */ ST20_bitrevword,       // reverse bits in word
/* 78 */ ST20_bitrevnbits,      // reverse bottom n bits in word
/* 79 */ ST20_pop,              // pop processor stack
/* 7A */ ST20_null,
/* 7B */ ST20_null,
/* 7C */ ST20_null,
/* 7D */ ST20_null,
/* 7E */ ST20_ldmemstartval,    // load value of MemStart address
/* 7F */ ST20_null,
/* 80 */ ST20_null,
/* 81 */ ST20_wsubdb,           // form double word subscript
/* 82 */ ST20_null,
/* 83 */ ST20_null,
/* 84 */ ST20_null,
/* 85 */ ST20_null,
/* 86 */ ST20_null,
/* 87 */ ST20_null,
/* 88 */ ST20_null,
/* 89 */ ST20_null,
/* 8A */ ST20_null,
/* 8B */ ST20_null,
/* 8C */ ST20_null,
/* 8D */ ST20_null,
/* 8E */ ST20_null,
/* 8F */ ST20_null,
/* 90 */ ST20_null,
/* 91 */ ST20_null,
/* 92 */ ST20_null,
/* 93 */ ST20_null,
/* 94 */ ST20_null,
/* 95 */ ST20_null,
/* 96 */ ST20_null,
/* 97 */ ST20_null,
/* 98 */ ST20_null,
/* 99 */ ST20_null,
/* 9A */ ST20_null,
/* 9B */ ST20_null,
/* 9C */ ST20_fptesterr,        // test for FPU error
/* 9D */ ST20_null,
/* 9E */ ST20_null,
/* 9F */ ST20_null,
/* A0 */ ST20_null,
/* A1 */ ST20_null,
/* A2 */ ST20_null,
/* A3 */ ST20_null,
/* A4 */ ST20_null,
/* A5 */ ST20_null,
/* A6 */ ST20_null,
/* A7 */ ST20_null,
/* A8 */ ST20_null,
/* A9 */ ST20_null,
/* AA */ ST20_null,
/* AB */ ST20_null,
/* AC */ ST20_null,
/* AD */ ST20_null,
/* AE */ ST20_null,
/* AF */ ST20_null,
/* B0 */ ST20_settimeslice,     // set timeslicing status
/* B1 */ ST20_null,
/* B2 */ ST20_null,
/* B3 */ ST20_null,
/* B4 */ ST20_null,
/* B5 */ ST20_null,
/* B6 */ ST20_null,
/* B7 */ ST20_null,
/* B8 */ ST20_xbword,           // sign extend byte to word
/* B9 */ ST20_lbx,              // load byte and sign extend
/* BA */ ST20_cb,               // check byte
/* BB */ ST20_cbu,              // check byte unsigned
/* BC */ ST20_null,
/* BD */ ST20_null,
/* BE */ ST20_null,
/* BF */ ST20_null,
/* C0 */ ST20_null,
/* C1 */ ST20_ssub,             // sixteen subscript
/* C2 */ ST20_null,
/* C3 */ ST20_null,
/* C4 */ ST20_intdis,           // (localised) interrupt disable
/* C5 */ ST20_intenb,           // (localised) interrupt enable
/* C6 */ ST20_ldtrapped,        // load trapped process status
/* C7 */ ST20_cir,              // check in range
/* C8 */ ST20_ss,               // store sixteen
/* C9 */ ST20_null,
/* CA */ ST20_ls,               // load sixteen
/* CB */ ST20_sttrapped,        // store trapped process
/* CC */ ST20_ciru,             // check in range unsigned
/* CD */ ST20_gintdis,          // general interrupt disable
/* CE */ ST20_gintenb,          // general interrupt enable
/* CF */ ST20_null,
/* D0 */ ST20_null,
/* D1 */ ST20_null,
/* D2 */ ST20_null,
/* D3 */ ST20_null,
/* D4 */ ST20_null,
/* D5 */ ST20_null,
/* D6 */ ST20_null,
/* D7 */ ST20_null,
/* D8 */ ST20_null,
/* D9 */ ST20_null,
/* DA */ ST20_null,
/* DB */ ST20_null,
/* DC */ ST20_null,
/* DD */ ST20_null,
/* DE */ ST20_null,
/* DF */ ST20_null,
/* E0 */ ST20_null,
/* E1 */ ST20_null,
/* E2 */ ST20_null,
/* E3 */ ST20_null,
/* E4 */ ST20_null,
/* E5 */ ST20_null,
/* E6 */ ST20_null,
/* E7 */ ST20_null,
/* E8 */ ST20_null,
/* E9 */ ST20_null,
/* EA */ ST20_null,
/* EB */ ST20_null,
/* EC */ ST20_null,
/* ED */ ST20_null,
/* EE */ ST20_null,
/* EF */ ST20_null,
/* F0 */ ST20_devlb,            // device load byte
/* F1 */ ST20_devsb,            // device store byte
/* F2 */ ST20_devls,            // device load sixteen
/* F3 */ ST20_devss,            // device store sixteen
/* F4 */ ST20_devlw,            // device load word
/* F5 */ ST20_devsw,            // device store word
/* F6 */ ST20_null,
/* F7 */ ST20_null,
/* F8 */ ST20_xsword,           // sign extend sixteen to word
/* F9 */ ST20_lsx,              // load sixteen and sign extend
/* FA */ ST20_cs,               // check sixteen
/* FB */ ST20_csu,              // check sixteen unsigned
/* FC */ ST20_null,
/* FD */ ST20_null,
/* FE */ ST20_null,
/* FF */ ST20_null,
};

//--------------------------------------------------------------------------
// ST20/C1
static const ushort primary1[] =
{
/* 00 */ ST20_j,
/* 01 */ ST20_ldlp,
/* 02 */ ST20_pfix,
/* 03 */ ST20_ldnl,
/* 04 */ ST20_ldc,
/* 05 */ ST20_ldnlp,
/* 06 */ ST20_nfix,
/* 07 */ ST20_ldl,
/* 08 */ ST20_adc,
/* 09 */ ST20_fcall,
/* 0A */ ST20_cj,
/* 0B */ ST20_ajw,
/* 0C */ ST20_eqc,
/* 0D */ ST20_stl,
/* 0E */ ST20_stnl,
/* 0F */ ST20_opr,
};

static const ushort secondary1[] =
{
/* 00 */ ST20_rev,
/* 01 */ ST20_dup,
/* 02 */ ST20_rot,
/* 03 */ ST20_arot,
/* 04 */ ST20_add,
/* 05 */ ST20_sub,
/* 06 */ ST20_mul,
/* 07 */ ST20_wsub,
/* 08 */ ST20_not,
/* 09 */ ST20_and,
/* 0A */ ST20_or,
/* 0B */ ST20_shl,
/* 0C */ ST20_shr,
/* 0D */ ST20_jab,
/* 0E */ ST20_timeslice,
/* 0F */ ST20_breakpoint,
/* 10 */ ST20_addc,
/* 11 */ ST20_subc,
/* 12 */ ST20_mac,
/* 13 */ ST20_umac,
/* 14 */ ST20_smul,
/* 15 */ ST20_smacinit,
/* 16 */ ST20_smacloop,
/* 17 */ ST20_biquad,
/* 18 */ ST20_divstep,
/* 19 */ ST20_unsign,
/* 1A */ ST20_saturate,
/* 1B */ ST20_gt,
/* 1C */ ST20_gtu,
/* 1D */ ST20_order,
/* 1E */ ST20_orderu,
/* 1F */ ST20_ashr,
/* 20 */ ST20_xor,
/* 21 */ ST20_xbword,
/* 22 */ ST20_xsword,
/* 23 */ ST20_bitld,
/* 24 */ ST20_bitst,
/* 25 */ ST20_bitmask,
/* 26 */ ST20_statusset,
/* 27 */ ST20_statusclr,
/* 28 */ ST20_statustst,
/* 29 */ ST20_rmw,
/* 2A */ ST20_lbinc,
/* 2B */ ST20_sbinc,
/* 2C */ ST20_lsinc,
/* 2D */ ST20_lsxinc,
/* 2E */ ST20_ssinc,
/* 2F */ ST20_lwinc,
/* 30 */ ST20_swinc,
/* 31 */ ST20_ecall,
/* 32 */ ST20_eret,
/* 33 */ ST20_run,
/* 34 */ ST20_stop,
/* 35 */ ST20_signal,
/* 36 */ ST20_wait,
/* 37 */ ST20_enqueue,
/* 38 */ ST20_dequeue,
/* 39 */ ST20_ldtdesc,
/* 3A */ ST20_ldpi,
/* 3B */ ST20_gajw,
/* 3C */ ST20_ldprodid,
/* 3D */ ST20_io,
/* 3E */ ST20_swap32,
/* 3F */ ST20_nop,
};

struct ana_info_t
{
  const ushort *primary;
  const ushort *secondary;
  size_t sqty;
  const ushort *secondary_negative;
  size_t nsqty;
};

static const ana_info_t c1 =
{
  primary1,
  secondary1,
  qnumber(secondary1),
  nullptr,
  0
};

static const ana_info_t c4 =
{
  primary4,
  secondary4,
  qnumber(secondary4),
  secondary4_negative,
  qnumber(secondary4_negative),
};

//--------------------------------------------------------------------------
int st20_t::st20_ana(insn_t *_insn)
{
  insn_t &insn = *_insn;
  const ana_info_t &a = isc4() ? c4 : c1;
  int value = 0;
  while ( 1 )
  {
    int code = insn.get_next_byte();
    value |= (code & 15);
    insn.itype = a.primary[code>>4];
    switch ( insn.itype )
    {
      case ST20_j:
      case ST20_cj:
      case ST20_fcall:
      case ST20_call:
        insn.Op1.type = o_near;
        insn.Op1.dtype = dt_code;
        insn.Op1.addr = uint32(insn.ip + insn.size + value);
        break;
      case ST20_ldlp:
      case ST20_ldnl:
      case ST20_ldc:
      case ST20_ldnlp:
      case ST20_ldl:
      case ST20_adc:
      case ST20_ajw:
      case ST20_eqc:
      case ST20_stl:
      case ST20_stnl:
        insn.Op1.type = o_imm;
        insn.Op1.dtype = dt_dword;
        insn.Op1.value = value;
        break;
      case ST20_nfix:
        value = ~value;
        // fallthrough
      case ST20_pfix:
        value <<= 4;
        continue;
      case ST20_opr:
        if ( isc4() && value == 0x17C )
        {
          insn.itype = ST20_lddevid;
          break;
        }
        if ( value < 0 )
        {
          value = (~value & ~15) | (value & 15);
          if ( value >= a.nsqty )
            return 0;
          insn.itype = a.secondary_negative[value];
        }
        else
        {
          if ( value >= a.sqty )
            return 0;
          insn.itype = a.secondary[value];
        }
        break;
    }
    break;
  }
  return insn.size;
}

