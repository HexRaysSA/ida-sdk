/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum
{
ST20_null = 0,      // Unknown Operation

// C1 instructions

ST20_adc,           // add constant
ST20_add,           // add
ST20_addc,          // add with carry
ST20_ajw,           // adjust work space
ST20_and,           // and
ST20_arot,          // anti-rotate stack
ST20_ashr,          // arithmetic shift right
ST20_biquad,        // biquad IIR filter step
ST20_bitld,         // load bit
ST20_bitmask,       // create bit mask
ST20_bitst,         // store bit
ST20_breakpoint,    // breakpoint
ST20_cj,            // conditional jump
ST20_dequeue,       // dequeue a process
ST20_divstep,       // divide step
ST20_dup,           // duplicate
ST20_ecall,         // exception call
ST20_enqueue,       // enqueue a process
ST20_eqc,           // equals constant
ST20_eret,          // exception return
ST20_fcall,         // function call
ST20_gajw,          // general adjust workspace
ST20_gt,            // greater than
ST20_gtu,           // greater than unsigned
ST20_io,            // input/output
ST20_j,             // jump
ST20_jab,           // jump absolute
ST20_lbinc,         // load byte and increment
ST20_ldc,           // load constant
ST20_ldl,           // load local
ST20_ldlp,          // load local pointer
ST20_ldnl,          // load non-local
ST20_ldnlp,         // load non-local pointer
ST20_ldpi,          // load pointer to instruction
ST20_ldprodid,      // load product identity
ST20_ldtdesc,       // load task descriptor
ST20_lsinc,         // load sixteen and increment
ST20_lsxinc,        // load sixteen sign extended and increment
ST20_lwinc,         // load word and increment
ST20_mac,           // multiply accumulate
ST20_mul,           // multiply
ST20_nfix,          // negative prefix
ST20_nop,           // no operation
ST20_not,           // bitwise not
ST20_opr,           // operate
ST20_or,            // or
ST20_order,         // order
ST20_orderu,        // unsigned order
ST20_pfix,          // prefix
ST20_rev,           // reverse
ST20_rmw,           // read modify write
ST20_rot,           // rotate stack
ST20_run,           // run process
ST20_saturate,      // saturate
ST20_sbinc,         // store byte and increment
ST20_shl,           // shift left
ST20_shr,           // shift right
ST20_signal,        // signal
ST20_smacinit,      // initialize short multiply accumulate loop
ST20_smacloop,      // short multiply accumulate loop
ST20_smul,          // short multiply
ST20_ssinc,         // store sixteen and increment
ST20_statusclr,     // clear bits in status register
ST20_statusset,     // set bits in status register
ST20_statustst,     // test status register
ST20_stl,           // store local
ST20_stnl,          // store non-local
ST20_stop,          // stop process
ST20_sub,           // subtract
ST20_subc,          // subtract with carry
ST20_swap32,        // byte swap 32
ST20_swinc,         // store word and increment
ST20_timeslice,     // timeslice
ST20_umac,          // unsigned multiply accumulate
ST20_unsign,        // unsign argument
ST20_wait,          // wait
ST20_wsub,          // word subscript
ST20_xbword,        // sign extend byte to word
ST20_xor,           // exclusive or
ST20_xsword,        // sign extend sixteen to word

// C2-C4 instructions

ST20_alt,           // alt start
ST20_altend,        // alt end
ST20_altwt,         // alt wait
ST20_bcnt,          // byte count
ST20_bitcnt,        // count bits set in word
ST20_bitrevnbits,   // reverse bottom n bits in word
ST20_bitrevword,    // reverse bits in word
ST20_bsub,          // byte subscript
ST20_call,          // call
ST20_causeerror,    // cause error
ST20_cb,            // check byte
ST20_cbu,           // check byte unsigned
ST20_ccnt1,         // check count from 1
ST20_cflerr,        // check floating point error
ST20_cir,           // check in range
ST20_ciru,          // check in range unsigned
ST20_clockdis,      // clock disable
ST20_clockenb,      // clock enable
ST20_clrhalterr,    // clear halt-on error flag
ST20_crcbyte,       // calculate CRC on byte
ST20_crcword,       // calculate CRC on word
ST20_cs,            // check sixteen
ST20_csngl,         // check single
ST20_csu,           // check sixteen unsigned
ST20_csub0,         // check subscript from 0
ST20_cword,         // check word
ST20_devlb,         // device load byte
ST20_devls,         // device load sixteen
ST20_devlw,         // device load word
ST20_devmove,       // device move
ST20_devsb,         // device store byte
ST20_devss,         // device store sixteen
ST20_devsw,         // device store word
ST20_diff,          // difference
ST20_disc,          // disable channel
ST20_diss,          // disable skip
ST20_dist,          // disable timer
ST20_div,           // divide
ST20_enbc,          // enable channel
ST20_enbs,          // enable skip
ST20_enbt,          // enable timer
ST20_endp,          // end process
ST20_fmul,          // fractional multiply
ST20_fptesterr,     // test for FPU error
ST20_gcall,         // general call
ST20_gintdis,       // general interrupt disable
ST20_gintenb,       // general interrupt enable
ST20_in,            // input message
ST20_insertqueue,   // insert at front of scheduler queue
ST20_intdis,        // (localised) interrupt disable
ST20_intenb,        // (localised) interrupt enable
ST20_iret,          // interrupt return
ST20_ladd,          // long add
ST20_lb,            // load byte
ST20_lbx,           // load byte and sign extend
ST20_ldclock,       // load clock
ST20_lddevid,       // load device identity
ST20_ldiff,         // long diff
ST20_ldinf,         // load infinity
ST20_ldiv,          // long divide
ST20_ldmemstartval, // load value of MemStart address
ST20_ldpri,         // load current priority
ST20_ldshadow,      // load shadow registers
ST20_ldtimer,       // load timer
ST20_ldtraph,       // load trap handler
ST20_ldtrapped,     // load trapped process status
ST20_lend,          // loop end
ST20_lmul,          // long multiply
ST20_ls,            // load sixteen
ST20_lshl,          // long shift left
ST20_lshr,          // long shift right
ST20_lsub,          // long subtract
ST20_lsum,          // long sum
ST20_lsx,           // load sixteen and sign extend
ST20_mint,          // minimum integer
ST20_move,          // move message
ST20_move2dall,     // 2D block copy
ST20_move2dinit,    // initialize data for 2D block move
ST20_move2dnonzero, // 2D block copy non-zero bytes
ST20_move2dzero,    // 2D block copy zero bytes
ST20_norm,          // normalize
ST20_out,           // output message
ST20_outbyte,       // output byte
ST20_outword,       // output word
ST20_pop,           // pop processor stack
ST20_postnormsn,    // post-normalize correction of single length fp number
ST20_prod,          // product
ST20_reboot,        // reboot
ST20_rem,           // remainder
ST20_resetch,       // reset channel
ST20_restart,       // restart
ST20_ret,           // return
ST20_roundsn,       // round single length floating point number
ST20_runp,          // run process
ST20_satadd,        // saturating add
ST20_satmul,        // saturating multiply
ST20_satsub,        // saturating subtract
ST20_saveh,         // save high priority queue registers
ST20_savel,         // save low priority queue registers
ST20_sb,            // store byte
ST20_seterr,        // set error flags
ST20_sethalterr,    // set halt-on error flag
ST20_settimeslice,  // set timeslicing status
ST20_slmul,         // signed long multiply
ST20_ss,            // store sixteen
ST20_ssub,          // sixteen subscript
ST20_startp,        // start process
ST20_stclock,       // store clock register
ST20_sthb,          // store high priority back pointer
ST20_sthf,          // store high priority front pointer
ST20_stlb,          // store low priority back pointer
ST20_stlf,          // store low priority front pointer
ST20_stoperr,       // stop on error
ST20_stopp,         // stop process
ST20_stshadow,      // store shadow registers
ST20_sttimer,       // store timer
ST20_sttraph,       // store trap handler
ST20_sttrapped,     // store trapped process
ST20_sulmul,        // signed timer unsigned long multiply
ST20_sum,           // sum
ST20_swapqueue,     // swap scheduler queue
ST20_swaptimer,     // swap timer queue
ST20_talt,          // timer alt start
ST20_taltwt,        // timer alt wait
ST20_testerr,       // test error flag
ST20_testhalterr,   // test halt-on error flag
ST20_testpranal,    // test processor analysing
ST20_tin,           // timer input
ST20_trapdis,       // trap disable
ST20_trapenb,       // trap enable
ST20_tret,          // trap return
ST20_unpacksn,      // unpack single length fp number
ST20_wcnt,          // word count
ST20_wsubdb,        // form double word subscript
ST20_xdble,         // extend to double
ST20_xword,         // extend word

ST20_last,

    };

#endif
