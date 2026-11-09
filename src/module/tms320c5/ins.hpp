/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2024 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
TMS_null = 0,   // Unknown Operation
TMS_abs,        // Absolute value of Acc
TMS_adcb,       // Add ACCB to Acc With Carry
TMS_add,        // Add to Acc
TMS_addb,       // Add ACCB to Acc
TMS_addc,       // Add to Acc With Carry
TMS_adds,       // Add to Acc With Sign-Extension Suppressed
TMS_addt,       // Add to Acc With Shift Specified by TREG1
TMS_adrk,       // Add to Aux Register With Short Immediate
TMS_and,        // AND With Acc
TMS_andb,       // AND ACCD With Acc
TMS_apac,       // Add P Register to Acc
TMS_apl,        // AND Data Memory Value With DBMR
TMS_apl2,       // AND Data Memory Value With Long Constant
TMS_b,          // Branch Unconditionally
TMS_bacc,       // Branch to Location (Acc)
TMS_baccd,      // Branch to Location (Acc) Delayed
TMS_banz,       // Branch on Aux Register Not Zero
TMS_banzd,      // Branch on Aux Register Not Zero Delayed
TMS_bcnd,       // Branch Conditionally
TMS_bcndd,      // Branch Conditionally Delayed
TMS_bd,         // Branch Unconditionally Delayed
TMS_bit,        // Test Bit
TMS_bitt,       // Test Bit Specified by TREG2
TMS_bldd,       // Block Move From Data Memory to Data Memory
TMS_bldp,       // Block Move From Data Memory to Program Memory
TMS_blpd,       // Block Move From Program Memory to Data Memory
TMS_bsar,       // Barrel Shift
TMS_cala,       // Call Subroutine at (Acc)
TMS_calad,      // Call Subroutine at (Acc) Delayed
TMS_call,       // Call Unconditionally
TMS_calld,      // Call Unconditionally Delayed
TMS_cc,         // Call Conditionally
TMS_ccd,        // Call Conditionally Delayed
TMS_clrc,       // Clear Control Bit
TMS_cmpl,       // Complement Acc
TMS_cmpr,       // Compare Aux Register With ARCR
TMS_cpl,        // Compare DBMR With Data Value
TMS_cpl2,       // Compare Long Immediate With Data Value
TMS_crgt,       // Test for Acc Greater Than ACCB
TMS_crlt,       // Test for Acc Smaller Than ACCB
TMS_dmov,       // Data Move in Data Memory
TMS_estop,      // Emulator Stop
TMS_exar,       // Exchange ACCB With Acc
TMS_idle,       // Idle Until Interrupt
TMS_idle2,      // Idle Until Interrupt - Low Power Mode
TMS_in,         // Input Data From Port
TMS_intr,       // Soft Interrupt
TMS_lacb,       // Load Acc With ACCB
TMS_lacc,       // Load Acc With Shift
TMS_lacl,       // Load Low Acc and Clear High Acc
TMS_lact,       // Load Acc With Shift Specified by TREG1
TMS_lamm,       // Load Acc With Memory-Mapped Register
TMS_lar,        // Load Aux Register
TMS_ldp,        // Load Data Memory Pointer
TMS_lmmr,       // Load Memory-Mapped Register
TMS_lph,        // Load Product High Register
TMS_lst,        // Load Status Register
TMS_lt,         // Load TREG0
TMS_lta,        // Load TREG0 and Accumulate Previous Product
TMS_ltd,        // Load TREG0,Accumulate Previous Product and Move Data
TMS_ltp,        // Load TREG0 and Store P -> Acc
TMS_lts,        // Load TREG0 and Subtract Previous Product
TMS_mac,        // Multiply and Accumulate
TMS_macd,       // Multiply and Accumulate With Data Move
TMS_madd,       // Multiply and Accumulate With Data Move and Dynamic Addressing
TMS_mads,       // Multiply and Accumulate With Dynamic Addressing
TMS_mar,        // Modify Aux Register
TMS_mpy,        // Multiply
TMS_mpya,       // Multiply and Accumulate Previous Product
TMS_mpys,       // Multiply and Subtract Previous Product
TMS_mpyu,       // Multiply Unsigned
TMS_neg,        // Negate Acc
TMS_nmi,        // Nonmaskable Interrupt
TMS_nop,        // No Operation
TMS_norm,       // Normalize Contents of Acc
TMS_opl,        // OR With DBMS
TMS_opl2,       // OR With Long Immediate
TMS_or,         // OR With Acc
TMS_orb,        // OR ACCB With Accumulator
TMS_out,        // Out Data to Port
TMS_pac,        // Load Acc <- P
TMS_pop,        // Pop Top of Stack to Low Acc
TMS_popd,       // Pop Top of Stack to Data Memory
TMS_pshd,       // Push Data Memory Value Onto Stack
TMS_push,       // Push Low Acc Onto Stack
TMS_ret,        // Return From Subroutine
TMS_retc,       // Return Conditionally
TMS_retcd,      // Return Conditionally Delayed
TMS_retd,       // Return From Subroutine Delayed
TMS_rete,       // Enable Interrupts and Return From Interrupt
TMS_reti,       // Return From Interrupt
TMS_rol,        // Rotate Acc Left
TMS_rolb,       // Rotate ACCB and Acc Left
TMS_ror,        // Rotate Acc Right
TMS_rorb,       // Rotate ACCB and Acc Right
TMS_rpt,        // Repeat Next Instruction
TMS_rptb,       // Repeat Block
TMS_rptz,       // Repeat Preceded by Clearing Acc and P
TMS_sacb,       // Store Acc in ACCB
TMS_sach,       // Store High Acc With Shift
TMS_sacl,       // Store Low Acc With Shift
TMS_samm,       // Store Acc in Memory-Mapped Register
TMS_sar,        // Store Aux Register
TMS_sath,       // Barrel Shift Acc as Specified by TREG1(4)
TMS_satl,       // Barrel Shift Acc as Specified by TREG1(3-0)
TMS_sbb,        // Subtract ACCB From Acc
TMS_sbbb,       // Subtract ACCB From Acc With Borrow
TMS_sbrk,       // Subtract From Aux Register Short Immediate
TMS_setc,       // Set Control Bit
TMS_sfl,        // Shift Acc Left
TMS_sflb,       // Shift ACCB and Acc Left
TMS_sfr,        // Shift Acc Right
TMS_sfrb,       // Shift ACCB and Acc Right
TMS_smmr,       // Store Memory-Mapped Register
TMS_spac,       // Subtract P From Acc
TMS_sph,        // Store High P Register
TMS_spl,        // Store Low P Register
TMS_splk,       // Store Parallel Long Immediate
TMS_spm,        // Store ACCB and Acc Right
TMS_sqra,       // Square and Accumulate Previous Product
TMS_sqrs,       // Square and Subtract Previous Product
TMS_sst,        // Store Status Register
TMS_sub,        // Subtract From Acc
TMS_subb,       // Subtract From Acc With Borrow
TMS_subc,       // Conditional Subtract
TMS_subs,       // Subtract From Acc With Sign-Extension Suppressed
TMS_subt,       // Subtract From Acc With Shift Specified by TREG1
TMS_tblr,       // Table Read
TMS_tblw,       // Table Write
TMS_trap,       // Software Interrupt
TMS_xc,         // Execute Conditionally
TMS_xor,        // Exclusive-OR With Acc
TMS_xorb,       // Exclusive-OR of ACCB With Acc
TMS_xpl,        // Exclusive-OR Data Memory Value
TMS_xpl2,       // Exclusive-OR Data Memory Value
TMS_zalr,       // Zero Low Acc Load High Acc With Rounding
TMS_zap,        // Zero Acc and P
TMS_zpr,        // Zero P Register

//
//      TMS320C2x instructions
//

TMS2_abs,               // Absolute value of accumulator
TMS2_add,               // Add to accumulator with shift
TMS2_addc,              // Add to accumulator with carry
TMS2_addh,              // Add to high accumulator
TMS2_addk,              // Add to accumulator short immediate
TMS2_adds,              // Add to low accumulator with sign extension suppressed
TMS2_addt,              // Add to accumulator with shift specified by T register
TMS2_adlk,              // Add to accumulator long immediate with shift
TMS2_adrk,              // Add to auxiliary register short immediate
TMS2_and,               // And with accumulator
TMS2_andk,              // And immediate with accumulator with shift
TMS2_apac,              // App P register to accumulator
TMS2_b,                 // Branch unconditionally
TMS2_bacc,              // Branch to address specified by accumulator
TMS2_banz,              // Bnrach on auxiliary register not zero
TMS2_bbnz,              // Branch if tc bit != 0
TMS2_bbz,               // Branch if tc bit = 0
TMS2_bc,                // Branch on carry
TMS2_bgez,              // Branch if accumulator >= 0
TMS2_bgz,               // Branch if accumulator > 0
TMS2_bioz,              // Branch on i/o status = 0
TMS2_bit,               // Test bit
TMS2_bitt,              // Test bit specifed by T register
TMS2_blez,              // Branch if accumulator <= 0
TMS2_blkd,              // Block move from data memory to data memory
TMS2_blkp,              // Block move from program memory to data memory
TMS2_blz,               // Branch if accumulator < 0
TMS2_bnc,               // Branch on no carry
TMS2_bnv,               // Branch if no overflow
TMS2_bnz,               // Branch if accumulator != 0
TMS2_bv,                // Branch on overflow
TMS2_bz,                // Branch if accumulator = 0
TMS2_cala,              // Call subroutine indirect
TMS2_call,              // Call subroutine
TMS2_cmpl,              // Complement accumulator
TMS2_cmpr,              // Compare auxiliary register with auxiliary register ar0
TMS2_cnfd,              // Configure block as data memory
TMS2_cnfp,              // Configure block as program memory
TMS2_conf,              // Configure block as data/program memory
TMS2_dint,              // Disable interrupt
TMS2_dmov,              // Data move in data memory
TMS2_eint,              // Enable interrupt
TMS2_fort,              // Format serial port registers
TMS2_idle,              // Idle until interrupt
TMS2_in,                // Input data from port
TMS2_lac,               // Load accumulator with shift
TMS2_lack,              // Load accumulator short immediate
TMS2_lact,              // Load accumulator with shift specified by T register
TMS2_lalk,              // Load accumulator long immediate with shift
TMS2_lar,               // Load auxiliary register
TMS2_lark,              // Load auxiliary register short immediate
TMS2_larp,              // Load auxiliary register pointer
TMS2_ldp,               // Load data memory page pointer
TMS2_ldpk,              // Load data memory page pointer immediate
TMS2_lph,               // Load high P register
TMS2_lrlk,              // Load auxiliary register long immediate
TMS2_lst,               // Load status register ST0
TMS2_lst1,              // Load status register ST1
TMS2_lt,                // Load T register
TMS2_lta,               // Load T register and accumulate previous product
TMS2_ltd,               // Load T register, accumulate previous product and move data
TMS2_ltp,               // Load T register and store P register in accumulator
TMS2_lts,               // Load T register and subtract previous product
TMS2_mac,               // Multiply and accumulate
TMS2_macd,              // Multiply and accumulate with data move
TMS2_mar,               // Modify auxiliary register
TMS2_mpy,               // Multiply (with T register, store product in P register)
TMS2_mpya,              // Multiply and accumulate previous product
TMS2_mpyk,              // Multiply immediate
TMS2_mpys,              // Multiply and subtract previous product
TMS2_mpyu,              // Multiply unsigned
TMS2_neg,               // Negate accumulator
TMS2_nop,               // No operation
TMS2_norm,              // Normalize contents of accumulator
TMS2_or,                // Or with accumulator
TMS2_ork,               // Or immediate with accumulator with shift
TMS2_out,               // Output data to port
TMS2_pac,               // Load accumulator with P register
TMS2_pop,               // Pop top of stack to low accumulator
TMS2_popd,              // Pop top of stack to data memory
TMS2_pshd,              // Push data memory value onto stack
TMS2_push,              // Push low accumulator onto stack
TMS2_rc,                // Reset carry bit
TMS2_ret,               // Return from subroutine
TMS2_rfsm,              // Reset serial port frame synchronization mode
TMS2_rhm,               // Reset hold mode
TMS2_rol,               // Rotate accumulator left
TMS2_ror,               // Rotate acuumulator right
TMS2_rovm,              // Reset overflow mode
TMS2_rpt,               // Repeat instruction as specified by data memory value
TMS2_rptk,              // Repeat instruction as specified by immediate value
TMS2_rsxm,              // Reset sign extension mode
TMS2_rtc,               // Reset test/control flag
TMS2_rtxm,              // Reset serial port transmit mode
TMS2_rxf,               // Reset external flag
TMS2_sach,              // Store high accumulator with shift
TMS2_sacl,              // Store low accumulator with shift
TMS2_sar,               // Store auxiliary register
TMS2_sblk,              // Subtract from accumulator long immediate with shift
TMS2_sbrk,              // Subtract from auxiliary register short immediate
TMS2_sc,                // Set carry bit
TMS2_sfl,               // Shift accumulator left
TMS2_sfr,               // Shift accumulator right
TMS2_sfsm,              // Set serial port frame synchronization mode
TMS2_shm,               // Set hold mode
TMS2_sovm,              // Set overflow mode
TMS2_spac,              // Subtract P register from accumulator
TMS2_sph,               // Store high P register
TMS2_spl,               // Store low P register
TMS2_spm,               // Set P register output shift mode
TMS2_sqra,              // Square and accumulate
TMS2_sqrs,              // Square and subtract previous product
TMS2_sst,               // Store status register ST0
TMS2_sst1,              // Store status register ST1
TMS2_ssxm,              // Set sign extension mode
TMS2_stc,               // Set test/control flag
TMS2_stxm,              // Set serial port transmit mode
TMS2_sub,               // Subtract from accumulator with shift
TMS2_subb,              // Subtract from accumulator with borrow
TMS2_subc,              // Conditional subtract
TMS2_subh,              // Subtract from high accumulator
TMS2_subk,              // Subtract from accumulator shoft immediate
TMS2_subs,              // Subtract from low accumulator with sign extension suppressed
TMS2_subt,              // Subtract from accumulator with shift specified by T register
TMS2_sxf,               // Set external flag
TMS2_tblr,              // Table read
TMS2_tblw,              // Table write
TMS2_trap,              // Software interrupt
TMS2_xor,               // Exclusive or with accumulator
TMS2_xork,              // Exclusive or immediate with accumulator with shift
TMS2_zac,               // Zero accumulator
TMS2_zalh,              // Zero low accumulator and load high accumulator
TMS2_zalr,              // Zero low accumulator and load high accumulator with rounding
TMS2_zals,              // Zero low accumulator and load high accumulator with sign extension suppressed

TMS_last,

    };

#endif
