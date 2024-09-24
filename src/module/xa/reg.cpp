/*
        This module has been created by Petr Novak
 */

#include "xa.hpp"
#include <entry.hpp>
#include <segregs.hpp>

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "R0L", "R0H", "R1L", "R1H", "R2L", "R2H", "R3L", "R3H",
  "R4L", "R4H", "R5L", "R5H", "R6L", "R6H", "R7L", "R7H",
  "R0",  "R1",  "R2",  "R3",  "R4",  "R5",  "R6",  "R7",
  "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15",
  "A", "DPTR", "C", "PC", "USP",
  "CS","DS", "ES",
};

//----------------------------------------------------------------------

const predefined_t iregs[] =
{
  { prc_xaG3,  0x6A, 0, "BCR",       "Bus configuration register" },
  { prc_xaG3,  0x69, 0, "BTRH",      "Bus timing register high byte" },
  { prc_xaG3,  0x68, 0, "BTRL",      "Bus timing register low byte" },
  { prc_xaG3,  0x43, 0, "CS",        "Code segment" },
  { prc_xaG3,  0x41, 0, "DS",        "Data segment" },
  { prc_xaG3,  0x42, 0, "ES",        "Extra segment" },
  { prc_xaG3,  0x27, 0, "IEH",       "Interrupt enable high byte" },
  { prc_xaG3,  0x26, 0, "IEL",       "Interrupt enable low byte" },
  { prc_xaG3,  0xa0, 0, "IPA0",      "Interrupt priority 0" },
  { prc_xaG3,  0xa1, 0, "IPA1",      "Interrupt priority 1" },
  { prc_xaG3,  0xa2, 0, "IPA2",      "Interrupt priority 2" },
  { prc_xaG3,  0xa3, 0, "IPA3",      "Interrupt priority 3" },
  { prc_xaG3,  0xa4, 0, "IPA4",      "Interrupt priority 4" },
  { prc_xaG3,  0xa5, 0, "IPA5",      "Interrupt priority 5" },
  { prc_xaG3,  0x30, 0, "P0",        "Port 0" },
  { prc_xaG3,  0x31, 0, "P1",        "Port 1" },
  { prc_xaG3,  0x32, 0, "P2",        "Port 2" },
  { prc_xaG3,  0x33, 0, "P3",        "Port 3" },
  { prc_xaG3,  0x70, 0, "P0CFGA",    "Port 0 configuration A" },
  { prc_xaG3,  0x71, 0, "P1CFGA",    "Port 1 configuration A" },
  { prc_xaG3,  0x72, 0, "P2CFGA",    "Port 2 configuration A" },
  { prc_xaG3,  0x73, 0, "P3CFGA",    "Port 3 configuration A" },
  { prc_xaG3,  0xF0, 0, "P0CFGB",    "Port 0 configuration B" },
  { prc_xaG3,  0xF1, 0, "P1CFGB",    "Port 1 configuration B" },
  { prc_xaG3,  0xF2, 0, "P2CFGB",    "Port 2 configuration B" },
  { prc_xaG3,  0xF3, 0, "P3CFGB",    "Port 3 configuration B" },
  { prc_xaG3,  0x04, 0, "PCON",      "Power control register" },
  { prc_xaG3,  0x01, 0, "PSWH",      "Program status word high byte" },
  { prc_xaG3,  0x00, 0, "PSWL",      "Program status word low byte" },
  { prc_xaG3,  0x02, 0, "PSW51",     "8051 compatible PSW" },
  { prc_xaG3,  0x55, 0, "RTH0",      "Timer 0 extender reload high byte" },
  { prc_xaG3,  0x57, 0, "RTH1",      "Timer 1 extender reload high byte" },
  { prc_xaG3,  0x54, 0, "RTL0",      "Timer 0 extender reload low byte" },
  { prc_xaG3,  0x56, 0, "RTL1",      "Timer 1 extender reload low byte" },
  { prc_xaG3,  0x20, 0, "S0CON",     "Serial port 0 control register" },
  { prc_xaG3,  0x21, 0, "S0STAT",    "Serial port 0 extended status" },
  { prc_xaG3,  0x60, 0, "S0BUF",     "Serial port 0 buffer register" },
  { prc_xaG3,  0x61, 0, "S0ADDR",    "Serial port 0 address register" },
  { prc_xaG3,  0x62, 0, "S0ADEN",    "Serial port 0 address enable" },
  { prc_xaG3,  0x24, 0, "S1CON",     "Serial port 1 control register" },
  { prc_xaG3,  0x25, 0, "S1STAT",    "Serial port 1 extended status" },
  { prc_xaG3,  0x64, 0, "S1BUF",     "Serial port 1 buffer register" },
  { prc_xaG3,  0x65, 0, "S1ADDR",    "Serial port 1 address register" },
  { prc_xaG3,  0x66, 0, "S1ADEN",    "Serial port 1 address enable" },
  { prc_xaG3,  0x40, 0, "SCR",       "System configuration register" },
  { prc_xaG3,  0x03, 0, "SSEL",      "Segment selection register" },
  { prc_xaG3,  0x7A, 0, "SWE",       "Software interrupt enable" },
  { prc_xaG3,  0x2A, 0, "SWR",       "Software interrupt reguest" },
  { prc_xaG3,  0x18, 0, "T2CON",     "Timer 2 control register" },
  { prc_xaG3,  0x19, 0, "T2MOD",     "Timer 2 mode control" },
  { prc_xaG3,  0x59, 0, "TH2",       "Timer 2 high byte" },
  { prc_xaG3,  0x58, 0, "TL2",       "Timer 2 low byte" },
  { prc_xaG3,  0x5B, 0, "T2CAPH",    "Timer 2 capture register high byte" },
  { prc_xaG3,  0x5A, 0, "T2CAPL",    "Timer 2 capture register low byte" },
  { prc_xaG3,  0x10, 0, "TCON",      "Timer 0 and 1 control register" },
  { prc_xaG3,  0x51, 0, "TH0",       "Timer 0 high byte" },
  { prc_xaG3,  0x53, 0, "TH1",       "Timer 1 high byte" },
  { prc_xaG3,  0x50, 0, "TL0",       "Timer 0 low byte" },
  { prc_xaG3,  0x52, 0, "TL1",       "Timer 1 low byte" },
  { prc_xaG3,  0x5C, 0, "TMOD",      "Timer 0 and 1 mode control" },
  { prc_xaG3,  0x11, 0, "TSTAT",     "Timer 0 and 1 extended status" },
  { prc_xaG3,  0x1F, 0, "WDCON",     "Watchdog control register" },
  { prc_xaG3,  0x5F, 0, "WDL",       "Watchdog timer reload" },
  { prc_xaG3,  0x5D, 0, "WFEED1",    "Watchdog feed 1" },
  { prc_xaG3,  0x5E, 0, "WFEED2",    "Watchdog feed 2" },
  { prc_xaG3,  0x00, 0, nullptr,        nullptr }
};

const predefined_t ibits[] =
{
  { prc_xaG3, 0x427, 0, "ERI0",      "IEH.0 - " },
  { prc_xaG3, 0x427, 1, "ETI0",      "IEH.1 - " },
  { prc_xaG3, 0x427, 2, "ERI1",      "IEH.2 - " },
  { prc_xaG3, 0x427, 3, "ETI1",      "IEH.3 - " },
  { prc_xaG3, 0x426, 0, "EX0",       "IEL.0 - " },
  { prc_xaG3, 0x426, 1, "ET0",       "IEL.1 - " },
  { prc_xaG3, 0x426, 2, "EX1",       "IEL.2 - " },
  { prc_xaG3, 0x426, 3, "ET1",       "IEL.3 - " },
  { prc_xaG3, 0x426, 4, "ET2",       "IEL.4 - " },
  { prc_xaG3, 0x426, 7, "EA",        "IEL.7 - " },
  { prc_xaG3, 0x426, 7, "EA",        "IEL.7 - " },
  { prc_xaG3, 0x404, 0, "IDL",       "PCON.0 - Idle Mode Bit" },
  { prc_xaG3, 0x404, 1, "PD",        "PCON.1 - Power Down Mode Bit" },
  { prc_xaG3, 0x401, 0, "IM0",       "PSWH.0 - Interrupt mask 0" },
  { prc_xaG3, 0x401, 1, "IM1",       "PSWH.1 - Interrupt mask 1" },
  { prc_xaG3, 0x401, 2, "IM2",       "PSWH.2 - Interrupt mask 2" },
  { prc_xaG3, 0x401, 3, "IM3",       "PSWH.3 - Interrupt mask 3" },
  { prc_xaG3, 0x401, 4, "RS0",       "PSWH.4 - Register select 0" },
  { prc_xaG3, 0x401, 5, "RS1",       "PSWH.5 - Register select 1" },
  { prc_xaG3, 0x401, 6, "TM",        "PSWH.6 - Trace mode" },
  { prc_xaG3, 0x401, 7, "SM",        "PSWH.7 - System mode" },
  { prc_xaG3, 0x400, 0, "Z",         "PSWL.0 - Zero flag" },
  { prc_xaG3, 0x400, 1, "N",         "PSWL.1 - Negative flag" },
  { prc_xaG3, 0x400, 2, "V",         "PSWL.2 - Overflow flag" },
  { prc_xaG3, 0x400, 6, "AC",        "PSWL.6 - Auxiliary carry flag" },
  { prc_xaG3, 0x400, 7, "CY",        "PSWL.7 - Carry flag" },
  { prc_xaG3, 0x420, 0, "RI_0",      "S0CON.0 -" },
  { prc_xaG3, 0x420, 1, "TI_0",      "S0CON.1 -" },
  { prc_xaG3, 0x420, 2, "RB8_0",     "S0CON.2 -" },
  { prc_xaG3, 0x420, 3, "TB8_0",     "S0CON.3 -" },
  { prc_xaG3, 0x420, 4, "REN_0",     "S0CON.4 -" },
  { prc_xaG3, 0x420, 5, "SM2_0",     "S0CON.5 -" },
  { prc_xaG3, 0x420, 6, "SM1_0",     "S0CON.6 -" },
  { prc_xaG3, 0x420, 7, "SM0_0",     "S0CON.7 -" },
  { prc_xaG3, 0x421, 0, "STINT0",    "S0STAT.0 -" },
  { prc_xaG3, 0x421, 1, "OE0",       "S0STAT.1 -" },
  { prc_xaG3, 0x421, 2, "BR0",       "S0STAT.2 -" },
  { prc_xaG3, 0x421, 3, "FE0",       "S0STAT.3 -" },
  { prc_xaG3, 0x424, 0, "RI_1",      "S1CON.0 -" },
  { prc_xaG3, 0x424, 1, "TI_1",      "S1CON.1 -" },
  { prc_xaG3, 0x424, 2, "RB8_1",     "S1CON.2 -" },
  { prc_xaG3, 0x424, 3, "TB8_1",     "S1CON.3 -" },
  { prc_xaG3, 0x424, 4, "REN_1",     "S1CON.4 -" },
  { prc_xaG3, 0x424, 5, "SM2_1",     "S1CON.5 -" },
  { prc_xaG3, 0x424, 6, "SM1_1",     "S1CON.6 -" },
  { prc_xaG3, 0x424, 7, "SM0_1",     "S1CON.7 -" },
  { prc_xaG3, 0x425, 0, "STINT1",    "S1STAT.0 -" },
  { prc_xaG3, 0x425, 1, "OE1",       "S1STAT.1 -" },
  { prc_xaG3, 0x425, 2, "BR1",       "S1STAT.2 -" },
  { prc_xaG3, 0x425, 3, "FE1",       "S1STAT.3 -" },
  { prc_xaG3, 0x403, 0, "R0SEG",     "SSEL.0 -" },
  { prc_xaG3, 0x403, 1, "R1SEG",     "SSEL.1 -" },
  { prc_xaG3, 0x403, 2, "R2SEG",     "SSEL.2 -" },
  { prc_xaG3, 0x403, 3, "R3SEG",     "SSEL.3 -" },
  { prc_xaG3, 0x403, 4, "R4SEG",     "SSEL.4 -" },
  { prc_xaG3, 0x403, 5, "R5SEG",     "SSEL.5 -" },
  { prc_xaG3, 0x403, 6, "R6SEG",     "SSEL.6 -" },
  { prc_xaG3, 0x403, 7, "ESWEN",     "SSEL.7 -" },
  { prc_xaG3, 0x42A, 0, "SWR1",      "SWR.0 -" },
  { prc_xaG3, 0x42A, 1, "SWR2",      "SWR.1 -" },
  { prc_xaG3, 0x42A, 2, "SWR3",      "SWR.2 -" },
  { prc_xaG3, 0x42A, 3, "SWR4",      "SWR.3 -" },
  { prc_xaG3, 0x42A, 4, "SWR5",      "SWR.4 -" },
  { prc_xaG3, 0x42A, 5, "SWR6",      "SWR.5 -" },
  { prc_xaG3, 0x42A, 6, "SWR7",      "SWR.6 -" },
  { prc_xaG3, 0x418, 0, "CPRL2",     "T2CON.0 -" },
  { prc_xaG3, 0x418, 1, "CT2",       "T2CON.1 -" },
  { prc_xaG3, 0x418, 2, "TR2",       "T2CON.2 -" },
  { prc_xaG3, 0x418, 3, "EXEN2",     "T2CON.3 -" },
  { prc_xaG3, 0x418, 4, "TCLK0",     "T2CON.4 -" },
  { prc_xaG3, 0x418, 5, "RCLK0",     "T2CON.5 -" },
  { prc_xaG3, 0x418, 6, "EXF2",      "T2CON.6 -" },
  { prc_xaG3, 0x418, 7, "TF2",       "T2CON.7 -" },
  { prc_xaG3, 0x419, 0, "DCEN",      "T2MOD.0 -" },
  { prc_xaG3, 0x419, 1, "T2OE",      "T2MOD.1 -" },
  { prc_xaG3, 0x419, 2, "T2RD",      "T2MOD.2 -" },
  { prc_xaG3, 0x419, 4, "TCLK1",     "T2MOD.4 -" },
  { prc_xaG3, 0x419, 5, "RCLK1",     "T2MOD.5 -" },
  { prc_xaG3, 0x410, 0, "IT0",       "TCON.0 -" },
  { prc_xaG3, 0x410, 1, "IE0",       "TCON.1 -" },
  { prc_xaG3, 0x410, 2, "IT1",       "TCON.2 -" },
  { prc_xaG3, 0x410, 3, "IE1",       "TCON.3 -" },
  { prc_xaG3, 0x410, 4, "TR0",       "TCON.4 -" },
  { prc_xaG3, 0x410, 6, "TF0",       "TCON.5 -" },
  { prc_xaG3, 0x410, 6, "TR1",       "TCON.6 -" },
  { prc_xaG3, 0x410, 7, "TF1",       "TCON.7 -" },
  { prc_xaG3, 0x411, 0, "T0OE",      "TSTAT.0 -" },
  { prc_xaG3, 0x411, 1, "T0RD",      "TSTAT.1 -" },
  { prc_xaG3, 0x411, 2, "T1OE",      "TSTAT.2 -" },
  { prc_xaG3, 0x411, 3, "T1RD",      "TSTAT.3 -" },
  { prc_xaG3, 0x41f, 1, "WDTOF",     "WDCON.1 -" },
  { prc_xaG3, 0x41f, 2, "WDRUN",     "WDCON.2 -" },
  { prc_xaG3, 0x41f, 5, "PRE0",      "WDCON.5 -" },
  { prc_xaG3, 0x41f, 6, "PRE1",      "WDCON.6 -" },
  { prc_xaG3, 0x41f, 7, "PRE2",      "WDCON.7 -" },
  { prc_xaG3, 0x000, 0, nullptr,        nullptr }
};

//----------------------------------------------------------------------
int xa_t::IsPredefined(const char *name)
{
  const predefined_t *ptr;

  for ( ptr = ibits; ptr->name != nullptr; ptr++ )
    if ( strcmp(ptr->name, name) == 0 )
      return 1;

  for ( ptr = iregs; ptr->name != nullptr; ptr++ )
    if ( strcmp(ptr->name, name) == 0 )
      return 1;

  return 0;
}

//----------------------------------------------------------------------
const predefined_t *xa_t::GetPredefined(const predefined_t *ptr, int addr, int bit) const
{
  for ( ; ptr->name != nullptr; ptr++ )
  {
    if ( ptr->proc != ptype )
      continue;
    if ( addr == ptr->addr && bit == ptr->bit )
      return ptr;
  }
  return nullptr;
}

//----------------------------------------------------------------------
const predefined_t *xa_t::GetPredefinedBits(int addr, int bit) const
{
  return GetPredefined(ibits, addr, bit);
}

//----------------------------------------------------------------------
void xa_t::attach_bit_comment(const insn_t &insn, int addr, int bit) const
{
  const predefined_t *predef = GetPredefined(ibits, addr, bit);
  if ( predef != nullptr && get_cmt(nullptr, insn.ea, false) <= 0 )
    set_cmt(insn.ea,predef->cmt,0);
}

struct entry_t
{
  const char *name;
  const char *cmt;
  uint32 off;
  char proc;
};

static entry_t const entries[] =
{
#define ENTRY(proc, off, name, cmt) { name, cmt, off, proc }
  ENTRY(prc_xaG3,  0x00, "Reset", "Reset (h/w, watchdog, s/w)"),
  ENTRY(prc_xaG3,  0x04, "Breakpoint", "Breakpoint instruction (h/w trap 1)"),
  ENTRY(prc_xaG3,  0x08, "Trace", "Trace (h/w trap 2)"),
  ENTRY(prc_xaG3,  0x0C, "StackOverflow", "Stack Overflow (h/w trap 3)"),
  ENTRY(prc_xaG3,  0x10, "DivBy0", "Divide by 0 (h/w trap 4)"),
  ENTRY(prc_xaG3,  0x14, "UserRETI", "User RETI (h/w trap 5)"),
  ENTRY(prc_xaG3,  0x40, "Trap0",   "Software TRAP 0"),
  ENTRY(prc_xaG3,  0x44, "Trap1",   "Software TRAP 1"),
  ENTRY(prc_xaG3,  0x48, "Trap2",   "Software TRAP 2"),
  ENTRY(prc_xaG3,  0x4C, "Trap3",   "Software TRAP 3"),
  ENTRY(prc_xaG3,  0x50, "Trap4",   "Software TRAP 4"),
  ENTRY(prc_xaG3,  0x54, "Trap5",   "Software TRAP 5"),
  ENTRY(prc_xaG3,  0x58, "Trap6",   "Software TRAP 6"),
  ENTRY(prc_xaG3,  0x5C, "Trap7",   "Software TRAP 7"),
  ENTRY(prc_xaG3,  0x60, "Trap8",   "Software TRAP 8"),
  ENTRY(prc_xaG3,  0x64, "Trap9",   "Software TRAP 9"),
  ENTRY(prc_xaG3,  0x68, "Trap10",  "Software TRAP 10"),
  ENTRY(prc_xaG3,  0x6C, "Trap11",  "Software TRAP 11"),
  ENTRY(prc_xaG3,  0x70, "Trap12",  "Software TRAP 12"),
  ENTRY(prc_xaG3,  0x74, "Trap13",  "Software TRAP 13"),
  ENTRY(prc_xaG3,  0x78, "Trap14",  "Software TRAP 14"),
  ENTRY(prc_xaG3,  0x7C, "Trap15",  "Software TRAP 15"),
  ENTRY(prc_xaG3,  0x80, "ExtInt0", "External Interrupt 0"),
  ENTRY(prc_xaG3,  0x84, "TimerInt0",  "Timer 0 Interrupt"),
  ENTRY(prc_xaG3,  0x88, "ExtInt1",    "External Interrupt 1"),
  ENTRY(prc_xaG3,  0x8C, "TimerInt1",  "Timer 1 Interrupt"),
  ENTRY(prc_xaG3,  0x90, "TimerInt2",  "Timer 2 Interrupt"),
  ENTRY(prc_xaG3,  0xA0, "SerIntRx0",  "Serial port 0 Rx"),
  ENTRY(prc_xaG3,  0xA4, "SerIntTx0",  "Serial port 0 Tx"),
  ENTRY(prc_xaG3,  0xA8, "SerIntRx1",  "Serial port 1 Rx"),
  ENTRY(prc_xaG3,  0xAC, "SerIntTx1",  "Serial port 1 Tx"),
  ENTRY(prc_xaG3, 0x100, "SWI1",  "Software Interrupt 1"),
  ENTRY(prc_xaG3, 0x104, "SWI2",  "Software Interrupt 2"),
  ENTRY(prc_xaG3, 0x108, "SWI3",  "Software Interrupt 3"),
  ENTRY(prc_xaG3, 0x10C, "SWI4",  "Software Interrupt 4"),
  ENTRY(prc_xaG3, 0x110, "SWI5",  "Software Interrupt 5"),
  ENTRY(prc_xaG3, 0x114, "SWI6",  "Software Interrupt 6"),
  ENTRY(prc_xaG3, 0x118, "SWI7",  "Software Interrupt 7"),
#undef ENTRY
};

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(new xa_t);
  return 0;
}

//--------------------------------------------------------------------------
// The kernel event notifications
// Here you may take desired actions upon some kernel events
ssize_t idaapi xa_t::on_event(ssize_t msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf_set_be(false);       // Set a little endian mode of the IDA kernel
      break;

    case processor_t::ev_newfile:
      {
        segment_t *sptr = get_first_seg();
        if ( sptr != nullptr )
        {
          if ( sptr->start_ea-get_segm_base(sptr) == 0 )
          {
            inf_set_start_ea(sptr->start_ea);
            inf_set_start_ip(BADADDR);
            if ( sptr->size() > 0x10000 )
            {
              ea_t end_ea = sptr->end_ea;
              ea_t start_ea = sptr->start_ea;

              if ( end_ea & 0xFFFF )
              {
                ea_t start = end_ea & 0xFFFF0000;
                add_segm(start >> 4, start, end_ea, "ROMxx", "CODE");
                end_ea = start;
              }
              for ( ea_t start = end_ea - 0x10000;
                    start > start_ea;
                    end_ea -= 0x10000, start -= 0x10000 )
              {
                char sname[32];
                qsnprintf(sname, sizeof(sname), "RAM%02x", int((start&0xFF0000)>>16));

                add_segm(start>>4, start, start+0x10000, sname, "CODE");
              }
              sptr = getseg(start_ea);
              set_segm_name(sptr, "ROM00");
              set_segm_class(sptr, "CODE");
            }
            for ( int i=0; i < qnumber(entries); i++ )
            {
              if ( entries[i].proc > ptype )
                continue;
              ea_t ea = inf_get_start_ea()+entries[i].off;
              if ( is_mapped(ea) && get_byte(ea) == 0 )
              {
                add_entry(ea, ea, entries[i].name, 0);
                create_word(ea, 2);
                create_word(ea+2, 2);
                op_offset(ea+2, 0, REF_OFF16, get_word(ea+2));
                add_cref(ea+2, get_word(ea+2), fl_CN);
                set_cmt(ea, entries[i].cmt, 1);
              }
            }
          }
        }

        add_segm(INTMEMBASE>>4, INTMEMBASE, INTMEMBASE+0x400, "INTMEM", "DATA");
        add_segm(INTMEMBASE>>4, SFRBASE, SFRBASE+0x400, "SFR", "DATA");

        // the default data segment will be INTMEM
        set_default_dataseg(getseg(INTMEMBASE)->sel);

        const predefined_t *ptr;
        for ( ptr=iregs; ptr->name != nullptr; ptr++ )
        {
          ea_t ea = SFRBASE + ptr->addr;
          ea_t oldea = get_name_ea(BADADDR, ptr->name);
          if ( oldea != ea )
          {
            if ( oldea != BADADDR )
              del_global_name(oldea);
            create_byte(ea, 1);
            set_name(ea, ptr->name, SN_NOCHECK|SN_NODUMMY);
          }
          if ( ptr->cmt != nullptr )
            set_cmt(ea, ptr->cmt, 0);
        }

        // Perform the final pass of analysis even for the binary files
        if ( inf_get_filetype() == f_BIN )
          inf_set_af(inf_get_af() | AF_FINAL);
      }
      break;

    case processor_t::ev_oldfile:
      break;

    case processor_t::ev_creating_segm:
        // make the default DS point to INTMEM
      {
        segment_t *newseg = va_arg(va, segment_t *);
        segment_t *intseg = getseg(INTMEMBASE);
        if ( intseg != nullptr )
          newseg->defsr[rDS-ph.reg_first_sreg] = intseg->sel;
      }
      break;

    case processor_t::ev_newprc:
      {
        processor_subtype_t prcnum = processor_subtype_t(va_arg(va, int));
        // bool keep_cfg = va_argi(va, bool);
        ptype = prcnum;
      }
      break;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        xa_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        xa_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        xa_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        xa_data(*ctx, analyze_only);
        return 1;
      }

    case processor_t::ev_is_switch:
      {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return xa_is_switch(si, *insn) ? 1 : 0;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        xa_create_func(pfn);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = xa_frame_retsize(pfn);
        return 1;
      }

    case processor_t::ev_gen_stkvar_def:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const udm_t *stkvar = va_arg(va, const udm_t *);
        sval_t v = va_arg(va, sval_t);
        xa_stkvar_def(*ctx, stkvar, v);
        return 1;
      }

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return xa_align_insn(ea);
      }

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
//
//              Definitions of the target assemblers
//              8051 has unusually many of them.
//

//-----------------------------------------------------------------------
//                   XA Assembler by Macraigor Systems
//-----------------------------------------------------------------------
static const asm_t xaasm =
{
  AS_COLON | ASH_HEXF0,
  UAS_PBIT | UAS_SECT,
  "XA Macro Assembler dummy entry",
  0,
  nullptr,         // no headers
  "org",
  "end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  "long",       // dword  (4 bytes)
  nullptr,         // qword  (8 bytes)
  nullptr,         // oword  (16 bytes)
  nullptr,         // float  (4 bytes)
  nullptr,         // double (8 bytes)
  nullptr,         // tbyte  (10/12 bytes)
  nullptr,         // packed decimal real
  "#d dup(#v)",         // arrays (#h,#d,#v,#s(...)
  "ds %s",      // uninited arrays
  "reg",        // equ
  nullptr,         // seg prefix
  "$",
  nullptr,         // func_header
  nullptr,         // func_footer
  nullptr,         // public
  nullptr,         // weak
  nullptr,         // extrn
  nullptr,         // comm
  nullptr,         // get_type_name
  "align",              // align
  '(', ')',     // lbrace, rbrace
  nullptr,    // mod
  "&",    // and
  "|",    // or
  "^",    // xor
  "not",    // not
  "shl",    // shl
  "shr",    // shr
  nullptr,    // sizeof
};

static const asm_t *const asms[] = { &xaasm, nullptr };
//-----------------------------------------------------------------------
// The short and long names of the supported processors
#define FAMILY "Philips 51XA Series:"

static const char *const shnames[] =
{
  "51XA-G3",
  nullptr
};

static const char *const lnames[] =
{
  FAMILY"Philips 51XA G3",
  nullptr
};

//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static const uchar retcode_1[] = { 0xd6, 0x80 };
static const uchar retcode_2[] = { 0xd6, 0x90 };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, nullptr }                            // nullptr terminated array
};

#define PLFM_XA 0x8051

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_XA,                // id
                          // flag
    PR_SEGS
  | PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM,            // The module creates RAM/ROM segments for binary files
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  RegNames,             // Regsiter names
  qnumber(RegNames),    // Number of registers

  rCS,rES,
  1,                    // size of a segment register
  rCS,rDS,

  nullptr,                 // No known code start sequences
  retcodes,

  0,XA_last,
  Instructions,         // instruc
  0,                    // tbyte_size
  {0,0,0,0},            // real_width
  XA_ret,               // icode_return
  nullptr                  // DEPREECATED: is_align_insn

,};
