// x86-specific code (compiled only on IDA side, never on the server side)

#include <dbg.hpp>
#include "pc_regs.hpp"
#include "deb_pc.hpp"

//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTION INFORMATIONS
//
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
#if 0
static void DEBUG_REGVALS(regval_t *values)
{
  for ( int i = 0; i < qnumber(registers); i++ )
  {
    msg("%s = ", registers[i].name);
    switch ( registers[i].dtyp )
    {
      case dt_qword: msg("%016LX\n", values[i].ival); break;
      case dt_dword: msg("%08X\n", values[i].ival); break;
      case dt_word:  msg("%04X\n", values[i].ival); break;
      case dt_tbyte:
        for ( int j = 0; j < sizeof(regval_t); j++ )
        {
          if ( j == 10 )
            msg(" - "); // higher bytes are not used by x86 floats
          msg("%02X ", ((unsigned char*)&values[i])[j]);
        }
          // msg("%02X ", (unsigned short)values[i].fval[j]);
        msg("\n");
        break;
    }
  }
  msg("\n");
}
#endif

//--------------------------------------------------------------------------
drc_t idaapi x86_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t *values,
        qstring *errbuf)
{
  return s_read_registers(thread_id, clsmask, values, errbuf);
}

//--------------------------------------------------------------------------
drc_t idaapi x86_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf)
{
  return s_write_register(thread_id, reg_idx, value, errbuf);
}

//--------------------------------------------------------------------------
int is_x86_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type != BPT_SOFT )
  {
    if ( (debugger.flags & DBG_FLAG_ANYSIZE_HWBPT) == 0 )
      return check_x86_hwbpt(type, ea, len);

    if ( type == 0 )
      return BPT_BAD_TYPE;
  }
  return BPT_OK;
}

//--------------------------------------------------------------------------
void processor_specific_init(void)
{
}

//--------------------------------------------------------------------------
void processor_specific_term(void)
{
}
