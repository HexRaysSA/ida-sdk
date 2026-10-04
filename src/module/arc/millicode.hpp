/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Recognition of the ARC millicode helpers by their name.
 *
 *      The compilers for ARC share the prolog and epilog code between
 *      functions: instead of saving and restoring the callee-saved registers
 *      inline, a function calls a helper that does it, and the epilog helpers
 *      return for it as well. The helpers are recognized by their name;
 *      check_millicode_name() describes what each family does to sp.
 *
 *      Both the processor module and the decompiler read this file.
 *
 */

#ifndef __ARC_MILLICODE_HPP
#define __ARC_MILLICODE_HPP

#include <pro.h>

//------------------------------------------------------------------------
// The frame the ARC4 helpers build starts with the stack back-trace data
// structure, which is 16 bytes: they reserve it, save the registers and the
// arguments of a variadic function above it, and leave fp at its top.
const sval_t ARC_MC_BTSIZE = 16;

enum arc_millicode_t
{
  ARCMC_NONE = 0,       // not a millicode helper

  // MetaWare, ARCompact: the frame is sp-based and the helpers push and pop
  ARCMC_PUSH_NONE,      // __ac_push_none
  ARCMC_PUSH,           // __ac_push_13_to_N
  ARCMC_POP_NONE,       // __ac_pop_none
  ARCMC_POP,            // __ac_pop_13_to_N
  ARCMC_POPV,           // __ac_pop_13_to_Nv
  ARCMC_POP_BLINK,      // __ac_pop_nonev, __ac_pop_blink
  ARCMC_POP_CHAIN,      // __ac_pop_N
  ARCMC_MC_VA,          // __ac_mc_va

  // MetaWare, ARC4: the frame is fp-based and starts with the back-trace data
  // structure; the prolog helpers leave fp pointing at its top
  ARCMC_PROLOG_SAVE,    // __prolog_saveN[_sub4]
  ARCMC_PROLOG_SAVE_SP, // __prolog_saveNsp[_sub4]
  ARCMC_PROLOG_STORE,   // __prolog_storeN
  ARCMC_EPILOG_RESTORE, // __epilog_restoreN[f|_add4[f]]
  ARCMC_EPILOG_LOAD,    // __epilog_loadN[f|_add4[f]]
  ARCMC_STORE_VA,       // __store_va

  // both, and GCC: the registers are saved in the frame of the caller
  ARCMC_SAVE,           // __store13toN, __load13toN, __st_r13_to_rN,
                        // __ld_r13_to_rN
  ARCMC_LOAD_RET,       // __ld_r13_to_rN_ret
};

//------------------------------------------------------------------------
// What the name of a millicode helper says about it.
struct arc_millicode_info_t
{
  arc_millicode_t kind = ARCMC_NONE;
  int reg = 0;          // the highest register the helper covers, 0 if the
                        // name carries none
  bool extra4 = false;  // the "_sub4"/"_add4" shapes take one more slot
};

//------------------------------------------------------------------------
// Does the name end here? A numeric suffix that IDA appended to make the name
// unique is not part of it.
inline bool arc_mc_name_end(const char *p)
{
  if ( *p == '_' )
  {
    ++p;
    while ( qisdigit(*p) )
      ++p;
  }
  return *p == '\0';
}

//------------------------------------------------------------------------
// Is the rest of the name 'suffix'?
inline bool arc_mc_name_suffix(const char *p, const char *suffix)
{
  size_t len = strlen(suffix);
  return strneq(p, suffix, len) && arc_mc_name_end(p + len);
}

//------------------------------------------------------------------------
// Recognize a millicode helper by its name, cleaned up by cleanup_name().
// Leading underscores do not have to be removed by the caller.
inline arc_millicode_t arc_millicode_kind(
        arc_millicode_info_t *out,
        const char *name)
{
  arc_millicode_info_t mc;
  const char *p = name;
  while ( *p == '_' )
    ++p;
  if ( arc_mc_name_suffix(p, "ac_push_none") )
  {
    mc.kind = ARCMC_PUSH_NONE;
  }
  else if ( arc_mc_name_suffix(p, "ac_pop_none") )
  {
    mc.kind = ARCMC_POP_NONE;
  }
  else if ( arc_mc_name_suffix(p, "ac_pop_nonev")
         || arc_mc_name_suffix(p, "ac_pop_blink") )
  {
    mc.kind = ARCMC_POP_BLINK;
  }
  else if ( arc_mc_name_suffix(p, "ac_mc_va") )
  {
    mc.kind = ARCMC_MC_VA;
  }
  else if ( arc_mc_name_suffix(p, "store_va") )
  {
    mc.kind = ARCMC_STORE_VA;
  }
  else
  {
#define ARC_MC_PREFIX(x) (strneq(p, x, strlen(x)) && (p += strlen(x), true))
    char *p2 = nullptr;
    uint64 reg = 0;
    if ( ARC_MC_PREFIX("ac_push_13_to_") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg >= 13 && reg <= 26 && arc_mc_name_end(p2) )
        mc.kind = ARCMC_PUSH;
    }
    else if ( ARC_MC_PREFIX("ac_pop_13_to_") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg >= 13 && reg <= 26 )
      {
        if ( arc_mc_name_end(p2) )
          mc.kind = ARCMC_POP;
        else if ( arc_mc_name_suffix(p2, "v") )
          mc.kind = ARCMC_POPV;
      }
    }
    else if ( ARC_MC_PREFIX("ac_pop_") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg >= 13 && reg <= 26 && arc_mc_name_end(p2) )
        mc.kind = ARCMC_POP_CHAIN;
    }
    else if ( ARC_MC_PREFIX("prolog_save") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg == 0 || reg >= 13 && reg <= 26 )
      {
        if ( arc_mc_name_end(p2) )
        {
          mc.kind = ARCMC_PROLOG_SAVE;
        }
        else if ( arc_mc_name_suffix(p2, "_sub4") )
        {
          mc.kind = ARCMC_PROLOG_SAVE;
          mc.extra4 = true;
        }
        else if ( arc_mc_name_suffix(p2, "sp") )
        {
          mc.kind = ARCMC_PROLOG_SAVE_SP;
        }
        else if ( arc_mc_name_suffix(p2, "sp_sub4") )
        {
          mc.kind = ARCMC_PROLOG_SAVE_SP;
          mc.extra4 = true;
        }
      }
    }
    else if ( ARC_MC_PREFIX("prolog_store") )
    {
      reg = strtoull(p, &p2, 10);
      if ( ( reg == 0 || reg >= 13 && reg <= 26 ) && arc_mc_name_end(p2) )
        mc.kind = ARCMC_PROLOG_STORE;
    }
    else if ( ARC_MC_PREFIX("epilog_restore") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg == 0 || reg >= 13 && reg <= 26 )
      {
        // the "f" versions also restore the flags
        if ( arc_mc_name_end(p2) || arc_mc_name_suffix(p2, "f") )
        {
          mc.kind = ARCMC_EPILOG_RESTORE;
        }
        else if ( arc_mc_name_suffix(p2, "_add4")
               || arc_mc_name_suffix(p2, "_add4f") )
        {
          mc.kind = ARCMC_EPILOG_RESTORE;
          mc.extra4 = true;
        }
      }
    }
    else if ( ARC_MC_PREFIX("epilog_load") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg == 0 || reg >= 13 && reg <= 26 )
      {
        if ( arc_mc_name_end(p2) || arc_mc_name_suffix(p2, "f") )
        {
          mc.kind = ARCMC_EPILOG_LOAD;
        }
        else if ( arc_mc_name_suffix(p2, "_add4")
               || arc_mc_name_suffix(p2, "_add4f") )
        {
          mc.kind = ARCMC_EPILOG_LOAD;
          mc.extra4 = true;
        }
      }
    }
    else if ( ARC_MC_PREFIX("store13to")
           || ARC_MC_PREFIX("load13to")
           || ARC_MC_PREFIX("st_r13_to_r") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg >= 13 && reg <= 26 && arc_mc_name_end(p2) )
        mc.kind = ARCMC_SAVE;
    }
    else if ( ARC_MC_PREFIX("ld_r13_to_r") )
    {
      reg = strtoull(p, &p2, 10);
      if ( reg >= 13 && reg <= 26 )
      {
        if ( arc_mc_name_end(p2) )
          mc.kind = ARCMC_SAVE;
        else if ( arc_mc_name_suffix(p2, "_ret") )
          mc.kind = ARCMC_LOAD_RET;
      }
    }
#undef ARC_MC_PREFIX
    if ( mc.kind != ARCMC_NONE )
      mc.reg = int(reg);
  }
  if ( out != nullptr )
    *out = mc;
  return mc.kind;
}

#endif // __ARC_MILLICODE_HPP
