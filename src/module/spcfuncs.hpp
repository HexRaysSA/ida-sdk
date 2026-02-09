/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _SPCFUNCS_H
#define _SPCFUNCS_H

enum special_func_t
{
  SPF_NONE,
  SPF_GNU_MCOUNT_NC,
  SPF_SECURITY_PUSH_COOKIE,
  SPF_SECURITY_POP_COOKIE,
  SPF_ALLOCA_PROBE,
  SPF_SAVE,
  SPF_RETURN,
};

special_func_t is_special_func(ea_t ea);
bool is_gnu_mcount_nc(ea_t ea);

#endif
