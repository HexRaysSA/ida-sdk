
#ifndef __IDAIDP_HPP
#define __IDAIDP_HPP

// Common include files for IDP modules:

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <problems.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <kernwin.hpp>
#include <mergemod.hpp>

#define DECLARE_PROC_LISTENER(listener_type, parent_type) \
  DECLARE_LISTENER(listener_type, parent_type, pm)

// Current processor in the module
// It must be exported
idaman processor_t ida_module_data LPH;

void idaapi out_insn(outctx_t &ctx);
void idaapi out_mnem(outctx_t &ctx);
bool idaapi out_opnd(outctx_t &ctx, const op_t &x);

// use this define if the default out_mnem() is good enough
#define DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(CTXNAME)      \
  void idaapi out_insn(outctx_t &ctx)                   \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    p->out_insn();                                      \
  }                                                     \
  bool idaapi out_opnd(outctx_t &ctx, const op_t &x)    \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    return p->out_operand(x);                           \
  }

// use this define if you want to print insn mnemonics yourself
#define DECLARE_OUT_FUNCS(CTXNAME)                      \
  DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(CTXNAME)            \
  void idaapi out_mnem(outctx_t &ctx)                   \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    p->out_proc_mnem();                                 \
  }

//--------------------------------------------------------------------------
inline bool print_predefined_segname(
        outctx_t &ctx,
        qstring *sname,
        const char *const predefined[],
        size_t n)
{
  for ( size_t i=0; i < n; i++ )
  {
    if ( *sname == predefined[i] )
    {
      ctx.gen_printf(DEFAULT_INDENT, COLSTR("%s", SCOLOR_ASMDIR), sname->c_str());
      return true;
    }
  }
  validate_name(sname, VNT_IDENT);
  return false;
}

//--------------------------------------------------------------------------
// is the ELF header magic at EA?
inline bool is_elf_magic(ea_t ea)
{
  uint32 magic = get_dword(ea);
  if ( inf_is_be() )
    magic = swap32(magic);
  return magic == 0x464C457F; // "\x7FELF"
}

//--------------------------------------------------------------------------
// may the address 0 be the entry of a function? only an ELF file may have
// code there, and only when its header is not mapped at 0
inline bool may_func_start_at_zero()
{
  return inf_get_filetype() == f_ELF && !is_elf_magic(0);
}

//--------------------------------------------------------------------------
// A function to create merge handlers for module.
// This function is defined by processor modules.
void create_std_procmod_handlers(merge_data_t &md);

#endif // __IDAIDP_HPP
