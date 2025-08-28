#ifndef __DBG_RPC_HLP__
#define __DBG_RPC_HLP__

#include <pro.h>
#include <range.hpp>
#include <idd.hpp>
#include <network.hpp>

void append_regvals(bytevec_t &s, const regval_t *values, int n, const uchar *regmap);

void append_debug_event(bytevec_t &s, const debug_event_t *ev);
void extract_debug_event(debug_event_t *ev, memory_deserializer_t &mmdsr);

void extract_exception(excinfo_t *exc, memory_deserializer_t &mmdsr);
void append_exception(bytevec_t &s, const excinfo_t *e);

inline void append_breakpoint(bytevec_t &s, const bptaddr_t *info)
{
  s.pack_ea64(info->hea);
  s.pack_ea64(info->kea);
}
inline void extract_breakpoint(bptaddr_t *info, memory_deserializer_t &mmdsr)
{
  info->hea = mmdsr.unpack_ea64();
  info->kea = mmdsr.unpack_ea64();
}
void extract_module_info(modinfo_t *info, memory_deserializer_t &mmdsr);
void append_module_info(bytevec_t &s, const modinfo_t *info);
void extract_process_info_vec(procinfo_vec_t *procs, memory_deserializer_t &mmdsr);
void append_process_info_vec(bytevec_t &s, const procinfo_vec_t *procs);

void extract_call_stack(call_stack_t *trace, memory_deserializer_t &mmdsr);
void append_call_stack(bytevec_t &s, const call_stack_t &trace);

void extract_regobjs(regobjs_t *regargs, bool with_values, memory_deserializer_t &mmdsr);
void append_regobjs(bytevec_t &s, const regobjs_t &regargs, bool with_values);

void extract_appcall(
        regobjs_t *regargs,
        relobj_t *stkargs,
        regobjs_t *retregs,
        memory_deserializer_t &mmdsr);

void append_appcall(
        bytevec_t &s,
        const regobjs_t &regargs,
        const relobj_t &stkargs,
        const regobjs_t *retregs);

void extract_debapp_attrs(
        debapp_attrs_t *attrs,
        memory_deserializer_t &mmdsr);
void append_debapp_attrs(bytevec_t &s, const debapp_attrs_t &attrs);

void extract_dynamic_register_set(
        dynamic_register_set_t *idaregs,
        memory_deserializer_t &mmdsr);
void append_dynamic_register_set(
        bytevec_t &s,
        dynamic_register_set_t &idaregs);

void extract_insn(
        insn_t *insn,
        memory_deserializer_t &mmdsr);
void append_insn(
        bytevec_t &s,
        const insn_t &insn);


inline void append_type(bytevec_t &s, const type_t *str)
{
  s.pack_str((char *)str);
}
void append_type(bytevec_t &s, const tinfo_t &tif);
void extract_type(tinfo_t *tif, memory_deserializer_t &mmdsr);

void extract_memory_info(memory_info_t *info, memory_deserializer_t &mmdsr);
void append_memory_info(bytevec_t &s, const memory_info_t *info);

void extract_scattered_segm(scattered_segm_t *ss, memory_deserializer_t &mmdsr);
void append_scattered_segm(bytevec_t &s, const scattered_segm_t *ss);

void append_exception_info(bytevec_t &s, const exception_info_t *table, int qty);
exception_info_t *extract_exception_info(int qty, memory_deserializer_t &mmdsr);


#endif // __DBG_RPC_HLP__
