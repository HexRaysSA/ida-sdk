
#include <segment.hpp>
#include <typeinf.hpp>

#include "dbg_rpc_hlp.h"

//--------------------------------------------------------------------------
void append_memory_info(bytevec_t &s, const memory_info_t *meminf)
{
  s.pack_ea64(meminf->sbase);
  s.pack_ea64(meminf->start_ea - (meminf->sbase << 4));
  s.pack_ea64(meminf->size());
  s.pack_dd(meminf->perm | (meminf->bitness<<4));
  s.pack_str(meminf->name.c_str());
  s.pack_str(meminf->sclass.c_str());
}

//--------------------------------------------------------------------------
void extract_memory_info(memory_info_t *meminf, memory_deserializer_t &mmdsr)
{
  meminf->sbase    = mmdsr.unpack_ea64();
  meminf->start_ea = ea_t(meminf->sbase << 4) + mmdsr.unpack_ea64();
  meminf->end_ea   = meminf->start_ea + mmdsr.unpack_ea64();
  int v = mmdsr.unpack_dd();
  meminf->perm    = uchar(v) & SEGPERM_MAXVAL;
  meminf->bitness = uchar(v>>4);
  meminf->name    = mmdsr.unpack_str();
  meminf->sclass  = mmdsr.unpack_str();
}

//--------------------------------------------------------------------------
void append_scattered_segm(bytevec_t &s, const scattered_segm_t *ss)
{
  s.pack_ea64(ss->start_ea);
  s.pack_ea64(ss->end_ea);
  s.pack_str(ss->name.c_str());
}

//--------------------------------------------------------------------------
void extract_scattered_segm(scattered_segm_t *ss, memory_deserializer_t &mmdsr)
{
  ss->start_ea = mmdsr.unpack_ea64();
  ss->end_ea   = mmdsr.unpack_ea64();
  ss->name     = mmdsr.unpack_str();
}

//--------------------------------------------------------------------------
void append_process_info_vec(bytevec_t &s, const procinfo_vec_t *procs)
{
  size_t size = procs->size();
  s.pack_dd(size);
  for ( size_t i = 0; i < size; i++ )
  {
    const process_info_t &pi = procs->at(i);
    s.pack_dd(pi.pid);
    s.pack_str(pi.name.c_str());
  }
}

//--------------------------------------------------------------------------
void extract_process_info_vec(procinfo_vec_t *procs, memory_deserializer_t &mmdsr)
{
  size_t size = mmdsr.unpack_dd();
  for ( size_t i = 0; i < size; i++ )
  {
    process_info_t &pi = procs->push_back();
    pi.pid  = mmdsr.unpack_dd();
    pi.name = mmdsr.unpack_str();
  }
}

//--------------------------------------------------------------------------
void append_module_info(bytevec_t &s, const modinfo_t *modinf)
{
  s.pack_str(modinf->name);
  s.pack_ea64(modinf->base);
  s.pack_ea64(modinf->size);
  s.pack_ea64(modinf->rebase_to);
}

//--------------------------------------------------------------------------
void extract_module_info(modinfo_t *modinf, memory_deserializer_t &mmdsr)
{
  modinf->name = mmdsr.unpack_str();
  modinf->base = mmdsr.unpack_ea64();
  modinf->size = mmdsr.unpack_ea64();
  modinf->rebase_to = mmdsr.unpack_ea64();
}

//--------------------------------------------------------------------------
void append_exception(bytevec_t &s, const excinfo_t *e)
{
  s.pack_dd(e->code);
  s.pack_dd(e->can_cont);
  s.pack_ea64(e->ea);
  s.pack_str(e->info);
}

//--------------------------------------------------------------------------
void extract_exception(excinfo_t *exc, memory_deserializer_t &mmdsr)
{
  exc->code     = mmdsr.unpack_dd();
  exc->can_cont = mmdsr.unpack_dd() != 0;
  exc->ea       = mmdsr.unpack_ea64();
  exc->info     = mmdsr.unpack_str();
}

//--------------------------------------------------------------------------
void extract_debug_event(debug_event_t *ev, memory_deserializer_t &mmdsr)
{
  ev->set_eid(event_id_t(mmdsr.unpack_dd()));
  ev->pid     = mmdsr.unpack_dd();
  ev->tid     = mmdsr.unpack_dd();
  ev->ea      = mmdsr.unpack_ea64();
  ev->handled = mmdsr.unpack_dd() != 0;
  switch ( ev->eid() )
  {
    case NO_EVENT:         // Not an interesting event
    case STEP:             // One instruction executed
    case PROCESS_DETACHED: // Detached from process
    default:
      break;
    case PROCESS_STARTED:  // New process started
    case PROCESS_ATTACHED: // Attached to running process
    case LIB_LOADED:       // New library loaded
      extract_module_info(&ev->modinfo(), mmdsr);
      break;
    case PROCESS_EXITED:   // Process stopped
    case THREAD_EXITED:    // Thread stopped
      ev->exit_code() = mmdsr.unpack_dd();
      break;
    case BREAKPOINT:       // Breakpoint reached
      extract_breakpoint(&ev->bpt(), mmdsr);
      break;
    case EXCEPTION:        // Exception
      extract_exception(&ev->exc(), mmdsr);
      break;
    case THREAD_STARTED:   // New thread started
    case LIB_UNLOADED:     // Library unloaded
    case INFORMATION:      // User-defined information
      ev->info() = mmdsr.unpack_str();
      break;
  }
}

//--------------------------------------------------------------------------
void append_debug_event(bytevec_t &s, const debug_event_t *ev)
{
  s.pack_dd(ev->eid());
  s.pack_dd(ev->pid);
  s.pack_dd(ev->tid);
  s.pack_ea64(ev->ea);
  s.pack_dd(ev->handled);
  switch ( ev->eid() )
  {
    case NO_EVENT:         // Not an interesting event
    case STEP:             // One instruction executed
    case PROCESS_DETACHED: // Detached from process
    default:
      break;
    case PROCESS_STARTED:  // New process started
    case PROCESS_ATTACHED: // Attached to running process
    case LIB_LOADED:       // New library loaded
      append_module_info(s, &ev->modinfo());
      break;
    case PROCESS_EXITED:   // Process stopped
    case THREAD_EXITED:    // Thread stopped
      s.pack_dd(ev->exit_code());
      break;
    case BREAKPOINT:       // Breakpoint reached
      append_breakpoint(s, &ev->bpt());
      break;
    case EXCEPTION:        // Exception
      append_exception(s, &ev->exc());
      break;
    case THREAD_STARTED:   // New thread started
    case LIB_UNLOADED:     // Library unloaded
    case INFORMATION:      // User-defined information
      s.pack_str(ev->info());
      break;
  }
}

//--------------------------------------------------------------------------
exception_info_t *extract_exception_info(int qty, memory_deserializer_t &mmdsr)
{
  exception_info_t *extable = nullptr;
  if ( qty > 0 )
  {
    extable = OPERATOR_NEW(exception_info_t, qty);
    for ( int i=0; i < qty; i++ )
    {
      extable[i].code  = mmdsr.unpack_dd();
      extable[i].flags = mmdsr.unpack_dd();
      extable[i].name  = mmdsr.unpack_str();
      extable[i].desc  = mmdsr.unpack_str();
    }
  }
  return extable;
}

//--------------------------------------------------------------------------
void append_exception_info(bytevec_t &s, const exception_info_t *table, int qty)
{
  for ( int i=0; i < qty; i++ )
  {
    s.pack_dd(table[i].code);
    s.pack_dd(table[i].flags);
    s.pack_str(table[i].name.c_str());
    s.pack_str(table[i].desc.c_str());
  }
}

//--------------------------------------------------------------------------
void extract_call_stack(call_stack_t *trace, memory_deserializer_t &mmdsr)
{
  int n = mmdsr.unpack_dd();
  trace->resize(n);
  for ( int i=0; i < n; i++ )
  {
    call_stack_info_t &ci = (*trace)[i];
    ci.callea = mmdsr.unpack_ea64();
    ci.funcea = mmdsr.unpack_ea64();
    ci.fp     = mmdsr.unpack_ea64();
    ci.funcok = mmdsr.unpack_dd() != 0;
  }
}

//--------------------------------------------------------------------------
void append_call_stack(bytevec_t &s, const call_stack_t &trace)
{
  int n = trace.size();
  s.pack_dd(n);
  for ( int i=0; i < n; i++ )
  {
    const call_stack_info_t &ci = trace[i];
    s.pack_ea64(ci.callea);
    s.pack_ea64(ci.funcea);
    s.pack_ea64(ci.fp);
    s.pack_dd(ci.funcok);
  }
}

//--------------------------------------------------------------------------
void extract_regobjs(
        regobjs_t *regargs,
        bool with_values,
        memory_deserializer_t &mmdsr)
{
  int n = mmdsr.unpack_dd();
  regargs->resize(n);
  for ( int i=0; i < n; i++ )
  {
    regobj_t &ro = (*regargs)[i];
    ro.regidx = mmdsr.unpack_dd();
    int size  = mmdsr.unpack_dd();
    ro.value.resize(size);
    if ( with_values )
    {
      ro.relocate = mmdsr.unpack_dd();
      mmdsr.unpack_obj(ro.value.begin(), size);
    }
  }
}

//--------------------------------------------------------------------------
static void extract_relobj(relobj_t *stkargs, memory_deserializer_t &mmdsr)
{
  int n = mmdsr.unpack_dd();
  stkargs->resize(n);
  mmdsr.unpack_obj(stkargs->begin(), n);

  stkargs->base = mmdsr.unpack_ea64();

  n = mmdsr.unpack_dd();
  stkargs->ri.resize(n);
  mmdsr.unpack_obj(stkargs->ri.begin(), n);
}

//--------------------------------------------------------------------------
void extract_appcall(
        regobjs_t *regargs,
        relobj_t *stkargs,
        regobjs_t *retregs,
        memory_deserializer_t &mmdsr)
{
  extract_regobjs(regargs, true, mmdsr);
  extract_relobj(stkargs, mmdsr);
  if ( retregs != nullptr )
    extract_regobjs(retregs, false, mmdsr);
}

//--------------------------------------------------------------------------
void append_regobjs(bytevec_t &s, const regobjs_t &regargs, bool with_values)
{
  s.pack_dd(regargs.size());
  for ( size_t i=0; i < regargs.size(); i++ )
  {
    const regobj_t &ro = regargs[i];
    s.pack_dd(ro.regidx);
    s.pack_dd(ro.value.size());
    if ( with_values )
    {
      s.pack_dd(ro.relocate);
      s.append(ro.value.begin(), ro.value.size());
    }
  }
}

//--------------------------------------------------------------------------
static void append_relobj(bytevec_t &s, const relobj_t &stkargs)
{
  s.pack_buf(stkargs.begin(), stkargs.size());
  s.pack_ea64(stkargs.base);
  s.pack_buf(stkargs.ri.begin(), stkargs.ri.size());
}

//--------------------------------------------------------------------------
void append_appcall(
        bytevec_t &s,
        const regobjs_t &regargs,
        const relobj_t &stkargs,
        const regobjs_t *retregs)
{
  append_regobjs(s, regargs, true);
  append_relobj(s, stkargs);
  if ( retregs != nullptr )
    append_regobjs(s, *retregs, false);
}

//--------------------------------------------------------------------------
void append_regvals(bytevec_t &s, const regval_t *values, int n, const uchar *regmap)
{
  for ( int i=0; i < n; i++ )
    if ( regmap == nullptr || test_bit(regmap, i) )
      append_regval(s, values[i]);
}

//--------------------------------------------------------------------------
void extract_debapp_attrs(debapp_attrs_t *attrs, memory_deserializer_t &mmdsr)
{
  attrs->addrsize = mmdsr.unpack_dd();
  attrs->platform = mmdsr.unpack_str();
}

//--------------------------------------------------------------------------
void append_debapp_attrs(bytevec_t &s, const debapp_attrs_t &attrs)
{
  s.pack_dd(attrs.addrsize);
  s.pack_str(attrs.platform.c_str());
}

//--------------------------------------------------------------------------
void extract_dynamic_register_set(
        dynamic_register_set_t *idaregs,
        memory_deserializer_t &mmdsr)
{
  deserialize_dynamic_register_set(idaregs, mmdsr);
}

//--------------------------------------------------------------------------
void append_dynamic_register_set(
        bytevec_t &s,
        dynamic_register_set_t &idaregs)
{
  serialize_dynamic_register_set(&s, idaregs);
}

//--------------------------------------------------------------------------
void extract_insn(
        insn_t *insn,
        memory_deserializer_t &mmdsr)
{
  deserialize_insn(insn, mmdsr);
}

//--------------------------------------------------------------------------
void append_insn(
        bytevec_t &s,
        const insn_t &insn)
{
  serialize_insn(&s, insn);
}
