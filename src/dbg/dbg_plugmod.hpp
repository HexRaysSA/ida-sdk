#pragma once

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
struct dbg_plugmod_t;
class debmod_t;
extern int data_id; // idb specific data id

//lint -esym(753,dbg_plugmod_t) local struct not referenced
//lint -esym(1762,dbg_plugmod_t::init_plugin) could be made const
//lint -esym(1762,dbg_plugmod_t::term_plugin) could be made const

//--------------------------------------------------------------------------
// HT_UI listener
DECLARE_LISTENER(ui_listener_t, dbg_plugmod_t, pm);

//--------------------------------------------------------------------------
struct dbg_plugmod_base_t : public plugmod_t, public event_listener_t
{
  static constexpr int MAX_BPT_SIZE = 4;

  debugger_t debugger;
  bool debugger_inited = false;
  uchar bpt_code[MAX_BPT_SIZE];
  thid_t idc_thread = NO_THREAD;

  dbg_plugmod_base_t();
  bool idaapi run(size_t arg) override;

  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  virtual debmod_t &get_debmod() newapi = 0;

  drc_t init_debugger(
        const char *hostname,
        int port_num,
        const char *password,
        qstring *errbuf);
  // the above function calls this one after all initialisation done
  virtual void init_debugger_finished() newapi {}
  drc_t term_debugger(void);

  virtual void plugin_run(int /*arg*/) newapi {}

  // debugger_t::ev_update_bpts
  drc_t update_bpts(
        int *nbpts,
        update_bpt_info_t *bpts,
        int nadd,
        int ndel,
        qstring *errbuf);
  // the above function uses this one as a callback to perform operation in dbgmod
  virtual drc_t g_dbgmod_update_bpts(
        int *nbpts,
        update_bpt_info_t *bpts,
        int nadd,
        int ndel,
        qstring *errbuf) newapi;

  // debugger_t::ev_set_dbg_options
  virtual const char *set_dbg_options(const char * /*keyword*/, int /*pri*/, int /*value_type*/, const void * /*value*/) newapi { return IDPOPT_OK; }

  void update_idd_registers(bool get_idaregs=true);

  inline qstring dstr() const
  {
    qstring tmp;
    tmp.sprnt("%" FMT_ZS ":%s%s(%s) data_t %d", get_dbctx_id(), debugger.is_remote() ? "remote " : "", debugger.name, debugger.processor, data_id);
    return tmp;
  }

private:
  bool is_our_event() const;
};
dbg_plugmod_t *get_dbg_plugmod();

//--------------------------------------------------------------------------
struct dbg_plugmod_stub_t : public dbg_plugmod_base_t
{
};

//--------------------------------------------------------------------------
struct dbg_plugmod_user_t : public dbg_plugmod_base_t
{
};
