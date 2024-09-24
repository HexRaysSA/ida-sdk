// Highlighter plugin v1.0
// Highlights executed instructions

// This plugin will display a colored box at the executed instructions.
// It will take into account only the instructions where the application
// has been suspended.

// http://www.hexblog.com/2005/11/the_highlighter.html

// Copyright 2005 Ilfak Guilfanov, <ig@hexblog.com>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t;
struct idd_post_events_t : public post_event_visitor_t
{
  plugin_ctx_t &ctx;
  idd_post_events_t(plugin_ctx_t &_ctx) : ctx(_ctx) {}
  virtual ssize_t idaapi handle_post_event(
        ssize_t code,
        int notification_code,
        va_list va) override;
};

//--------------------------------------------------------------------------
struct exec_prefix_t : public user_defined_prefix_t
{
  static const int prefix_width = 1;

  plugin_ctx_t &ctx;
  exec_prefix_t(plugin_ctx_t &_ctx)
    : user_defined_prefix_t(prefix_width, &_ctx), ctx(_ctx) {}

  virtual void idaapi get_user_defined_prefix(
        qstring *out,
        ea_t ea,
        const insn_t &insn,
        int lnnum,
        int indent,
        const char *line) override;
};

//--------------------------------------------------------------------------
typedef std::set<ea_t> easet_t;
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  idd_post_events_t idd_post_events = idd_post_events_t(*this);

  exec_prefix_t *exec_prefix = nullptr;

  // List of executed addresses
  easet_t execset;

  ea_t old_ea = BADADDR;
  int old_lnnum = 0;

  plugin_ctx_t()
  {
    hook_event_listener(HT_DBG, this);
  }
  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
    exec_prefix = nullptr; // make lint happy
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//--------------------------------------------------------------------------
// A sample how to generate user-defined line prefixes
static const char highlight_prefix[] = { COLOR_INV, ' ', COLOR_INV, 0 };
void idaapi exec_prefix_t::get_user_defined_prefix(
        qstring *buf,
        ea_t ea,
        const insn_t &,
        int lnnum,
        int indent,
        const char *line)
{
  buf->qclear();        // empty prefix by default

  // We want to display the prefix only the lines which
  // contain the instruction itself

  if ( indent != -1 )
    return;           // a directive
  if ( line[0] == '\0' )
    return;        // empty line
  if ( tag_advance(line,1)[-1] == ASH.cmnt[0] )
    return; // comment line...

  // We don't want the prefix to be printed again for other lines of the
  // same instruction/data. For that we remember the line number
  // and compare it before generating the prefix

  if ( ctx.old_ea == ea && ctx.old_lnnum == lnnum )
    return;

  if ( ctx.execset.find(ea) != ctx.execset.end() )
    *buf = highlight_prefix;

  // Remember the address and line number we produced the line prefix for:
  ctx.old_ea = ea;
  ctx.old_lnnum = lnnum;
}

//--------------------------------------------------------------------------
ssize_t idaapi idd_post_events_t::handle_post_event(
        ssize_t retcode,
        int notification_code,
        va_list va)
{
  switch ( notification_code )
  {
    case debugger_t::ev_get_debug_event:
      {
        gdecode_t *code = va_arg(va, gdecode_t *);
        debug_event_t *event = va_arg(va, debug_event_t *);
        if ( *code == GDE_ONE_EVENT )    // got an event?
          ctx.execset.insert(event->ea);
      }
      break;
  }
  return retcode;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  info("AUTOHIDE NONE\n"
       "This is the highlighter plugin.\n"
       "It highlights executed instructions if a debug event occurs at them.\n"
       "The plugins is fully automatic and has no parameters.\n");
  return true;
}

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list /*va*/)
{
  // We set our debug event handler at the beginning and remove it at the end
  // of a debug session
  switch ( code )
  {
    case dbg_process_start:
    case dbg_process_attach:
      exec_prefix = new exec_prefix_t(*this);
      register_post_event_visitor(HT_IDD, &idd_post_events, this);
      break;
    case dbg_process_exit:
      // do not unregister idd_post_events - it should be removed automatically
      delete exec_prefix;
      exec_prefix = nullptr;
      execset.clear();
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Highlighter";
static const char wanted_hotkey[] = "";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  wanted_name,          // long comment about the plugin
  wanted_name,          // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey,        // the preferred hotkey to run the plugin
};
