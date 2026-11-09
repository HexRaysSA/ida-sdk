#include <pro.h>
#include <name.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include "w32sehch.h"

static int req_id = -1;

//-------------------------------------------------------------------------
// represents data to store on x86seh_chooser_t
struct x86seh_entry_t
{
  uint32 handler = 0; // address of SEH handler
  uint32 stack = 0;   // address of SEH chain on the stack
  x86seh_entry_t(uint32 _handler, uint32 _stack)
    : handler(_handler), stack(_stack) {}

  bool operator ==(const x86seh_entry_t &e) const { return handler == e.handler && stack == e.handler; }
};
DECLARE_TYPE_AS_MOVABLE(x86seh_entry_t);

//-------------------------------------------------------------------------
// non-modal exception handler chooser
struct x86seh_chooser_t : public chooser_t
{
protected:
  qvector<x86seh_entry_t> list;
  qstring title_;
  thid_t tid;

  static const int widths_[];
  static const char *const header_[];
  enum { ICON = 144 };

public:
  // this object must be allocated using `new`
  x86seh_chooser_t(thid_t tid);
  virtual ~x86seh_chooser_t()
  {
    unhook_from_notification_point(
            HT_DBG,
            dbg_handler, const_cast<char *>(title));
  }
  ssize_t choose(uint32 addr = uint32(-1))    //lint !e1511 member hides non-virtual member
  {
    return ::choose(this, &addr);
  }

  virtual const void *get_obj_id(size_t *len) const override
  {
    *len = sizeof(tid);
    return &tid;
  }

  virtual size_t idaapi get_count() const override { return list.size(); }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;
  virtual cbret_t idaapi enter(size_t n) override;

  // calculate the location of the item,
  virtual ssize_t idaapi get_item_index(const void *item_data) const override;
  virtual bool idaapi init() override;
  virtual cbret_t idaapi refresh(ssize_t n) override;

  ea_t get_stack_addr(int n) const;

protected:
  static ssize_t idaapi dbg_handler(void *ud, int notif_code, va_list va);
};

//-------------------------------------------------------------------------
const int x86seh_chooser_t::widths_[] =
{
  CHCOL_HEX | 10, // Address
  30,             // Name
  10,             // Stack
};
const char *const x86seh_chooser_t::header_[] =
{
  "Address",  // 0
  "Name",     // 1
  "Stack",    // 2
};

static const char seh_widget_title[] = "Structured exception handlers";
//-------------------------------------------------------------------------
inline x86seh_chooser_t::x86seh_chooser_t(thid_t tid_)
  : chooser_t(CH_NOBTNS | CH_FORCE_DEFAULT | CH_CAN_REFRESH,
              qnumber(widths_), widths_, header_),
    tid(tid_)
{
  title_.sprnt("[%04X] - %s", tid, seh_widget_title);
  title = title_.c_str();
  CASSERT(qnumber(widths_) == qnumber(header_));
  icon = ICON;

  hook_to_notification_point(
          HT_DBG,
          dbg_handler, const_cast<char *>(title));
}

//-------------------------------------------------------------------------
void idaapi x86seh_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  // assert: n < list.size()
  uint32 addr = list[n].handler;

  qstrvec_t &cols = *cols_;
  cols[0].sprnt("%08X", addr);
  get_nice_colored_name(&cols[1], addr, GNCN_NOCOLOR | GNCN_NOLABEL);
  // set Stack column data
  cols[2].sprnt("%08X", list[n].stack);
  CASSERT(qnumber(header_) == 3);
}

//-------------------------------------------------------------------------
chooser_t::cbret_t idaapi x86seh_chooser_t::enter(size_t n)
{
  // assert: n < list.size()
  ea_t ea = ea_t(list[n].handler);
  if ( !is_code(get_flags(ea)) )
    create_insn(ea);
  jumpto(ea);
  return cbret_t(); // nothing changed
}

//------------------------------------------------------------------------
ssize_t idaapi x86seh_chooser_t::get_item_index(const void *item_data) const
{
  if ( list.empty() )
    return NO_SELECTION;

  const x86seh_entry_t item = *(const x86seh_entry_t *)item_data;
  if ( item.handler == uint32(-1) )
    return 0; // first item by default

  // find `item_script` in the list
  const x86seh_entry_t *p = list.find(item);
  if ( p != list.end() )
    return p - list.begin();
  return 0; // first item by default
}

//--------------------------------------------------------------------------
bool idaapi x86seh_chooser_t::init()
{
  // rebuild the handlers list
  uint64 fs_sel;
  ea_t fs_base;
  uint32 excr_ea;
  list.clear();
  if ( !get_reg_val("fs", &fs_sel)
    || internal_get_sreg_base(&fs_base, tid, int(fs_sel)) <= DRC_NONE
    || read_dbg_memory(fs_base, &excr_ea, sizeof(excr_ea)) != sizeof(excr_ea) )
  {
    warning("Failed to build the SEH list for thread %08X", tid);
    return false; // do not show the empty chooser
  }

  struct EXC_REG_RECORD
  {
    uint32 prev;
    uint32 handler;
  };
  EXC_REG_RECORD rec;
  std::set<uint32> seen;
  while ( excr_ea != 0xffffffff )
  {
    if ( read_dbg_memory(excr_ea, &rec, sizeof(rec)) != sizeof(rec) )
      break;

    if ( !seen.insert(excr_ea).second )
    {
      msg("Circular SEH record has been detected\n");
      break;
    }

    list.push_back(x86seh_entry_t(rec.handler, excr_ea));
    excr_ea = rec.prev;
  }
  return true;
}

//------------------------------------------------------------------------
chooser_t::cbret_t idaapi x86seh_chooser_t::refresh(ssize_t n)
{
  uint32 item_addr = uint32(-1);
  if ( n >= 0 && n < list.size() )
    item_addr = list[n].handler;  // remember the currently selected handler

  init();

  if ( n < 0 )
    return NO_SELECTION;
  ssize_t idx = get_item_index(&item_addr);
  // no need to adjust `idx` as get_item_index() returns first item by
  // default
  return idx;
}

//-------------------------------------------------------------------------
ea_t x86seh_chooser_t::get_stack_addr(int n) const
{
  if ( n < list.size() )
    return ea_t(list[n].stack);

  return BADADDR;
}

//-------------------------------------------------------------------------
ssize_t idaapi x86seh_chooser_t::dbg_handler(void *ud, int code, va_list)
{
  if ( code == dbg_suspend_process )
  {
    const char *ttl = static_cast<const char *>(ud);
    refresh_chooser(ttl);
  }
  return 0;
}

//-------------------------------------------------------------------------
struct stkview_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx) override
  {
    if ( !ctx->chooser_selection.empty() ) // should always be the case
    {
      size_t idx = ctx->chooser_selection[0];
      const x86seh_chooser_t *c = (x86seh_chooser_t *) ctx->chooser;
      if ( c == nullptr )
        return 0;

      ea_t ea = c->get_stack_addr(idx);
      if ( ea != BADADDR )
      {
        TWidget *w = find_widget("Stack view");
        if ( w != nullptr )
        {
          activate_widget(w, true);
          jumpto(ea);
        }
      }
    }
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return ::qstrstr(ctx->widget_title.c_str(), seh_widget_title) != nullptr
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};
static stkview_ah_t stkview_ah;

//-------------------------------------------------------------------------
struct show_window_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *) override
  {
    thid_t tid = get_current_thread();
    x86seh_chooser_t *ch = new x86seh_chooser_t(tid);
    bool ok = ch->choose() == 0;
    if ( ok )
    {
      TWidget *w = find_widget(ch->title);
      if ( w != nullptr )
      {
#define ACTION_NAME "x86seh:Stack"
        const action_desc_t stkview_ah_action = ACTION_DESC_LITERAL_OWNER(
          ACTION_NAME,
          "Follow in stack view",
          &stkview_ah,
          &PLUGIN,
          nullptr,
          nullptr,
          -1,
          ADF_OT_PLUGIN);
        register_action(stkview_ah_action);
        attach_action_to_popup(
          w,
          nullptr, // make permanent
          ACTION_NAME);
      }
    }
    return ok; //-V773 The function was exited without releasing the 'ch' pointer.
  } //lint !e429 Custodial pointer 'ch' has not been freed or returned

  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE;
  }
};
static show_window_ah_t show_window_ah;


//---------------------------------------------------------------------------
void remove_x86seh_menu()
{
  if ( req_id != -1 )
  {
    cancel_exec_request(req_id);
    req_id = -1;
  }
}

//---------------------------------------------------------------------------
void install_x86seh_menu()
{
  // HACK: We queue this request because commdbg apparently enables the debug menus
  //       just after calling init_debugger().
  struct uireq_install_menu_t: public ui_request_t
  {
    virtual bool idaapi run() override
    {
      if ( !inf_is_64bit() )
      {
        register_and_attach_to_menu(
                "Debugger/Debugger windows/Stack trace",
                "dbg:sehList", "SEH list", nullptr, SETMENU_APP,
                &show_window_ah,
                &PLUGIN,
                ADF_OT_PLUGIN);
      }
      req_id = -1;
      return false;
    }
  };
  req_id = execute_ui_requests(new uireq_install_menu_t, nullptr);
}
