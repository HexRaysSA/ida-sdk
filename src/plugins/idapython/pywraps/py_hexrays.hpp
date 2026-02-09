//-------------------------------------------------------------------------
//<code(py_hexrays)>
idaman bool ida_export_data idapython_do_not_check_ctree;
idaman bool ida_export_data idapython_hexrays_exiting;

//-------------------------------------------------------------------------
static bool is_hexrays_plugin(const plugin_t *entry)
{
  return entry != nullptr && streq(entry->wanted_name, MODULE_NAME);
}

//-------------------------------------------------------------------------
inline bool hexdsp_inited() { return get_hexdsp() != nullptr; }

//-------------------------------------------------------------------------
static void hexrays_unloading__unhook_hooks(void);
static ssize_t idaapi ida_hexrays_ui_notification(void *, int code, va_list va)
{
  switch ( code )
  {
    case ui_plugin_loaded:
      if ( !hexdsp_inited() )
      {
        const plugin_info_t *pi = va_arg(va, plugin_info_t *);
        if ( pi != nullptr && is_hexrays_plugin(pi->entry) && init_hexrays_plugin(0) )
          msg("IDAPython Hex-Rays bindings initialized.\n");
      }
      break;

    case ui_destroying_plugmod:
      if ( hexdsp_inited() )
      {
        /*const plugmod_t *plugmod =*/ va_arg(va, plugmod_t *);
        const plugin_t *entry = va_arg(va, plugin_t *);
        if ( is_hexrays_plugin(entry) )
        {
          QASSERT(30500, !idapython_do_not_check_ctree);

          // Make sure all the refcounted objects are cleared right away.
          hexrays_deregister_all_python_clearable_references();

          // Make sure all hooks are unhooked
          hexrays_unloading__unhook_hooks();

          idapython_do_not_check_ctree = true;
        }
      }
      break;
    case ui_database_closed:
      idapython_do_not_check_ctree = false;
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
static void ida_hexrays_init(void) {}

//-------------------------------------------------------------------------
static void ida_hexrays_term(void)
{
  idapython_hexrays_exiting = true;
  idapython_unhook_from_notification_point(
          HT_UI, ida_hexrays_ui_notification, nullptr);
}

//-------------------------------------------------------------------------
static void ida_hexrays_closebase(void) {}

//</code(py_hexrays)>

//<inline(py_hexrays)>
//-------------------------------------------------------------------------
// Some examples will want to use action_handler_t's whose update() method
// calls get_widget_vdui() to figure out whether the action should be enabled
// for the current widget. Unfortunately, if hexrays is first unloaded before
// the widget cleanup is performed (e.g., while loading another IDB),
// the action would crash. Ideally we should wrap all toplevel calls
// with such wrappers, but it doesn't seem to be really necessary at the
// moment: only corner-cases will reveal this issue (reported by
// the idapython_hr-decompile test.)
vdui_t *py_get_widget_vdui(TWidget *f)
{
  return ( get_hexdsp() != nullptr ) ? get_widget_vdui(f) : nullptr;
}

//---------------------------------------------------------------------
bool py_init_hexrays_plugin(int flags=0)
{
  // Only initialize one time
  return (get_hexdsp() != nullptr) || init_hexrays_plugin(flags);
}

//-------------------------------------------------------------------------
inline boundaries_iterator_t py_boundaries_find(
        const boundaries_t *map,
        const cinsn_t *key)
{
  return boundaries_find(map, key);
}

//-------------------------------------------------------------------------
inline boundaries_iterator_t py_boundaries_insert(
        boundaries_t *map,
        const cinsn_t *key,
        const rangeset_t &val)
{
  return boundaries_insert(map, key, val);
}

void py_term_hexrays_plugin(void) {}
//</inline(py_hexrays)>

//<init(py_hexrays)>
idapython_hook_to_notification_point(HT_UI, ida_hexrays_ui_notification, nullptr, /*is_hooks_base=*/ false);
//</init(py_hexrays)>
