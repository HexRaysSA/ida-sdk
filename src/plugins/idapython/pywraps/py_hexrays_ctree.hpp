//-------------------------------------------------------------------------
//<code(py_hexrays_ctree)>
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
static ssize_t idaapi ida_hexrays_ctree_ui_notification(void *, int code, va_list va)
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
static void ida_hexrays_ctree_init(void) {}

//-------------------------------------------------------------------------
static void ida_hexrays_ctree_term(void)
{
  idapython_hexrays_exiting = true;
  idapython_unhook_from_notification_point(
          HT_UI, ida_hexrays_ctree_ui_notification, nullptr);
}

//-------------------------------------------------------------------------
static void ida_hexrays_ctree_closebase(void) {}

//</code(py_hexrays_ctree)>

//<init(py_hexrays_ctree)>
idapython_hook_to_notification_point(HT_UI, ida_hexrays_ctree_ui_notification, nullptr, /*is_hooks_base=*/ false);
//</init(py_hexrays_ctree)>
