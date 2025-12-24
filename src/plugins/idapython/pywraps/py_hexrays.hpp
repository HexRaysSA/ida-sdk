//-------------------------------------------------------------------------
//<code(py_hexrays)>
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
