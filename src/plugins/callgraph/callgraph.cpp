#include "callgraph.h"
#include <mergemod.hpp>
#include <cvt64.hpp>

int data_id;

static bool get_graph_title(ea_t ea, qstring *out);

//-------------------------------------------------------------------------
#define ACTION_NAME "callgraph:ShowCallgraph"
#define ACTION_LABEL "Function call graph"

plugin_ctx_t::plugin_ctx_t()
  : main_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_NAME,
        ACTION_LABEL,
        &show_callgraph_ah,
        this,
        "Ctrl+Shift+B",
        nullptr,
        get_icon_id_by_name("FunctionCallGraph")))
{
  ::hook_event_listener(HT_IDP, &idp_listener, this);
  ::hook_event_listener(HT_VIEW, &view_listener, this);
}

bool plugin_ctx_t::register_main_action()
{
  return register_action(main_action)
      && attach_action_to_menu("View/Open subviews/Function calls",
                               ACTION_NAME, SETMENU_APP);
}

plugin_ctx_t::~plugin_ctx_t()
{
  clr_module_data(data_id);
}

//--------------------------------------------------------------------------
int idaapi show_callgraph_ah_t::activate(action_activation_ctx_t *)
{
  ctx.run(0);
  return 0;
}

//--------------------------------------------------------------------------
// Checks if a function is visited already
// If it is visited then true is returned and nid contains the node ID
bool callgraph_t::visited(ea_t func_ea, int *nid)
{
  ea_int_map_t::const_iterator it = ea2node.find(func_ea);
  if ( it != ea2node.end() )
  {
    if ( nid != nullptr )
      *nid = it->second;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void callgraph_t::add_fathers(
        func_t * /*func*/,
        ea_t func_start,
        int id,
        funcs_walk_options_t *opt,
        int level)
{
  if ( level >= (opt->callers_recurse_limit+2) )
  {
    return;
  }

  //msg("Level %d, node 0x%08x\n", level, func_start);
  xrefblk_t xb_to;

  for ( bool xb_to_ok = xb_to.first_to(func_start, XREF_FAR);
        xb_to_ok && xb_to.iscode;
        xb_to_ok = xb_to.next_to() )
  {
    func_t *f_from = get_func(xb_to.from);
    if ( f_from == nullptr )
      continue;

    int idto = add(f_from->start_ea);
    //msg("Adding XREF to 1st node %d\n", idto);
    create_edge(idto, id);

    add_fathers(f_from, f_from->start_ea, idto, opt, level+1);
  }
}

//--------------------------------------------------------------------------
int callgraph_t::walk_func(
        eavec_t *hide_nodes,
        func_t *func,
        funcs_walk_options_t *opt,
        int level)
{
  // add a node for this function
  ea_t func_start = func->start_ea;

  int id = add(func_start);

  // Add the callers of the 1st function
  if ( level == 2 )
  {
    add_fathers(func, func_start, id, opt, 2);
  }

  int total = 0;
  func_item_iterator_t fii;

  for ( bool fi_ok=fii.set(func); fi_ok; fi_ok=fii.next_code() )
  {
    xrefblk_t xb;
    for ( bool xb_ok = xb.first_from(fii.current(), XREF_FAR);
          xb_ok && xb.iscode;
          xb_ok = xb.next_from() )
    {
      bool is_func_lib;
      ea_t ea;

      func_t *f = get_func(xb.to);
      if ( f == nullptr )
      {
        ea = xb.to;
        is_func_lib = true;

        if ( (opt->flags & FWO_SKIPLIB) != 0 )
          continue;
      }
      else
      {
        ea = f->start_ea;
        is_func_lib = false;
      }

      eavec_t::iterator hide_nodes_it;

      // Any node to hide?
      if ( !hide_nodes->empty() )
      {
        hide_nodes_it = std::find(hide_nodes->begin(), hide_nodes->end(), ea);
        if ( *hide_nodes_it == ea )
        {
          //msg("Hiding node 0x%08x\n", *hide_nodes_it);
          continue;
        }
      }

      int id2 = -1;
      if ( !visited(ea, &id2) )
      {
        if ( func_contains(func, xb.to) )
          continue;

        bool skip = false;

        skip = is_func_lib && (opt->flags & FWO_SKIPLIB) != 0 // skip lib funcs?
            || ((opt->flags & FWO_CALLEE_RECURSE_UNLIM) == 0 // max recursion is off, and limit is reached?
             && level > opt->callees_recurse_limit);

        // More nodes in this level than the maximum specified?
        if ( total++ >= ctx.fg_opts.max_nodes )
        {
          id2 = add((ea_t)VERTEX_HIDDEN_NODES);
          create_edge(id, id2);
          break;
        }

        if ( skip )
          id2 = add(ea);
        else if ( !is_func_lib )
          id2 = walk_func(hide_nodes, f, opt, level+1);
        else if ( (opt->flags & FWO_SKIPLIB) == 0 )
          id2 = add(ea);

        if ( id2 != -1 )
          create_edge(id, id2);
      }
      //msg("Adding edge between %d and %d\n", id, id2);
    }
  }
  return id;
}

//--------------------------------------------------------------------------
int callgraph_t::find_first(const char *text)
{
  if ( text == nullptr || text[0] == '\0' )
    return -1;

  qstrncpy(cur_text, text, sizeof(cur_text));
  cur_node = 0;
  return find_next();
}

//--------------------------------------------------------------------------
int callgraph_t::find_next()
{
  for ( int i = cur_node; i < node_count; i++ )
  {
    const char *s = get_name(i);
    if ( stristr(s, cur_text) != nullptr )
    {
      cur_node = i + 1;
      return i;
    }
  }
  // reset search
  cur_node = 0;
  // nothing is found
  return -1;
}

//--------------------------------------------------------------------------
void callgraph_t::create_edge(int id1, int id2)
{
  edges.push_back(edge_t(id1, id2));
}

//--------------------------------------------------------------------------
void callgraph_t::reset()
{
  node_count = 0;
  cur_node = 0;
  cur_text[0] = '\0';
  ea2node.clear();
  node2ea.clear();
  cached_funcs.clear();
  edges.clear();
}

//--------------------------------------------------------------------------
ea_t callgraph_t::get_addr(int nid) const
{
  int_ea_map_t::const_iterator it = node2ea.find(nid);
  return it == node2ea.end() ? BADADDR : it->second;
}

//--------------------------------------------------------------------------
// Given an address, this function first returns ASCII string if found
// otherwise it returns a UNICODE string
// FIXME: not comprehensive, better follow the settings in strings options
size_t get_string(ea_t ea, qstring *out)
{
  const char *encodings[2] =
    {
      encoding_from_strtype(STRTYPE_C),
      inf_is_be() ? ENC_UTF16BE : ENC_UTF16LE
    };
  for ( int i = 0; i < qnumber(encodings); i++ )
  {
    int enc_idx = add_encoding(encodings[i]);
    uint32 strtype = make_str_type(STRTYPE_C, enc_idx);
    size_t len = get_max_strlit_length(ea, strtype);
    if ( len > 4 && get_strlit_contents(out, ea, len, strtype) > 0 )
      break;
    out->qclear();
  }
  return out->size();
}

//--------------------------------------------------------------------------
bool get_strings(ea_t ea, qstring *out)
{
  qstring tmp;

  func_t *func = get_func(ea);
  func_item_iterator_t fii;
  for ( bool fi_ok=fii.set(func); fi_ok; fi_ok=fii.next_code() )
  {
    xrefblk_t xb;
    for ( bool xb_ok = xb.first_from(fii.current(), XREF_DATA);
          xb_ok;
          xb_ok = xb.next_from() )
      {
        if ( get_string(xb.to, &tmp) > 0 )
          *out += tmp + "\n";
      }
  }

  if ( out->size() > 1 )
    out->insert("\n\nStrings:\n");

  return !out->empty();
}

//--------------------------------------------------------------------------
callgraph_t::funcinfo_t *callgraph_t::get_info(int nid)
{
  funcinfo_t *ret = nullptr;

  do
  {
    // returned cached name
    int_funcinfo_map_t::iterator it = cached_funcs.find(nid);

    if ( it != cached_funcs.end() )
    {
      ret = &it->second;
      break;
    }

    // node does not exist?
    int_ea_map_t::const_iterator it_ea = node2ea.find(nid);
    if ( it_ea == node2ea.end() )
      break;

    funcinfo_t fi;

    qstring buf;
    if ( ::get_name(&buf, it_ea->second) <= 0 )
    {
      /*
      ** NOTE: With patched databases it may fail for a reason unknown (ATM).
      ** To test it, open an Objective-C app and patch it with the following
      ** script: https://github.com/zynamics/objc-helper-plugin-ida
      */
      if ( (int32)it_ea->second == VERTEX_HIDDEN_NODES )
      {
        fi.name = "More nodes hidden...";
      }
      else
      {
        msg("%a: Invalid address\n", it_ea->second);
        fi.name = "?";
      }
    }
    else
    {
      qstring outbuf = buf;
      qstring demangled;
      if ( demangle_name(&demangled, buf.begin(), MNG_SHORT_FORM) > 0 )
      {
        outbuf.append("\n");
        outbuf.append(demangled);
      }

      // Assign the name
      fi.name = outbuf;

      // Add the strings reference if set
      qstring strings;
      if ( (ctx.fg_opts.flags & FWO_SHOWSTRING) != 0 && get_strings(it_ea->second, &strings) )
        fi.strings = strings;
    }

    // XXX: FIXME: UGLY HACK
    // Use a special color for the selected node
    if ( nid == 0 )
    {
      fi.color = 0x44FF55;
    }
    else
    {
      // Is it an imported function?
      segment_t *seg = getseg(it_ea->second);
      if ( seg != nullptr && seg->type == SEG_XTRN )
      {
        fi.color = 0xf000f0;
      }
      else
      {
        // XXX: FIXME Horrible...
        func_t *f = get_func(it_ea->second);
        if ( f != nullptr
          && ((f->flags & FUNC_LIB) != 0 || buf[0] == '.') )
        {
          fi.color = 0xfff000;
        }
        else
        {
          fi.color = calc_bg_color(it_ea->second);
        }
      }
    }

    fi.ea = it_ea->second;

    it = cached_funcs.insert(cached_funcs.end(), std::make_pair(nid, fi));  //-V783 Dereferencing of the invalid iterator
    ret = &it->second;
  } while ( false );

  return ret;
}

//--------------------------------------------------------------------------
const char *callgraph_t::get_name(int nid)
{
  funcinfo_t *fi = get_info(nid);
  if ( fi == nullptr )
    return "?";
  else
    return fi->name.c_str();
}

//--------------------------------------------------------------------------
int callgraph_t::add(ea_t func_ea)
{
  ea_int_map_t::const_iterator it = ea2node.find(func_ea);
  if ( it != ea2node.end() )
    return it->second;

  ea2node[func_ea]    = node_count;
  node2ea[node_count] = func_ea;
  return node_count++;
}

//--------------------------------------------------------------------------
callgraph_t::callgraph_t(plugin_ctx_t &_ctx) : ctx(_ctx)
{
  cur_text[0] = '\0';
}

//--------------------------------------------------------------------------
void callgraph_t::clear_edges()
{
  edges.clear();
}

//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
bool graph_info_t::find(plugin_ctx_t &ctx, ea_t ea, iterator *out)
{
  iterator end = ctx.instances.end();
  for ( iterator it = ctx.instances.begin(); it != end; ++it )
  {
    if ( (*it)->func_ea == ea )
    {
      if ( out != nullptr )
        *out = it;
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
graph_info_t *graph_info_t::find(plugin_ctx_t &ctx, ea_t ea)
{
  iterator it;
  return find(ctx, ea, &it) ? *it : nullptr;
}

//--------------------------------------------------------------------------
graph_info_t *graph_info_t::find(plugin_ctx_t &ctx, const char *_title)
{
  for ( auto &gi : ctx.instances )
    if ( gi->title == _title )
      return gi;
  return nullptr;
}

//-------------------------------------------------------------------------
graph_info_t *graph_info_t::find(plugin_ctx_t &ctx, const graph_viewer_t *v)
{
  for ( auto &gi : ctx.instances )
    if ( gi->gv == v )
      return gi;
  return nullptr;
}

//--------------------------------------------------------------------------
graph_info_t *graph_info_t::create(plugin_ctx_t &ctx, ea_t ea)
{
  graph_info_t *r = find(ctx, ea);

  // not there? create it
  if ( r == nullptr )
  {
    // we need a function!
    func_t *pfn = get_func(ea);
    if ( pfn == nullptr )
      return nullptr;

    r = new graph_info_t(ctx);
    get_graph_title(ea, &r->title);
    r->func_ea = pfn->start_ea;
    ctx.instances.push_back(r);

    r->install_hooks();
  }
  return r;
}

//--------------------------------------------------------------------------
// Check if the user changed any of the functions in the current graph
static void check_func_changed(ea_t ea, graph_info_t &gi)
{
  ea_int_map_t::const_iterator it = gi.fg.ea2node.find(ea);
  if ( it != gi.fg.ea2node.end() )
  {
    // The center node has been changed, destroy the current callgraph
    if ( it->second == 0 )
      close_widget(gi.widget, WCLS_SAVE);
    else
      // A function shown in the callgraph has been changed, refresh
      // the callgraph
      gi.refresh();
  }
}

//--------------------------------------------------------------------------
// We hook to IDP event to receive processor module notifications
ssize_t idaapi idb_gi_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case idb_event::func_added:
    case idb_event::func_updated:
    case idb_event::deleting_func:
    case idb_event::set_func_start:
    case idb_event::set_func_end:
      {
        func_t *pfn = va_arg(va, func_t *);
        check_func_changed(pfn->start_ea, gi);
        break;
      }
  }

  return 0;
}

//--------------------------------------------------------------------------
// We hook to IDP event to receive processor module notifications
ssize_t idaapi idp_gi_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case processor_t::ev_create_switch_xrefs:
    case processor_t::ev_add_cref:
    case processor_t::ev_del_cref:
      {
        ea_t ea = va_arg(va, ea_t);
        check_func_changed(ea, gi);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
ssize_t idaapi idp_listener_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case processor_t::ev_create_merge_handlers:
      {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_merge_handlers(*md);
      }
      break;

#ifdef CVT64
    case processor_t::ev_cvt64_supval:
      {
        netnode helper = netnode(PROCMOD_NODE_NAME);
        static const cvt64_node_tag_t node_info[] =
        {
          { helper, stag, 1 },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
#endif
  }
  qnotused(code);
  qnotused(va);
  return 0;
}

//--------------------------------------------------------------------------
void graph_info_t::install_hooks()
{
  hook_event_listener(HT_IDP, &idp_gi_listener, &ctx);
  hook_event_listener(HT_IDB, &idb_gi_listener, &ctx);
}

//--------------------------------------------------------------------------
void graph_info_t::remove_hooks()
{
  unhook_event_listener(HT_IDP, &idp_gi_listener);
  unhook_event_listener(HT_IDB, &idb_gi_listener);
}

//--------------------------------------------------------------------------
void graph_info_t::destroy_graph(plugin_ctx_t &ctx, graph_info_t *gi)
{
  iterator it;
  if ( find(ctx, gi->func_ea, &it) )
  {
    ctx.instances.erase(it);
    gi->remove_hooks();
    delete gi;
  }
}

//--------------------------------------------------------------------------
// Get a new title for the form to be opened
qstring plugin_ctx_t::gen_graph_title(ea_t ea)
{
  // We should succeed in getting the name
  qstring func_name;
  if ( get_func_name(&func_name, ea) > 0 )
  {
    qstring tmp;
    for ( int i=1; i < 255; i++ )
    {
      tmp.sprnt("Call graph: %s (%d)", func_name.begin(), i);
      if ( find_widget(tmp.c_str()) == nullptr )
        return tmp;
    }
  }
  return qstring();
}

//--------------------------------------------------------------------------
static bool get_graph_title(ea_t ea, qstring *out)
{
  // we should succeed in getting the name
  qstring func_name;
  if ( get_func_name(&func_name, ea) <= 0 )
    return false;

  out->sprnt("Call graph: %s", func_name.begin());
  return true;
}

//--------------------------------------------------------------------------
void graph_info_t::mark_for_refresh()
{
  refresh_needed = true;
}

//--------------------------------------------------------------------------
void graph_info_t::mark_as_refreshed()
{
  refresh_needed = false;
}

//--------------------------------------------------------------------------
void graph_info_t::refresh()
{
  mark_for_refresh();
  refresh_viewer(gv);
}

//--------------------------------------------------------------------------
//
//--------------------------------------------------------------------------
void idaapi callgraph_t::user_refresh(
        void *ud,
        int code,
        va_list va,
        int current_node)
{
  graph_info_t *gi = (graph_info_t *) ud;
  callgraph_t *fg = &gi->fg;
  qnotused(code);
  qnotused(current_node);
  if ( !gi->is_refresh_needed() )
    return;

  gi->mark_as_refreshed();
  fg->reset();

  func_t *f = get_func(gi->func_ea);
  if ( f == nullptr )
  {
    msg("%a: Invalid function\n", gi->func_ea);
    return;
  }

  fg->walk_func(&gi->hide_nodes, f, &fg->ctx.fg_opts, 2);

  interactive_graph_t *mg = va_arg(va, interactive_graph_t *);

  // we have to resize
  mg->reset();
  mg->resize(fg->count());

  callgraph_t::edge_iterator it;
  callgraph_t::edge_iterator end = fg->end_edges();

  for ( it=fg->begin_edges(); it != end; ++it )
    mg->add_edge(it->id1, it->id2, nullptr);

  fg->clear_edges();
}

//--------------------------------------------------------------------------
ssize_t idaapi callgraph_t::gr_callback(void *ud, int code, va_list va)
{
  bool result = false;
  graph_info_t *gi = (graph_info_t *) ud;
  callgraph_t *fg = &gi->fg;
  switch ( code )
  {
    // a graph node has been double clicked
    // in:  graph_viewer_t *gv
    //      selection_item_t *current_item
    // out: 0-ok, 1-ignore click
    case grcode_dblclicked:
      result = fg->center(gi);
      break;
    // refresh user-defined graph nodes and edges
    // in:  interactive_graph_t *g
    // out: success
    case grcode_user_refresh:
      user_refresh(ud, code, va, -1);
      result = true;
      break;

    // retrieve text for user-defined graph node
    // in:  interactive_graph_t *g
    //      int node
    //      const char **result
    //      bgcolor_t *bg_color (maybe nullptr)
    // out: must return 0, result must be filled
    case grcode_user_text:
      {
        va_arg(va, interactive_graph_t *);
        int node           = va_arg(va, int);
        const char **text  = va_arg(va, const char **);
        bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);

        callgraph_t::funcinfo_t *fi = fg->get_info(node);
        result = fi != nullptr;
        if ( result )
        {
          qstring hint;

          hint = fi->name + fi->strings;
          *text = hint.extract();
          //*text = fi->name.c_str();
          if ( bgcolor != nullptr )
            *bgcolor = fi->color;
        }
        break;
      }

    // retrieve hint for the user-defined graph
    // in:  interactive_graph_t *g
    //      int mousenode
    //      int mouseedge_src
    //      int mouseedge_dst
    //      char **hint
    // 'hint' must be allocated by qalloc() or qstrdup()
    // out: 0-use default hint, 1-use proposed hint
    case grcode_user_hint:
      {
        va_arg(va, interactive_graph_t *);

        int mousenode = va_argi(va, int);
        int to = va_argi(va, int);
        int from = va_argi(va, int);
        char **hint = va_arg(va, char **);

        result = true;

        ea_t addr;
        if ( mousenode != -1 && (addr = fg->get_addr(mousenode)) != BADADDR )
        {
          qstrvec_t lines;
          qstring all_lines;

          for ( int j=0; j < 16; j++ )
          {
            int nl = generate_disassembly(&lines, nullptr, addr, 1024, false);

            for ( int i = 0; i < nl; i++ )
            {
              all_lines.append(lines[i]);
              all_lines.append('\n');
            }
            addr = get_item_end(addr);
          }

          *hint = all_lines.extract();
        }
        else if ( mousenode == -1 )
        {
          qstring line;

          if ( from != -1 && to != -1 )
          {
            funcinfo_t *fifrom = fg->get_info(from);
            funcinfo_t *fito = fg->get_info(to);

            // XXX: FIXME: Hack. It should be fixed hooking to del_func, etc...
            if ( fifrom == nullptr || fito == nullptr )
            {
              msg("Invalid function\n");
              result = false;
            }
            else
            {
              line.insert(fifrom->name.c_str());
              line.insert(" -> ");
              line.insert(fito->name.c_str());

              *hint = line.extract();
            }
          }
        }
        break;
      }
  }
  return (int)result;
}

//--------------------------------------------------------------------------
bool plugin_ctx_t::load_options()
{
  funcs_walk_options_t opt;
  netnode n(PROCMOD_NODE_NAME);
  if ( !exist(n) )
    return false;

  n.supval(1, &opt, sizeof(opt));

  if ( opt.version != FWO_VERSION )
    return false;

  fg_opts = opt;
  return true;
}

//--------------------------------------------------------------------------
void plugin_ctx_t::save_options()
{
  netnode n;
  n.create(PROCMOD_NODE_NAME);
  n.supset(1, &fg_opts, sizeof(fg_opts));
}

//--------------------------------------------------------------------------
static int idaapi options_cb(int fid, form_actions_t &fa)
{
  ushort opt = 0;

  if ( fid == FIELD_ID_CHILDS || fid == CB_INIT )
  {
    if ( !fa.get_checkbox_value(FIELD_ID_CHILDS, &opt) )
      INTERR(562);

    // Disable recursion level textbox
    fa.enable_field(FIELD_ID_CHILDS_LEVEL, !opt);//(opt & FWO_CALLEE_RECURSE_UNLIM) == 0);
  }

  if ( fid == FIELD_ID_FATHERS )
  {
    if ( !fa.get_checkbox_value(FIELD_ID_FATHERS, &opt) )
      INTERR(563);

    if ( opt > MAX_CALLERS_LEVEL )
    {
      info("Sorry, value is too big: %d", opt);
      opt = MAX_CALLERS_LEVEL;
      fa.set_checkbox_value(FIELD_ID_FATHERS, &opt);
    }
  }

  return 1;
}

//--------------------------------------------------------------------------
bool plugin_ctx_t::show_options()
{
  static const char opt_form[] =
    "Call graph configuration\n"
    "%/"
    "<##Show ~s~tring references:C1>\n"
    "<##Options##Hide ~l~ibrary functions:C2>\n"
    "<##Max ~p~arents recursion level:D3:5:5::>\n"
    "<##Unlimited children recursion:C4>5>\n"
    "<##Max ~c~hildren recursion level:D6:5:5::>\n"
    "<##~L~imit of nodes per level:D7:5:5::>\n"
    ;

  ushort opt = fg_opts.flags;

  // When analyzing big functions, fg_opts.recurse_limit is too big
  sval_t callers_limit = fg_opts.callers_recurse_limit;
  sval_t callees_limit = fg_opts.callees_recurse_limit;
  sval_t max_nodes = fg_opts.max_nodes;

  if ( !ask_form(opt_form,
                 options_cb,
                 &callers_limit,
                 &opt,
                 &callees_limit,
                 &max_nodes) )
  {
    return false;
  }

  if ( callees_limit <= 0 )
  {
    callers_limit = 0;
    opt |= FWO_CALLEE_RECURSE_UNLIM;
  }

  fg_opts.flags = opt;
  fg_opts.callees_recurse_limit = callees_limit;
  fg_opts.callers_recurse_limit = callers_limit;
  fg_opts.max_nodes = max_nodes;

  save_options();
  return true;
}

//--------------------------------------------------------------------------
static void jump_to_node(const graph_info_t *gi, const int nid)
{
  viewer_center_on(gi->gv, nid);
  int x, y;

  // will return a place only when a node was previously selected
  place_t *old_pl = get_custom_viewer_place(gi->gv, false, &x, &y);
  if ( old_pl != nullptr )
  {
    user_graph_place_t *new_pl = (user_graph_place_t *) old_pl->clone();
    new_pl->node = nid;
    jumpto(gi->gv, new_pl, x, y);
    ::qfree(new_pl);
  }
}

//--------------------------------------------------------------------------
static int findfirst_node(callgraph_t *fg)
{
  static const char form[] =
    "Enter search substring\n"
    "\n"
    " <#Search is not case sensitive#Function name:q:1000:50::>\n\n";

  CASSERT(IS_QSTRING(fg->ctx.last_text));
  if ( !ask_form(form, &fg->ctx.last_text) )
    return -2;

  return fg->find_first(fg->ctx.last_text.c_str());
}

//--------------------------------------------------------------------------
static void display_node_search_result(graph_info_t *gi, int nid)
{
  // search was cancelled
  if ( nid == -2 )
    return;

  const char *txt = gi->fg.get_findtext();
  if ( nid == -1 )
  {
    msg("No match for '%s'\n", txt);
  }
  else
  {
    msg("%a: matched '%s'\n", gi->fg.get_addr(nid), txt);
    jump_to_node(gi, nid);
  }
}

//--------------------------------------------------------------------------
bool callgraph_t::options(graph_info_t *gi) const
{
  if ( ctx.show_options() )
    gi->refresh();

  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::refresh(graph_info_t *gi) const
{
  gi->refresh();
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::jumpxref(graph_info_t *gi) const
{
  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if ( node != -1 )
  {
    addr = gi->fg.get_addr(node);
    ea_t xref = choose_xref(addr);

    if ( xref != 0 && xref != BADADDR )
      navigate(gi, xref);

  }
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::jumpaddr(graph_info_t *gi) const
{
  ea_t addr;

  if ( ask_addr(&addr, "Jump address") )
  {
    func_t *pfn = get_func(addr);
    if ( pfn == nullptr )
    {
      warning("You have entered an invalid address");
      return false;
    }
    navigate(gi, addr);
  }

  return true;
}


//--------------------------------------------------------------------------
bool callgraph_t::jump(const graph_info_t *gi) const
{
  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if ( node != -1 )
  {
    addr = gi->fg.get_addr(node);
    jumpto(addr);
  }
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::back(graph_info_t *gi) const
{
  if ( gi->queue.empty() )
    close_widget(gi->widget, WCLS_SAVE);
  else
    go_back(gi);
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::forward(graph_info_t *gi) const
{
  if ( !gi->forward_queue.empty() )
    go_forward(gi);
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::center(graph_info_t *gi) const
{
  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if ( node != -1 )
  {
    addr = gi->fg.get_addr(node);
    return navigate(gi, addr);
  }
  else
    return false;

}

//-------------------------------------------------------------------------
// node chooser's helper
struct node_chooser_t : public chooser_t
{
protected:
  static const int widths_[];
  static const char *const header_[];

public:
  // this chooser is modal
  node_chooser_t(const char * title);
};

const int node_chooser_t::widths_[] =
{
  CHCOL_HEX | 32, // Function
  10,             // Address
};
const char *const node_chooser_t::header_[] =
{
  "Function", // 0
  "Address",  // 1
};

inline node_chooser_t::node_chooser_t(const char *title_)
  : chooser_t(CH_MODAL | CH_KEEP,
              qnumber(widths_), widths_, header_,
              title_)
{
  CASSERT(qnumber(widths_) == qnumber(header_));
}


//-------------------------------------------------------------------------
// modal call node chooser
struct call_node_chooser_t : public node_chooser_t
{
  const callgraph_t &fg;

  // this chooser is modal
  call_node_chooser_t(const callgraph_t &fg_)
    : node_chooser_t("Select function"), fg(fg_) {}

  virtual size_t idaapi get_count() const override { return fg.count(); }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;
};

void idaapi call_node_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  ea_t ea = fg.get_addr(n);

  qstrvec_t &cols = *cols_;
  if ( get_name(&cols[0], ea) > 0 )
    cols[1].sprnt("%a", ea);
  CASSERT(qnumber(header_) == 2);
}

//--------------------------------------------------------------------------
bool callgraph_t::select(const graph_info_t *gi) const
{
  call_node_chooser_t ch(gi->fg);
  ssize_t n = ch.choose(chooser_base_t::NO_SELECTION); // why?
  if ( n >= 0 )
    jump_to_node(gi, n);
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::home(const graph_info_t *gi) const
{
  if ( count() > 1 )
    jump_to_node(gi, 0);
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::searchfirst(graph_info_t *gi)
{
  display_node_search_result(gi, findfirst_node(this));
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::searchnext(graph_info_t *gi)
{
  display_node_search_result(gi, find_next());
  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::hidenode(graph_info_t *gi) const
{
  int node;
  ea_t addr;

  node = viewer_get_curnode(gi->gv);
  if ( node != -1 )
  {
    addr = gi->fg.get_addr(node);
    //msg("Should hide 0x%08x\n", addr);
    gi->hide_nodes.push_back(addr);
    gi->refresh();
  }

  return true;
}

//-------------------------------------------------------------------------
// modal hidden node chooser
struct hidden_node_chooser_t : public node_chooser_t
{
  const eavec_t &hn;

  // this chooser is modal
  hidden_node_chooser_t(const eavec_t &hn_)
    : node_chooser_t("Show function"), hn(hn_) {}

  virtual size_t idaapi get_count() const override { return hn.size(); }
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;
};

void idaapi hidden_node_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  ea_t ea = hn[n];

  qstrvec_t &cols = *cols_;
  if ( get_name(&cols[0], ea) > 0 )
    cols[1].sprnt("%a", ea);
  CASSERT(qnumber(header_) == 2);
}

//--------------------------------------------------------------------------
bool callgraph_t::showhidden(graph_info_t *gi) const
{
  if ( gi->hide_nodes.empty() )
  {
    info("No functions hidden\n");
    return true;
  }

  hidden_node_chooser_t ch(gi->hide_nodes);
  ssize_t n = ch.choose(chooser_base_t::NO_SELECTION); // why?
  if ( n >= 0 )
  {
    eavec_t::iterator it = gi->hide_nodes.begin() + n;
    gi->hide_nodes.erase(it);
    gi->refresh();
  }

  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::showall(graph_info_t *gi) const
{
  gi->hide_nodes.clear();
  gi->refresh();

  return true;
}

//--------------------------------------------------------------------------
bool callgraph_t::navigate(graph_info_t *gi, ea_t addr) const
{
  ea_t func_ea;

  func_ea = gi->fg.get_addr(0);

  // Is it a function?
  func_t *pfn = get_func(addr);
  if ( pfn != nullptr )
  {
    // Is it the same function?
    if ( gi->func_ea != addr )
    {
      // Clear the forward queue
      gi->forward_queue.clear();

      // Enqueue the current center node
      gi->queue.push_front(func_ea);

      gi->func_ea = addr;
      gi->refresh();

      jump_to_node(gi, 0);
      return true;
    }
  }
  else
  {
    return true;
  }

  return false;
}

//--------------------------------------------------------------------------
void callgraph_t::go_back(graph_info_t *gi) const
{
  gi->forward_queue.push_front(gi->func_ea);
  gi->func_ea = gi->queue.front();
  gi->queue.pop_front();
  gi->refresh();

  jump_to_node(gi, 0);
}

//--------------------------------------------------------------------------
void callgraph_t::go_forward(graph_info_t *gi) const
{
  ea_t ea;

  ea = gi->forward_queue.front();
  gi->forward_queue.pop_front();
  gi->queue.push_front(gi->func_ea);
  gi->func_ea = ea;
  gi->refresh();

  jump_to_node(gi, 0);
}

//-------------------------------------------------------------------------
void plugin_ctx_t::ensure_actions_registered()
{
  if ( !actions_registered )
  {
    for ( int i = 0, n = qnumber(actions); i < n; ++i )
      register_action(actions[i]);

    actions_registered = true;
  }
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t arg)
{
  if ( ssize_t(arg) == -1 )
  {
    load_options();
    show_options();
    return true;
  }

  func_t *pfn = get_func(get_screen_ea());
  if ( pfn == nullptr )
  {
    warning("Please position the cursor in a function first!");
    return true;
  }

  load_options();
  qstring title = gen_graph_title(pfn->start_ea);
  TWidget *form = find_widget(title.c_str());
  if ( form == nullptr )
  {
    // no current window, but instance is in the list?
    graph_info_t *gi = graph_info_t::find(*this, title.c_str());
    if ( gi != nullptr )
    {
      // In that case let us "recycle" the instance
      gi->func_ea = pfn->start_ea;
    }
    else
    {
      // we create a new instance
      gi = graph_info_t::create(*this, pfn->start_ea);
    }

    if ( gi != nullptr )
    {
      // get a unique graph id
      netnode id;
      id.create("$ callgraph sample");

      gi->hide_nodes.begin();

      gi->mark_for_refresh();
      // gi->form = form;
      gi->gv = create_graph_viewer(title.c_str(), id, callgraph_t::gr_callback, gi, 0);
      if ( gi->gv != nullptr )
      {
        display_widget(/*form*/ gi->gv, WOPN_DP_TAB);

        ensure_actions_registered();

        viewer_fit_window(gi->gv);
#define ADD_POPUP(Method) viewer_attach_menu_item(gi->gv, "callgraph:" #Method)
#define ADD_SEPARATOR() viewer_attach_menu_item(gi->gv, nullptr)
        ADD_POPUP(options);
        ADD_POPUP(refresh);
        ADD_SEPARATOR();
        ADD_POPUP(jumpxref);
        ADD_POPUP(jumpaddr);
        ADD_POPUP(jump);
        ADD_POPUP(back);
        ADD_POPUP(forward);
        ADD_SEPARATOR();
        ADD_POPUP(center);
        ADD_POPUP(select);
        ADD_POPUP(home);
        ADD_POPUP(searchfirst);
        ADD_POPUP(searchnext);
        ADD_POPUP(hidenode);
        ADD_POPUP(showhidden);
        ADD_POPUP(showall);
#undef ADD_SEPARATOR
#undef ADD_POPUP
      }
      else
      {
        graph_info_t::destroy_graph(*this, gi);
        gi = nullptr;
      }
    }

    // Failed to create a graph view?
    if ( gi == nullptr )
    {
      warning("Failed to create call graph window!");
      return true;
    }
  }
  else
  {
    graph_info_t *gi = graph_info_t::find(*this, title.c_str());
    if ( gi != nullptr )
    {
      gi->refresh();
      display_widget(gi->gv, WOPN_DP_TAB);
    }
  }
  return true;
}

//-------------------------------------------------------------------------
ssize_t idaapi view_listener_t::on_event(ssize_t code, va_list va)
{
  if ( code == view_close )
  {
    TWidget *cc = va_arg(va, TWidget *);
    graph_info_t *gi = graph_info_t::find(ctx, (graph_viewer_t *) cc);
    if ( gi != nullptr )
      graph_info_t::destroy_graph(ctx, gi);
  }
  return 0;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
#ifdef CVT64
  if ( is_cvt64() )
    return new plugin_ctx_t;
#endif
  if ( !is_idaq() ) // GUI version?
    return nullptr;
  plugin_ctx_t *ctx = new plugin_ctx_t;
  if ( !ctx->register_main_action() )
  {
    msg("Failed to register menu item for <" ACTION_LABEL "> plugin!\n");
    delete ctx;
    return nullptr;
  }
  set_module_data(&data_id, ctx);
  return ctx;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE|PLUGIN_MULTI, // plugin flags
  init,                 // initialize

  nullptr,              // terminate. this pointer may be nullptr.
  nullptr,              // invoke plugin

  // long comment about the plugin
  "Proximity browser plugin.",
  // it could appear in the status line
  // or as a hint

  // multiline help about the plugin
  "Proximity browser using the graph SDK\n"
  "\n"
  "Position the cursor in a function and run the plugin.",

  ACTION_LABEL,     // the preferred short name of the plugin
  ""                // the preferred hotkey to run the plugin
};
