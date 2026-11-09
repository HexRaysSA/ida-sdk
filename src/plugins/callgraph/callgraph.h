#ifndef __CALLGRAPH__06192009__
#define __CALLGRAPH__06192009__

#include <deque>
#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <demangle.hpp>

#define MAX_CALLERS_LEVEL 10

#define FIELD_ID_STRINGS 1
#define FIELD_ID_LIBS 2
#define FIELD_ID_FATHERS 3
#define FIELD_ID_CHILDS 4
#define FIELD_ID_CHILDS_LEVEL 6

#define VERTEX_HIDDEN_NODES -1

struct plugin_ctx_t;
typedef std::deque<int> int_queue_t;
typedef std::map<ea_t, int> ea_int_map_t;

//--------------------------------------------------------------------------
struct funcs_walk_options_t
{
  int32 version;
#define FWO_VERSION 1 // current version of options block
  int32 flags;
#define FWO_SHOWSTRING                           0x0001 // show string references
#define FWO_SKIPLIB                              0x0002 // skip library functions
#define FWO_CALLEE_RECURSE_UNLIM 0x0004 // unlimited callees recursion
  int32 callees_recurse_limit; // how deep to recurse callees (0 = unlimited)
  int32 callers_recurse_limit; // how deep to recurse callers (0 = unlimited)
  int32 max_nodes;             // maximum number of nodes per level
};

class graph_info_t;

//--------------------------------------------------------------------------
// function call graph creator class
class callgraph_t
{
public:
  plugin_ctx_t &ctx;

private:
  int node_count = 0;

  // node id to func addr and reverse lookup
  typedef std::map<int, ea_t> int_ea_map_t;
  int_ea_map_t node2ea;

  // current node search ptr
  int  cur_node = 0;
  char cur_text[MAXSTR];

  bool visited(ea_t func_ea, int *nid);
  int  add(ea_t func_ea);

public:

  ea_int_map_t ea2node;
  // edge structure
  struct edge_t
  {
    int id1;
    int id2;
    edge_t(int i1, int i2): id1(i1), id2(i2) {}
    edge_t(): id1(0), id2(0) {}
  };
  typedef qlist<edge_t> edges_t;

  // edge manipulation
  typedef edges_t::iterator edge_iterator;
  void create_edge(int id1, int id2);
  edge_iterator begin_edges() { return edges.begin(); }
  edge_iterator end_edges() { return edges.end(); }
  void clear_edges();

  // find nodes by text
  int find_first(const char *text);
  int find_next();
  const char *get_findtext() { return cur_text; }
  callgraph_t(plugin_ctx_t &ctx);
  int count() const { return node_count; }
  void reset();

  // node / func info
  struct funcinfo_t
  {
    qstring name;
    bgcolor_t color;
    ea_t ea;
    qstring strings;
  };
  typedef std::map<int, funcinfo_t> int_funcinfo_map_t;
  int_funcinfo_map_t cached_funcs;
  funcinfo_t *get_info(int nid);

  // function name manipulation
  ea_t get_addr(int nid) const;
  const char *get_name(int nid);

  int walk_func(eavec_t *hide_nodes, func_t *func, funcs_walk_options_t *o=nullptr, int level=1);
  void add_fathers(func_t *func, ea_t func_start, int id, funcs_walk_options_t *opt, int level);

  bool navigate(graph_info_t *gi, ea_t addr) const;

  void go_back(graph_info_t *gi) const;
  void go_forward(graph_info_t *gi) const;

  bool options(graph_info_t *gi) const;
  bool refresh(graph_info_t *gi) const;

  bool jumpxref(graph_info_t *gi) const;
  bool jumpaddr(graph_info_t *gi) const;
  bool jump(const graph_info_t *gi) const;
  bool back(graph_info_t *gi) const;
  bool forward(graph_info_t *gi) const;

  bool center(graph_info_t *gi) const;
  bool select(const graph_info_t *gi) const;
  bool home(const graph_info_t *gi) const;
  bool searchfirst(graph_info_t *gi);
  bool searchnext(graph_info_t *gi);
  bool hidenode(graph_info_t *gi) const;
  bool showhidden(graph_info_t *gi) const;
  bool showall(graph_info_t *gi) const;

  static ssize_t idaapi gr_callback(void *ud, int code, va_list va);
  static void idaapi user_refresh(void *ud, int code, va_list va, int current_node);
private:
  edges_t edges;
};

//--------------------------------------------------------------------------
DECLARE_LISTENER(view_listener_t, plugin_ctx_t, ctx);
DECLARE_LISTENER(idp_gi_listener_t, graph_info_t, gi);
DECLARE_LISTENER(idb_gi_listener_t, graph_info_t, gi);

struct idp_listener_t : public event_listener_t
{
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//--------------------------------------------------------------------------
// Per function call graph context
typedef qlist<class graph_info_t *> graphinfo_list_t;
class graph_info_t
{
  plugin_ctx_t &ctx;
  idp_gi_listener_t idp_gi_listener = idp_gi_listener_t(*this);
  idb_gi_listener_t idb_gi_listener = idb_gi_listener_t(*this);

public:
  typedef graphinfo_list_t::iterator iterator;

  callgraph_t fg; // associated call graph maker
  graph_viewer_t *gv = nullptr; // associated graph_view
  TWidget *widget = nullptr; // associated widget
  ea_t func_ea = BADADDR; // function ea in question
  qstring title; // the title

  int_queue_t queue;
  int_queue_t forward_queue;

  eavec_t hide_nodes;

private:
  bool refresh_needed = true; // schedule a refresh

  graph_info_t(plugin_ctx_t &_ctx) : ctx(_ctx), fg(_ctx) {}
  static bool find(plugin_ctx_t &ctx, ea_t func_ea, iterator *out);
public:
  static graph_info_t *find(plugin_ctx_t &ctx, ea_t func_ea);
  static graph_info_t *find(plugin_ctx_t &ctx, const char *title);
  static graph_info_t *find(plugin_ctx_t &ctx, const graph_viewer_t *v);
  static graph_info_t *create(plugin_ctx_t &ctx, ea_t func_ea);
  static void destroy_graph(plugin_ctx_t &ctx, graph_info_t *gi);
  void install_hooks();
  void remove_hooks();
  void mark_for_refresh(void);
  void mark_as_refreshed(void);
  void refresh(void);
  bool is_refresh_needed(void) const { return refresh_needed; }
};

//-------------------------------------------------------------------------
// The main action to invoke the plugin
struct show_callgraph_ah_t : public action_handler_t
{
  plugin_ctx_t &ctx;
  show_callgraph_ah_t(plugin_ctx_t &_ctx) : ctx(_ctx) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

//-------------------------------------------------------------------------
// Base class for additional actions in the graph view
struct cg_ah_t : public action_handler_t
{
  plugin_ctx_t &plg;
  cg_ah_t(plugin_ctx_t &p) : plg(p) {}
  virtual int act(graph_info_t *gi) = 0;

  virtual int idaapi activate(action_activation_ctx_t *ctx) override
  {
    graph_info_t *gi = graph_info_t::find(plg, (graph_viewer_t *) ctx->widget);
    return gi != nullptr ? act(gi) : 0;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return graph_info_t::find(plg, (graph_viewer_t *) ctx->widget) != nullptr
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};

//-------------------------------------------------------------------------
#define DECLARE_ACTION_HANDLER(Method)                                  \
struct Method##_ah_t : public cg_ah_t                                   \
{                                                                       \
  Method##_ah_t(plugin_ctx_t &p) : cg_ah_t(p) {}                        \
  virtual int act(graph_info_t *gi) override                            \
  {                                                                     \
    return int(gi->fg.Method(gi));                                      \
  }                                                                     \
}
DECLARE_ACTION_HANDLER(options);
DECLARE_ACTION_HANDLER(refresh);
DECLARE_ACTION_HANDLER(jumpxref);
DECLARE_ACTION_HANDLER(jumpaddr);
DECLARE_ACTION_HANDLER(jump);
DECLARE_ACTION_HANDLER(back);
DECLARE_ACTION_HANDLER(forward);
DECLARE_ACTION_HANDLER(center);
DECLARE_ACTION_HANDLER(select);
DECLARE_ACTION_HANDLER(home);
DECLARE_ACTION_HANDLER(searchfirst);
DECLARE_ACTION_HANDLER(searchnext);
DECLARE_ACTION_HANDLER(hidenode);
DECLARE_ACTION_HANDLER(showhidden);
DECLARE_ACTION_HANDLER(showall);
#undef DECLARE_ACTION_HANDLER

//--------------------------------------------------------------------------
#define PROCMOD_NODE_NAME "$ proximity browser"

struct plugin_ctx_t : public plugmod_t
{
  view_listener_t view_listener = view_listener_t(*this);
  idp_listener_t idp_listener;

  show_callgraph_ah_t show_callgraph_ah = show_callgraph_ah_t(*this);
  const action_desc_t main_action;
#define DEFINE_ACTION_HANDLER(Method) Method##_ah_t Method##_ah = Method##_ah_t(*this) //lint !e773 macro not parenthized
  DEFINE_ACTION_HANDLER(options);
  DEFINE_ACTION_HANDLER(refresh);
  DEFINE_ACTION_HANDLER(jumpxref);
  DEFINE_ACTION_HANDLER(jumpaddr);
  DEFINE_ACTION_HANDLER(jump);
  DEFINE_ACTION_HANDLER(back);
  DEFINE_ACTION_HANDLER(forward);
  DEFINE_ACTION_HANDLER(center);
  DEFINE_ACTION_HANDLER(select);
  DEFINE_ACTION_HANDLER(home);
  DEFINE_ACTION_HANDLER(searchfirst);
  DEFINE_ACTION_HANDLER(searchnext);
  DEFINE_ACTION_HANDLER(hidenode);
  DEFINE_ACTION_HANDLER(showhidden);
  DEFINE_ACTION_HANDLER(showall);
#undef DEFINE_ACTION_HANDLER
  const action_desc_t actions[15] =
  {
#define ROW(Method, Label, Shortcut)                                    \
    ACTION_DESC_LITERAL_PLUGMOD("callgraph:" #Method, Label, &Method##_ah, this, Shortcut, nullptr, -1)
    ROW(options, "Options", "O"),                       // 1
    ROW(refresh, "Refresh", "R"),                       // 2
    ROW(jumpxref, "Jump to xref", "X"),                 // 3
    ROW(jumpaddr, "Jump to address", "G"),              // 4
    ROW(jump, "Jump to function", "SPACE"),             // 5
    ROW(back, "Jump to previous node", "ESC"),          // 6
    ROW(forward, "Jump to next node", "Ctrl+Enter"),    // 7
    ROW(center, "Center node", "Enter"),                // 8
    ROW(select, "Select node", "Ctrl+L"),               // 9
    ROW(home, "Goto to first node", "H"),               // 0
    ROW(searchfirst, "Search first", "S"),              // 1
    ROW(searchnext, "Search next", "N"),                // 2
    ROW(hidenode, "Hide selected node", nullptr),       // 3
    ROW(showhidden, "Show hidden node", nullptr),       // 4
    ROW(showall, "Show all nodes", nullptr),            // 5
#undef ROW
  };

  graphinfo_list_t instances;
  funcs_walk_options_t fg_opts =
  {
    FWO_VERSION,                 // version
    FWO_CALLEE_RECURSE_UNLIM,    // flags
    2,                           // max callees recursion
    1,                           // max callers recursion
    255                          // max nodes per level
  };

  bool actions_registered = false;

  qstring last_text;  //lint !e958 padding  // see findfirst_node()


  virtual bool idaapi run(size_t arg) override;
  plugin_ctx_t();
  bool register_main_action();
  ~plugin_ctx_t();
  qstring gen_graph_title(ea_t ea);
  bool load_options();
  void save_options();
  bool show_options();
  void ensure_actions_registered();
};

extern int data_id;

#endif
