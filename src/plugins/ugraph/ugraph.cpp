/*
 * This plugin demonstrates how one can create a graph viewer, and
 * manipulate the graph that is being displayed (by adding nodes &
 * edges.)
 *
 * To illustrate this functionality, we will be showing the a subset
 * of the "family tree" of the elvish characters described in JRR
 * Tolkien's "Lord of the rings" books.
 *
 * That "family tree" was found at:
 * https://i.pinimg.com/originals/aa/36/0b/aa360b00a0f309f56e6b7f48ff92de2d.jpg
 * and please note that we didn't check that it is actually correct
 * since this is not exactly relevant to the functionality being
 * showcased.
 * We'll limit ourselves to 4 "generations" of characters, and provide
 * the graph user the ability to show, or hide generations (thus
 * modifying the underlying graph.)
 *
 * The following actions will be available in the graph's
 * context menu:
 *  - change the layout type
 *  - show & hide generations
 *  - modify the character's name
 *  - modify the character name's background color
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//
// Dramatis personae
//
#define Finarfin "Finarfin"
#define Earwen "Earwen"
#define Eldalote "Eldalote"
#define Finrod "Finrod"
#define Angrod "Angrod"
#define Aegnor "Aegnor"
#define Galadriel "Galadriel"
#define Celeborn "Celeborn"
#define Orodreth "Orodreth"
#define Unknown_name "Purple dress lady\n(name unknown)"
#define Celebrian "Celebrian"
#define Gil_Galad "Gil-Galad"
#define Finduilas "Finduilas"

static const char *characters[] =
{
  // Generation 0
  Finarfin, Earwen,

  // Generation 1
  Eldalote, Finrod, Angrod, Aegnor, Galadriel, Celeborn,

  // Generation 2
  Orodreth, Unknown_name, Celebrian,

  // Generation 3
  Gil_Galad, Finduilas,
};
static const size_t ncharacters = qnumber(characters);
static const size_t nlevels = 4;
static const size_t levels_offsets[] =
{
  0,
  2,
  2 + 6,
  2 + 6 + 3,
  2 + 6 + 3 + 2,
};
CASSERT(qnumber(levels_offsets) == nlevels+1);

//-------------------------------------------------------------------------
static int character_to_node_number(const char *name)
{
  for ( size_t i = 0; i < ncharacters; ++i )
    if ( streq(characters[i], name) )
      return int(i);
  INTERR(30630); // This shouldn't happen
}

//-------------------------------------------------------------------------
static const char *node_number_to_character(int n)
{
  QASSERT(30631, n >= 0 && n < ncharacters);
  return characters[n];
}

//-------------------------------------------------------------------------
// Relationship between the characters
struct parenthood_t
{
  const char *parent0;
  const char *parent1;
  const char *child;
};
DECLARE_TYPE_AS_MOVABLE(parenthood_t);
static const parenthood_t parenthood_data[] =
{
  // level 0
  { Finarfin, Earwen, Finrod },
  { Finarfin, Earwen, Angrod },
  { Finarfin, Earwen, Aegnor },
  { Finarfin, Earwen, Galadriel },

  // level 1
  { Eldalote, Angrod, Orodreth },
  { Galadriel, Celeborn, Celebrian },

  // level 2
  { Orodreth, Unknown_name, Gil_Galad },
  { Orodreth, Unknown_name, Finduilas },
};
static const size_t nparenthood = qnumber(parenthood_data);

//-------------------------------------------------------------------------
// Optional coloring of character names' text
struct character_name_decoration_t
{
  const char *name;
  const char *color;
  const char *name_subset;
};
DECLARE_TYPE_AS_MOVABLE(character_name_decoration_t);
static const character_name_decoration_t character_name_decorations[] =
{
  { Finarfin, SCOLOR_MACRO, "Fin" },
  { Finrod, SCOLOR_MACRO, "Fin" },
  { Finduilas, SCOLOR_MACRO, "Fin" },

  { Earwen, SCOLOR_CNAME, nullptr },
  { Unknown_name, SCOLOR_ERROR, "name unknown" },

  { Galadriel, SCOLOR_IMPNAME, "Gal" },
  { Gil_Galad, SCOLOR_IMPNAME, "Gal" },

  { Celeborn, SCOLOR_DNUM, "Celeb" },
  { Celebrian, SCOLOR_DNUM, "Celeb" },
};

//--------------------------------------------------------------------------
static void gen_character_name(qstring *out, const char *name)
{
  *out = name;

  for ( size_t i = 0; i < qnumber(character_name_decorations); ++i )
  {
    if ( streq(character_name_decorations[i].name, name) )
    {
      const character_name_decoration_t *d = &character_name_decorations[i];
      qstring token;
      token.append(SCOLOR_ON);
      token.append(d->color);
      const char *token_s = d->name_subset != nullptr ? d->name_subset : d->name;
      token.append(token_s);
      token.append(SCOLOR_OFF);
      token.append(d->color);
      out->replace(token_s, token.c_str());
      break;
    }
  }
}

//-------------------------------------------------------------------------
struct graph_data_t
{
  // Currently shown nodes data. Since we want to have some
  // nodes show a special color, we keep a 'live' version of
  // their text, which contains that information.
  qstrvec_t live;
  size_t levels_shown = 4;

  void refresh(interactive_graph_t *g);
};

//-------------------------------------------------------------------------
void graph_data_t::refresh(interactive_graph_t *g)
{
  QASSERT(30632, levels_shown < qnumber(levels_offsets));

  // Clear nodes & edges information
  g->clear();

  // Add nodes
  const size_t nnodes = levels_offsets[levels_shown];
  g->resize(nnodes);

  // Add edges
  for ( size_t i = 0; i < nparenthood; ++i )
  {
    const parenthood_t &p = parenthood_data[i];
    int c_n = character_to_node_number(p.child);
    if ( c_n >= g->size() )
      break; // means we are not showing this (and the following) level(s)
    int p0_n = character_to_node_number(p.parent0);
    int p1_n = character_to_node_number(p.parent1);
    g->add_edge(p0_n, c_n, nullptr);
    g->add_edge(p1_n, c_n, nullptr);
  }

  // Generate names w/ possible colors
  live.resize(nnodes);
  for ( size_t i = 0; i < nnodes; ++i )
    gen_character_name(&live[i], node_number_to_character(i));

  // Clear previously-registered custom text & background color.
  // (We could be smarter and move those from old nodes to new
  // nodes, but this would only bring little benefit in the
  // context of this sample.)
  for ( size_t i = 0; i < nnodes; ++i )
    del_node_info(g->gid, i);
}

//-------------------------------------------------------------------------
struct plugin_ctx_t;

//-------------------------------------------------------------------------
// A base action handler, ensuring the action is only available on the
// right widget, and possibly only if a (or more) node(s) is(are)
// selected.
struct base_ugraph_ah_t : public action_handler_t
{
  plugin_ctx_t &plg;
  bool requires_node;

  base_ugraph_ah_t(
        plugin_ctx_t &_plg,
        bool _requires_node=false)
    : plg(_plg),
      requires_node(_requires_node) {}
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;

  struct node_visitor_t
  {
    virtual ~node_visitor_t() {}
    virtual bool on_node(int node, node_info_t &ni) newapi = 0;
  };

protected:
  bool get_nodes(
        intvec_t *out,
        const action_ctx_base_t &ctx) const;

  bool for_each_node(
        const action_ctx_base_t &ctx,
        node_visitor_t &visitor);
};

//-------------------------------------------------------------------------
struct change_layout_ah_t : public base_ugraph_ah_t
{
  change_layout_ah_t(plugin_ctx_t &_plg)
    : base_ugraph_ah_t(_plg) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

//-------------------------------------------------------------------------
struct modify_levels_ah_t : public base_ugraph_ah_t
{
  int inc;

  modify_levels_ah_t(plugin_ctx_t &_plg, int _inc)
    : base_ugraph_ah_t(_plg),
      inc(_inc) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override;
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;

private:
  size_t compute_levels_to_show() const;
};

//-------------------------------------------------------------------------
struct set_custom_text_ah_t : public base_ugraph_ah_t
{
  set_custom_text_ah_t(plugin_ctx_t &_plg)
    : base_ugraph_ah_t(_plg, /*_requires_node=*/ true) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

//-------------------------------------------------------------------------
struct set_custom_bgcolor_ah_t : public base_ugraph_ah_t
{
  set_custom_bgcolor_ah_t(plugin_ctx_t &_plg)
    : base_ugraph_ah_t(_plg, /*_requires_node=*/ true) {}

  virtual int idaapi activate(action_activation_ctx_t *ctx) override;
};

#define ANAME_CHANGE_LAYOUT "ugraph:ChangeLayout"
#define ANAME_INC_LEVELS "ugraph:IncVisibleLevels"
#define ANAME_DEC_LEVELS "ugraph:DecVisibleLevels"
#define ANAME_SET_CUSTOM_TEXT "ugraph:SetCustomText"
#define ANAME_SET_CUSTOM_BGCOLOR "ugraph:SetCustomBgcolor"

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  change_layout_ah_t change_layout_ah = change_layout_ah_t(*this);
  const action_desc_t change_layout_desc = ACTION_DESC_LITERAL_PLUGMOD(
        ANAME_CHANGE_LAYOUT,
        "Change layout type",
        &change_layout_ah,
        this,
        nullptr,
        nullptr,
        -1);

  modify_levels_ah_t inc_levels_ah = modify_levels_ah_t(*this, 1);
  const action_desc_t inc_levels_desc = ACTION_DESC_LITERAL_PLUGMOD(
        ANAME_INC_LEVELS,
        "Add level",
        &inc_levels_ah,
        this,
        nullptr,
        nullptr,
        -1);

  modify_levels_ah_t dec_levels_ah = modify_levels_ah_t(*this, -1);
  const action_desc_t dec_levels_desc = ACTION_DESC_LITERAL_PLUGMOD(
        ANAME_DEC_LEVELS,
        "Remove level",
        &dec_levels_ah,
        this,
        nullptr,
        nullptr,
        -1);

  set_custom_text_ah_t set_custom_text_ah = set_custom_text_ah_t(*this);
  const action_desc_t set_custom_text_desc = ACTION_DESC_LITERAL_PLUGMOD(
        ANAME_SET_CUSTOM_TEXT,
        "Custom text",
        &set_custom_text_ah,
        this,
        nullptr,
        nullptr,
        -1);

  set_custom_bgcolor_ah_t set_custom_bgcolor_ah = set_custom_bgcolor_ah_t(*this);
  const action_desc_t set_custom_bgcolor_desc = ACTION_DESC_LITERAL_PLUGMOD(
        ANAME_SET_CUSTOM_BGCOLOR,
        "Custom background color",
        &set_custom_bgcolor_ah,
        this,
        nullptr,
        nullptr,
        -1);

  graph_data_t data;
  graph_viewer_t *gv = nullptr;

  plugin_ctx_t()
  {
    hook_event_listener(HT_VIEW, this);

    register_action(change_layout_desc);
    register_action(inc_levels_desc);
    register_action(dec_levels_desc);
    register_action(set_custom_text_desc);
    register_action(set_custom_bgcolor_desc);
  }
  ~plugin_ctx_t()
  {
    // FIXME: there is no delete counterpart to create_graph_viewer so we have a leak here
    gv = nullptr;
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
  static ssize_t idaapi gr_callback(void *ud, int code, va_list va);
};

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::gr_callback(void *ud, int code, va_list va)
{
  // Please refer to the SDK's graph.hpp for an explanation
  // of the notifications, and their parameters

  plugin_ctx_t &ctx = *(plugin_ctx_t *)ud;
  ssize_t result = 0;
  switch ( code )
  {
    case grcode_calculating_layout:
      msg("calculating graph layout...\n");
      break;

    case grcode_clicked:
      {
        graph_viewer_t *v = va_arg(va, graph_viewer_t *); qnotused(v);
        selection_item_t *it = va_arg(va, selection_item_t *); qnotused(it);
        graph_item_t *m = va_arg(va, graph_item_t *);
        msg("clicked on ");
        switch ( m->type )
        {
          case git_none:
            msg("background\n");
            break;
          case git_edge:
            msg("edge (%d, %d)\n", m->e.src, m->e.dst);
            break;
          case git_node:
            msg("node %d\n", m->n);
            break;
          case git_tool:
            msg("toolbutton %d\n", m->b);
            break;
          case git_text:
            msg("text (x,y)=(%d,%d)\n", m->p.x, m->p.y);
            break;
          case git_elp:
            msg("edge layout point (%d, %d) #%d\n", m->elp.e.src, m->elp.e.dst, m->elp.pidx);
            break;
        }
      }
      break;

    case grcode_dblclicked:
      {
        graph_viewer_t *v   = va_arg(va, graph_viewer_t *);
        selection_item_t *s = va_arg(va, selection_item_t *);
        msg("%p: dblclicked on ", v);
        if ( s == nullptr )
          msg("background\n");
        else if ( s->is_node )
          msg("node %d\n", s->node);
        else
          msg("edge (%d, %d) layout point #%d\n", s->elp.e.src, s->elp.e.dst, s->elp.pidx);
      }
      break;

    case grcode_creating_group:
      {
        interactive_graph_t *g = va_arg(va, interactive_graph_t *);
        intvec_t &nodes = *va_arg(va, intvec_t *);
        msg("%p: creating group", g);
        for ( intvec_t::iterator p=nodes.begin(); p != nodes.end(); ++p )
          msg(" %d", *p);
        msg("...\n");
      }
      break;

    case grcode_deleting_group:
      {
        interactive_graph_t *g = va_arg(va, interactive_graph_t *);
        int group = va_argi(va, int);
        msg("%p: deleting group %d\n", g, group);
      }
      break;

    case grcode_group_visibility:
      {
        interactive_graph_t *g = va_arg(va, interactive_graph_t *);
        int group = va_argi(va, int);
        bool expand = va_argi(va, bool);
        msg("%p: %scollapsing group %d\n", g, expand ? "un" : "", group);
      }
      break;

    case grcode_gotfocus:
      {
        graph_viewer_t *g = va_arg(va, graph_viewer_t *);
        msg("%p: got focus\n", g);
      }
      break;

    case grcode_lostfocus:
      {
        graph_viewer_t *g = va_arg(va, graph_viewer_t *);
        msg("%p: lost focus\n", g);
      }
      break;

    case grcode_user_refresh:
      {
        interactive_graph_t *g = va_arg(va, interactive_graph_t *);
        msg("%p: refresh\n", g);
        ctx.data.refresh(g);
        result = true;
      }
      break;

    case grcode_user_text:
      {
        interactive_graph_t *g = va_arg(va, interactive_graph_t *);
        int node           = va_arg(va, int);
        const char **text  = va_arg(va, const char **);
        bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
        *text = ctx.data.live[node].c_str();
        if ( bgcolor != nullptr )
          *bgcolor = DEFCOLOR;
        result = true;
        qnotused(g);
      }
      break;


    case grcode_user_size:
      // result is 0 -> ida will calculate the node size based on the node text
      break;

    case grcode_user_title:
      // result is 0 -> ida will draw the node title itself
      break;

    case grcode_user_draw:
      // result is 0 -> ida will draw the node text itself
      break;

    case grcode_user_hint:
      {
        interactive_graph_t *g = va_arg(va, interactive_graph_t *);
        int mousenode      = va_argi(va, int);
        int mouseedge_src  = va_argi(va, int);
        int mouseedge_dst  = va_argi(va, int);
        char **hint        = va_arg(va, char **);
        char buf[MAXSTR];
        buf[0] = '\0';
        if ( mousenode != -1 )
          qsnprintf(buf, sizeof(buf), "My fancy hint for node %d", mousenode);
        else if ( mouseedge_src != -1 )
          qsnprintf(buf, sizeof(buf), "Hovering on (%d,%d)", mouseedge_src, mouseedge_dst);
        if ( buf[0] != '\0' )
          *hint = qstrdup(buf);
        result = true; // use our hint
        qnotused(g);
      }
      break;
  }
  return result;
}

//-------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  if ( code == view_close )
  {
    TWidget *view = va_arg(va, TWidget *);
    if ( view == (TWidget *)gv )
      gv = nullptr;
  }
  return 0;
}

//-------------------------------------------------------------------------
action_state_t idaapi base_ugraph_ah_t::update(action_update_ctx_t *ctx)
{
  if ( ctx->widget != (TWidget *) plg.gv )
    return AST_DISABLE_FOR_WIDGET;
  if ( requires_node )
  {
    // If this requires nodes, we want to be called again as
    // soon as something (i.e., the selection) changes
    return get_nodes(nullptr, *ctx) ? AST_ENABLE : AST_DISABLE;
  }
  else
  {
    return AST_ENABLE_FOR_WIDGET;
  }
}

//-------------------------------------------------------------------------
bool base_ugraph_ah_t::get_nodes(
        intvec_t *out,
        const action_ctx_base_t &ctx) const
{
  screen_graph_selection_t *s = ctx.graph_selection;
  if ( s == nullptr )
    return false;
  intvec_t tmp;
  size_t nitems = s->size();
  for ( size_t i = 0; i < nitems; ++i )
  {
    const selection_item_t &item = s->at(i);
    if ( item.is_node )
      tmp.push_back(item.node);
  }
  bool ok = !tmp.empty();
  if ( out != nullptr )
    out->swap(tmp);
  return ok;
}

//-------------------------------------------------------------------------
bool base_ugraph_ah_t::for_each_node(
        const action_ctx_base_t &ctx,
        node_visitor_t &visitor)
{
  interactive_graph_t *g = get_viewer_graph(plg.gv);
  intvec_t nodes;
  bool ok = get_nodes(&nodes, ctx);
  if ( ok )
  {
    size_t nnodes = nodes.size();
    for ( size_t i = 0; i < nnodes; ++i )
    {
      int node = nodes[i];
      node_info_t ni;
      get_node_info(&ni, g->gid, node);
      visitor.on_node(node, ni);
      uint32 niflags = ni.get_flags_for_valid();
      if ( niflags != 0 )
        set_node_info(g->gid, node, ni, niflags);
      else
        del_node_info(g->gid, node);
    }
  }
  return ok;
}

//-------------------------------------------------------------------------
int idaapi change_layout_ah_t::activate(action_activation_ctx_t *)
{
  interactive_graph_t *g = get_viewer_graph(plg.gv);
  int code = ask_buttons(
          "Circle", "Tree", "Digraph", 1, "Please select layout type");
  g->current_layout = code + 2;
  g->circle_center = point_t(200, 200);
  g->circle_radius = 200;
  refresh_viewer(plg.gv);
  return 1;
}

//-------------------------------------------------------------------------
int idaapi modify_levels_ah_t::activate(action_activation_ctx_t *)
{
  plg.data.levels_shown = compute_levels_to_show();
  refresh_viewer(plg.gv);
  return 1;
}

//-------------------------------------------------------------------------
action_state_t idaapi modify_levels_ah_t::update(action_update_ctx_t *ctx)
{
  action_state_t state = base_ugraph_ah_t::update(ctx);
  if ( !is_action_enabled(state) )
    return state;
  const size_t next = compute_levels_to_show();
  return next > 0 && next <= nlevels ? AST_ENABLE : AST_DISABLE;
}

//-------------------------------------------------------------------------
size_t modify_levels_ah_t::compute_levels_to_show() const
{
  return plg.data.levels_shown + inc;
}

//-------------------------------------------------------------------------
int idaapi set_custom_text_ah_t::activate(action_activation_ctx_t *ctx)
{
  struct ida_local visitor_t : public node_visitor_t
  {
    qstring text;

    virtual ~visitor_t() {}
    virtual bool on_node(int, node_info_t &ni) override
    {
      ni.text = text;
      return true;
    }
  };
  visitor_t visitor;
  return ask_text(&visitor.text, 256, nullptr, "Please enter node custom text")
      && for_each_node(*ctx, visitor);
}

//-------------------------------------------------------------------------
int idaapi set_custom_bgcolor_ah_t::activate(action_activation_ctx_t *ctx)
{
  struct ida_local visitor_t : public node_visitor_t
  {
    bgcolor_t bg_color = DEFCOLOR;

    virtual ~visitor_t() {}
    virtual bool on_node(int, node_info_t &ni) override
    {
      ni.bg_color = bg_color;
      return true;
    }
  };
  visitor_t visitor;
  static const char form[] =
    "Please pick a color\n"
    "\n"
    "<~C~olor:K::6::>\n";

  CASSERT(sizeof(visitor.bg_color) == sizeof(bgcolor_t));
  return ask_form(form, &visitor.bg_color)
      && for_each_node(*ctx, visitor);
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( !is_idaq() )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char wanted_title[] = "Sample graph";
bool idaapi plugin_ctx_t::run(size_t)
{
  TWidget *widget = find_widget(wanted_title);
  if ( widget == nullptr )
  {
    // get a unique graph id
    netnode id;
    id.create("$ ugraph sample");
    gv = create_graph_viewer(wanted_title, id, gr_callback, this, 0);
    if ( gv != nullptr )
    {
      display_widget(gv, WOPN_DP_TAB);
      viewer_fit_window(gv);
      register_action(change_layout_desc);
      register_action(inc_levels_desc);
      register_action(dec_levels_desc);
      register_action(set_custom_text_desc);
      register_action(set_custom_bgcolor_desc);
      widget = find_widget(wanted_title);
      attach_action_to_popup(widget, nullptr, change_layout_desc.name);
      attach_action_to_popup(widget, nullptr, inc_levels_desc.name);
      attach_action_to_popup(widget, nullptr, dec_levels_desc.name);
      attach_action_to_popup(widget, nullptr, set_custom_text_desc.name, "Set/");
      attach_action_to_popup(widget, nullptr, set_custom_bgcolor_desc.name, "Set/");
    }
  }
  else
  {
    close_widget(widget, 0);
  }

  return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "This is a sample graph plugin.";

static const char help[] =
  "A sample graph plugin module\n"
  "\n"
  "This module shows you how to create a graph viewer.";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overridden in plugins.cfg file

static const char wanted_name[] = "Create sample graph view";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overridden in plugins.cfg file

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

  nullptr,              // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
