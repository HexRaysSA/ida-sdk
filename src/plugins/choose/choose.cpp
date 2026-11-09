/*
 *  This is a sample plugin module
 *
 *  It demonstrates the use of the choose() function
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>

struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t arg) override;
};

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//-------------------------------------------------------------------------
// non-modal call instruction chooser
struct calls_chooser_t : public chooser_t
{
protected:
  static const int widths_[];
  static const char *const header_[];

public:
  // remember the call instruction addresses in this qvector
  eavec_t list;

  // this object must be allocated using `new`
  calls_chooser_t(const char *title, bool ok, func_item_iterator_t *fii);

  // function that is used to decide whether a new chooser should be opened
  // or we can use the existing one.
  // The contents of the window are completely determined by its title
  virtual const void *get_obj_id(size_t *len) const override
  {
    *len = strlen(title);
    return title;
  }

  // function that returns number of lines in the list
  virtual size_t idaapi get_count() const override { return list.size(); }

  // function that generates the list line
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;

  // function that is called when the user hits Enter
  virtual cbret_t idaapi enter(size_t n) override
  {
    if ( n < list.size() )
      jumpto(list[n]);
    return cbret_t(); // nothing changed
  }

protected:
  void build_list(bool ok, func_item_iterator_t *fii)
  {
    insn_t insn;
    while ( ok )
    {
      ea_t ea = fii->current();
      if ( decode_insn(&insn, ea) > 0 && is_call_insn(insn) ) // a call instruction is found
        list.push_back(ea);
      ok = fii->next_code();
    }
  }
};

// column widths
const int calls_chooser_t::widths_[] =
{
  CHCOL_HEX | 8,  // Address
  32,             // Instruction
};
// column headers
const char *const calls_chooser_t::header_[] =
{
  "Address",      // 0
  "Instruction",  // 1
};

inline calls_chooser_t::calls_chooser_t(
        const char *title_,
        bool ok,
        func_item_iterator_t *fii)
  : chooser_t(0, qnumber(widths_), widths_, header_, title_),
    list()
{
  CASSERT(qnumber(widths_) == qnumber(header_));

  // build the list of calls
  build_list(ok, fii);
}

void idaapi calls_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  // assert: n < list.size()
  ea_t ea = list[n];

  // generate the line
  qstrvec_t &cols = *cols_;
  cols[0].sprnt("%08a", ea);
  generate_disasm_line(&cols[1], ea, GENDSM_REMOVE_TAGS);
  CASSERT(qnumber(header_) == 2);
}


//--------------------------------------------------------------------------
// The plugin method
// This is the main function of the plugin.
bool idaapi plugin_ctx_t::run(size_t)
{
  qstring title;
  // Let's display the functions called from the current one
  // or from the selected area

  // First we determine the working area
  func_item_iterator_t fii;
  bool ok;
  ea_t ea1, ea2;
  if ( read_range_selection(nullptr, &ea1, &ea2) ) // the selection is present?
  {
    callui(ui_unmarksel);                       // unmark selection
    title.sprnt("Functions called from %08a..%08a", ea1, ea2);
    ok = fii.set_range(ea1, ea2);
  }
  else                                          // nothing is selected
  {
    func_t *pfn = get_func(get_screen_ea());    // try the current function
    if ( pfn == nullptr )
    {
      warning("Please position the cursor on a function or select an area");
      return true;
    }
    ok = fii.set(pfn);
    get_func_name(&title, pfn->start_ea);
    title.insert("Functions called from ");
  }

  // now open the window
  calls_chooser_t *ch = new calls_chooser_t(title.c_str(), ok, &fii);
  ch->choose(); // the default cursor position is 0 (first row)
  return true; //-V773
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  // plugin flags
  PLUGIN_MULTI,
  // initialize
  init,
  nullptr,
  nullptr,
  // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  "This is a sample plugin. It displays the chooser window",
  // multiline help about the plugin
  "A sample plugin module\n"
  "\n"
  "This module shows you how to use choose() function.\n",

  // the preferred short name of the plugin
  "Called functions",
  // the preferred hotkey to run the plugin
  ""
};
