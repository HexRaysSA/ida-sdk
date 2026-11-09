/*
 *  This is a sample plugin module
 *
 *      It demonstrates how to get the the entry point prototypes
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

//-------------------------------------------------------------------------
// non-modal entry point chooser
struct entry_chooser_t : public chooser_t
{
protected:
  struct item_t
  {
    ea_t ea;
    qstring decl;
    int ord;
    uint32 argsize;
  };
  // remember the information about an entry point in this qvector
  qvector<item_t> list;

  static const int widths_[];
  static const char *const header_[];

public:
  // this object must be allocated using `new`
  entry_chooser_t();

  // function that is used to decide whether a new chooser should be opened
  // or we can use the existing one.
  // There should be the only window as the entry points data are static.
  virtual const void *get_obj_id(size_t *len) const override { *len = 1; return ""; }

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
      jumpto(list[n].ea);
    return cbret_t(); // nothing changed
  }

  // function that is called when the chooser is initialized
  virtual bool idaapi init() override
  {
    // rebuild the list
    list.clear();
    size_t n = get_entry_qty();
    // gather information about the entry points
    for ( size_t i = 0; i < n; ++i )
    {
      asize_t ord = get_entry_ordinal(int(i));
      ea_t ea = get_entry(ord);
      if ( ord == ea )
        continue;
      tinfo_t type;
      qstring decl;
      qstring long_name;
      qstring true_name;
      asize_t argsize = 0;
      qstring entry_name;
      get_entry_name(&entry_name, ord);
      if ( get_tinfo(&type, ea) && type.print(&decl, entry_name.c_str()) )
      {
        // found type info, calc the size of arguments
        func_type_data_t fi;
        if ( type.get_func_details(&fi) && !fi.empty() )
        {
          for ( int k=0; k < fi.size(); k++ )
          {
            int s1 = fi[k].type.get_size();
            uchar szi = inf_get_cc_size_i();
            s1 = qmax(s1, szi);
            argsize += s1;
          }
        }
      }
      else if ( get_long_name(&long_name, ea) > 0
             && get_name(&true_name, ea, GN_NOT_DUMMY) > 0
             && long_name != true_name )
      {
        // found mangled name
      }
      else
      {
        // found nothing, just show the name
        if ( get_visible_name(&decl, ea) <= 0 )
          continue;
      }
      if ( argsize == 0 )
      {
        func_t *pfn = get_func(ea);
        if ( pfn != nullptr )
          argsize = pfn->argsize;
      }
      item_t x;
      x.ord = ord;
      x.ea = ea;
      x.decl.swap(decl);
      x.argsize = uint32(argsize);
      list.push_back(x);
    }
    return true;
  }

  // function that is called when the user wants to refresh the chooser
  virtual cbret_t idaapi refresh(ssize_t n) override
  {
    init();
    if ( n < 0 )
      return NO_SELECTION;
    return adjust_last_item(n);  // try to preserve the cursor
  }
};
DECLARE_TYPE_AS_MOVABLE(entry_chooser_t::item_t);

// column widths
const int entry_chooser_t::widths_[] =
{
  CHCOL_DEC | 4,  // Ordinal
  CHCOL_HEX | 8,  // Address
  CHCOL_HEX | 6,  // ArgSize
  70,             // Declaration
};
// column headers
const char *const entry_chooser_t::header_[] =
{
  "Ordinal",      // 0
  "Address",      // 1
  "ArgSize",      // 2
  "Declaration",  // 3
};

inline entry_chooser_t::entry_chooser_t()
  : chooser_t(CH_CAN_REFRESH, // user can refresh the chooser using Ctrl-U
              qnumber(widths_), widths_, header_,
              "Exported functions"),
    list()
{
  CASSERT(qnumber(widths_) == qnumber(header_));
}

void idaapi entry_chooser_t::get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const
{
  // assert: n < list.size()
  const item_t &item = list[n];

  // generate the line
  qstrvec_t &cols = *cols_;
  cols[0].sprnt("%d", item.ord);
  cols[1].sprnt("%08a", item.ea);
  if ( item.argsize != 0 )
    cols[2].sprnt("%04x", item.argsize);
  cols[3] = item.decl;
  CASSERT(qnumber(header_) == 4);
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  if ( !auto_is_ok()
    && ask_yn(ASKBTN_NO,
              "HIDECANCEL\n"
              "The autoanalysis has not finished yet.\n"
              "The result might be incomplete.\n"
              "Do you want to continue?") < ASKBTN_YES )
  {
    return true;
  }

  // open the window
  entry_chooser_t *ch = new entry_chooser_t();
  ch->choose();
  return true; //-V773
} //lint !e429 'ch' has not been freed or returned

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if ( get_entry_qty() == 0 )
    return nullptr;
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "Generate list of exported function prototypes",
  "Generate list of exported function prototypes",
  "List of exported functions",
  "Ctrl-F11",
};
