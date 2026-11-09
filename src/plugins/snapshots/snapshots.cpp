/*
* This is a sample plugin to demonstrate the snapshot management API
*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
class snapman_t : public chooser_t
{
  struct snapdesc_t
  {
    snapshot_t *ss;
    qstring title;
    qstring date;
  };
  typedef qvector<snapdesc_t> sdlist_t;
  snapshot_t root;
  sdlist_t sdlist;

  static const int widths_[2];
  static const char *const header_[2];

  static void idaapi done_restore(const char *err_msg, void *)
  {
    if ( err_msg != nullptr )
      warning("ICON ERROR\nError restoring: %s", err_msg);
    else
      warning("Restored successfully!");
  }

  void build_tree_list(snapshot_t *n, int level = 0)
  {
    if ( n != &root )
    {
      // Insert new description record
      snapdesc_t &sd = sdlist.push_back();

      // Compute title
      for ( int i=0; i < level; i++ )
        sd.title += "      ";
      if ( n->id == root.id )
        sd.title += "->";
      sd.title += n->desc;

      // Compute date
      char ss_date[MAXSTR];
      qstrftime64(ss_date, sizeof(ss_date), "%Y-%m-%d %H:%M:%S", n->id);
      sd.date = ss_date;
      // Store ss
      sd.ss = n;
    }
    for ( snapshots_t::iterator it=n->children.begin(); it != n->children.end(); ++it )
      build_tree_list(*it, level+1);
  }

  snapdesc_t *get_item(uint32 n)
  {
    return n >= sdlist.size() ? nullptr : &sdlist[n];
  }
  const snapdesc_t *get_item(uint32 n) const
  {
    return n >= sdlist.size() ? nullptr : &sdlist[n];
  }

public:
  bool init() override
  {
    sdlist.clear();
    root.clear();
    if ( !build_snapshot_tree(&root) )
    {
      warning("Snapshot tree cannot be built.\nNo snapshots exist?");
      return false;
    }

    // Convert the tree to a list
    build_tree_list(&root);
    if ( sdlist.empty() )
    {
      warning("Snapshot tree empty!");
      return false;
    }
    return true;
  }

  snapman_t()
    : chooser_t(CH_MODAL | CH_KEEP | CH_CAN_INS | CH_CAN_DEL | CH_CAN_EDIT,
                qnumber(widths_), widths_, header_,
                "Simple snapshot manager"),
      root(),
      sdlist() {}

  virtual size_t idaapi get_count() const override
  {
    return sdlist.size();
  }

  virtual void idaapi get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
  {
    const snapdesc_t *sd = get_item(n);
    QASSERT(561, sd != nullptr);

    qstrvec_t &cols = *cols_;
    cols[0] = sd->date;
    cols[1] = sd->title;
  }

  virtual cbret_t idaapi ins(ssize_t n) override
  {
    qstring desc = "snapshot description";
    if ( !ask_str(&desc, HIST_CMT, "Enter snapshot description") )
      return cbret_t(); // nothing changed

    qstring err_msg;
    snapshot_t new_attr;
    qstrncpy(new_attr.desc, desc.c_str(), sizeof(new_attr.desc));
    if ( !take_database_snapshot(&new_attr, &err_msg) )
    {
      warning("Failed to create a snapshot, error: %s", err_msg.c_str());
      return cbret_t(); // nothing changed
    }
    msg("Created new snapshot: %s\n", new_attr.filename);
    init();
    // we preserve the selection
    // FIXME use get_item_index()
    return n;
  }

  virtual cbret_t idaapi del(size_t n) override
  {
    const snapdesc_t *sd = get_item(n);
    if ( sd == nullptr )
      return cbret_t();

    // Simply delete the file
    qunlink(sd->ss->filename);

    // Rebuild the list
    init();

    return adjust_last_item(n); // take in account deleting of the last item
  }

  virtual cbret_t idaapi edit(size_t n) override
  {
    snapdesc_t *sd = get_item(n);
    if ( sd == nullptr )
      return cbret_t();

    qstring desc = sd->ss->desc;
    if ( !ask_str(&desc, HIST_CMT, "Enter new snapshot description") )
      return cbret_t();

    // Update the description
    qstrncpy(sd->ss->desc, desc.c_str(), sizeof(sd->ss->desc));
    update_snapshot_attributes(sd->ss->filename, &root, sd->ss, SSUF_DESC);
    return n;
  }

  // calculate the location of the default item only,
  // `item_data` is a pointer to a snapshot ID
  virtual ssize_t idaapi get_item_index(const void *item_data) const override
  {
    qtime64_t item_id = *(const qtime64_t *)item_data;
    for ( size_t i = 0; i < sdlist.size(); ++i )
    {
      if ( sdlist[i].ss->id == item_id )
        return i;
    }
    return NO_SELECTION;
  }

  void show()
  {
    // now open the window
    ssize_t n = ::choose(this, &root.id);
    if ( n >= 0 )
    {
      snapdesc_t *sd = get_item(n);
      if ( sd != nullptr && sd->ss != nullptr )
        restore_database_snapshot(sd->ss, done_restore, nullptr);
    }
  }
};
DECLARE_TYPE_AS_MOVABLE(snapman_t::snapdesc_t);

// column widths
const int snapman_t::widths_[2] =
{
  12, // Date
  70, // Description
};

// column headers
const char *const snapman_t::header_[2] =
{
  "Date",         // 0
  "Description",  // 1
};


//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  snapman_t sm;
  if ( !sm.init() )
    return false;

  sm.show();
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  // Display help
  msg(
    "Simple snapshot manager loaded!\n"
    "Press Shift+F8 to toggle the plugin\n"
    "Inside the snapshots window, press:\n"
    " - Insert: to take a snapshot\n"
    " - Delete: to delete\n"
    " - Edit: to edit the snapshot description\n"
    "\n"
    "Click on:\n"
    " - Ok: to restore the selected snapshot\n"
    " - Cancel: close without doing anything\n");

  // The plugin flags must include PLUGIN_FIX as well
  return new plugin_ctx_t;
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
  PLUGIN_FIX            // Load plugin when IDA starts and keep it in the
                        // memory until IDA stops
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "This is a sample plugin. It displays the list of snapshots",
                        // long comment about the plugin
  "A snapshot manager sample plugin\n"
  "\n"
  "This plugin allows you to list and restore snapshots.\n",
                        // multiline help about the plugin
  "Simple snapshot manager", // the preferred short name of the plugin
  "Shift-F8",           // the preferred hotkey to run the plugin
};
