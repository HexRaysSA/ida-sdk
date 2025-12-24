%{
#include <undo.hpp>
%}

// Make the label output argument for `get_undo_action_label/get_redo_action_label`
%apply qstring *result { qstring *action_to_be_undone, qstring *action_to_be_redone};

%inline %{
// And define our own wrapper, too

/// Create a new restore point.
/// The user can undo to this point in the future.
/// \param action_name  name of the action for UNDO_ACTION_START
/// \param label        label for the undo action
/// \return success; undo can be disabled, such as during auto-analysis.
bool create_undo_point(const char *action_name, const char *label)
{
  bytevec_t rec;
  rec.pack_ds(action_name);
  rec.pack_ds(label);
  return create_undo_point(rec.begin(), rec.size());
}
%}

// Use documentation for our wrapper, not the inner routine.
%ignore create_undo_point(const uchar *bytes, size_t size);

%include "undo.hpp"
