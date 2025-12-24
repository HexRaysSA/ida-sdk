
%{
#include <dirtree.hpp>
%}

%apply SWIGTYPE *DISOWN { dirspec_t *ds };

%template(direntry_vec_t) qvector<direntry_t>;
%template(dirtree_cursor_vec_t) qvector<dirtree_cursor_t>;
%uncomparable_elements_qvector(dirtree_bulk_result_t, dirtree_bulk_results_t);


//
// compat
//
%ignore dirtree_get_nodename;
%ignore dirtree_set_nodename;
%ignore dirtree_add_event_handler;
%ignore dirtree_remove_event_handler;

%extend dirspec_t {
  %pythoncode {
      nodename = id
  }
}

%extend dirtree_t {
  %pythoncode {
      get_nodename = get_id
      set_nodename = set_id
  }
}

%include "dirtree.hpp"
