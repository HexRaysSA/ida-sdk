
%{
#include <pathfind.hpp>
%}

// 'from' is a reserved Python keyword
%rename (frm) path_node_t::from;

%template(path_node_list_t) qvector<path_node_t>;
%template(path_pair_info_vec_t) qvector<path_pair_info_t>;

%typemap(out) path_node_list_t *nodes,
              path_pair_info_vec_t *pair_info
{
  $result = SWIG_NewPointerObj($1, $1_descriptor, 0);
  if ( $result != nullptr && $result != Py_None )
    PyObject_SetAttrString($result, "__swig_parent__", $self);
}

// The C export uses an output parameter (extern "C" cannot return C++
// types).  Provide a Python-friendly wrapper that returns the result
// directly, and hide the inner routine from SWIG.
%inline %{
/// \brief Find call-graph paths between consecutive waypoints.
/// Returns a pathfinding_result_t (empty on failure).
pathfinding_result_t find_path(const pathfinding_cfg_t &cfg)
{
  pathfinding_result_t result;
  find_path(&result, cfg);
  return result;
}
%}

%ignore find_path(pathfinding_result_t *, const pathfinding_cfg_t &);

%include "pathfind.hpp"
