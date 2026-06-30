%include "std_string_view.i"

%{
#include <loader.hpp>
#include <dscu.h>
%}

%ignore dscu_req_t;
%ignore dscu_svc_t::get_toplevel;
%ignore dscu_create_layout_req_t;
%ignore dscu_svc_req_t;

%feature("nodirector") dscu_svc_t;

//-------------------------------------------------------------------------
// intvec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) intvec_t *out (intvec_t temp)
{
  // %typemap(in,numinputs=0) intvec_t *out (intvec_t temp)
  $1 = &temp;
}
%typemap(argout) intvec_t *out
{
  // %typemap(argout) intvec_t *out
  if ( result )
  {
    ref_t py_list(PyW_IntVecToPyList(*($1)));
    py_list.incref();
    $result = py_list.o;
  }
  else
  {
    Py_INCREF(Py_None);
    $result = Py_None;
  }
}
%typemap(freearg) intvec_t *out
{
  // %typemap(freearg) intvec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// sizevec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) sizevec_t *out (sizevec_t temp)
{
  // %typemap(in,numinputs=0) sizevec_t *out (sizevec_t temp)
  $1 = &temp;
}
%typemap(argout) sizevec_t *out
{
  // %typemap(argout) sizevec_t *out
  if ( result )
  {
    ref_t py_list(PyW_SizeVecToPyList(*($1)));
    py_list.incref();
    $result = py_list.o;
  }
  else
  {
    Py_INCREF(Py_None);
    $result = Py_None;
  }
}
%typemap(freearg) sizevec_t *out
{
  // %typemap(freearg) sizevec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
%extend region_info_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("region_info_t(start=%a, size=%" FMT_Z " (0x%llx), type=%d, image_index/branch_island_number=%d, name=\"%s\")",
              $self->start,
              size_t($self->size), uint64($self->size),
              int($self->type),
              $self->image_index,
              $self->name);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%template(symbol_match_vec_t) qvector<symbol_match_t>;
%template(string_match_vec_t) qvector<string_match_t>;
%template(region_info_vec_t) qvector<region_info_t>;
%template(mapping_coords_vec_t) qvector<mapping_coords_t>;
%template(dependency_match_entry_vec_t) qvector<dependency_match_entry_t>;

//-------------------------------------------------------------------------
// symbol_match_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) symbol_match_vec_t *out (symbol_match_vec_t temp)
{
  // %typemap(in,numinputs=0) symbol_match_vec_t *out (symbol_match_vec_t temp)
  $1 = &temp;
}
%typemap(argout) symbol_match_vec_t *out
{
  // %typemap(argout) symbol_match_vec_t *out
  Py_XDECREF($result);
  auto *inst = new symbol_match_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) symbol_match_vec_t *out
{
  // %typemap(freearg) symbol_match_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// string_match_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) string_match_vec_t *out (string_match_vec_t temp)
{
  // %typemap(in,numinputs=0) string_match_vec_t *out (string_match_vec_t temp)
  $1 = &temp;
}
%typemap(argout) string_match_vec_t *out
{
  // %typemap(argout) string_match_vec_t *out
  Py_XDECREF($result);
  auto *inst = new string_match_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) string_match_vec_t *out
{
  // %typemap(freearg) string_match_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// mapping_coords_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) mapping_coords_vec_t *out (mapping_coords_vec_t temp)
{
  // %typemap(in,numinputs=0) mapping_coords_vec_t *out (mapping_coords_vec_t temp)
  $1 = &temp;
}
%typemap(argout) mapping_coords_vec_t *out
{
  // %typemap(argout) mapping_coords_vec_t *out
  Py_XDECREF($result);
  auto *inst = new mapping_coords_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) mapping_coords_vec_t *out
{
  // %typemap(freearg) mapping_coords_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// region_info_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) region_info_vec_t *out (region_info_vec_t temp)
{
  // %typemap(in,numinputs=0) region_info_vec_t *out (region_info_vec_t temp)
  $1 = &temp;
}
%typemap(argout) region_info_vec_t *out
{
  // %typemap(argout) region_info_vec_t *out
  Py_XDECREF($result);
  auto *inst = new region_info_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) region_info_vec_t *out
{
  // %typemap(freearg) region_info_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

// Same for `vout` + override
%apply region_info_vec_t *out { region_info_vec_t *vout };
%typemap(argout) region_info_vec_t *vout
{
  // %typemap(argout) region_info_vec_t *vout
  auto *inst = new region_info_vec_t();
  Py_XDECREF($result);
  inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}

//-------------------------------------------------------------------------
// range_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) range_t *out (range_t temp)
{
  // %typemap(in,numinputs=0) range_t *out (range_t temp)
  $1 = &temp;
}
%typemap(argout) range_t *out
{
  // %typemap(argout) range_t *out
  Py_XDECREF($result);
  auto *inst = new range_t();
  if ( result )
    *inst = *$1;
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) range_t *out
{
  // %typemap(freearg) range_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// dependency_match_result_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) dependency_match_result_t *out (dependency_match_result_t temp)
{
  // %typemap(in,numinputs=0) dependency_match_result_t *out (dependency_match_result_t temp)
  $1 = &temp;
}
%typemap(argout) dependency_match_result_t *out
{
  // %typemap(argout) dependency_match_result_t *out
  if ( result == dscu_svc_t::dmc_ok )
  {
    PyObject *py_inst = SWIG_NewPointerObj(new dependency_match_result_t(*($1)), $1_descriptor, SWIG_POINTER_OWN | 0);
    $result = SWIG_Python_AppendOutput($result, py_inst, /*is_void=*/ 1);
  }
  else
  {
    Py_INCREF(Py_None);
    $result = SWIG_Python_AppendOutput($result, Py_None, /*is_void=*/ 1);
  }
}
%typemap(freearg) dependency_match_result_t *out
{
  // %typemap(freearg) dependency_match_result_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
%extend address_info_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_dscu.address_info_t("
              "region=%s, "
              "mapping=ida_dscu.mapping_coords_t(file_index=%hd, mapping_index=%hd), "
              "file_offset=0x%llx)",
              qstring().sprnt(
                "region_info_t(start=%a, size=0x%llx, type=%d, "
                "image_index/branch_island_number=%d, name=\"%s\")",
                $self->region.start,
                uint64($self->region.size),
                int($self->region.type),
                $self->region.image_index,
                $self->region.name).c_str(),
              $self->mapping.file_index, $self->mapping.mapping_index,
              (unsigned long long) $self->file_offset);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend mapping_coords_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_dscu.mapping_coords_t(file_index=%hd, mapping_index=%hd)",
              $self->file_index, $self->mapping_index);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend dependency_match_entry_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_dscu.dependency_match_entry_t(image_name=%s, image_index=%d, load_command_type=%u)",
              $self->image_name.c_str(),
              $self->image_index,
              $self->load_command_type);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend symbol_match_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_dscu.symbol_match_t(symbol=\"%.*s\", ea=%a, image_index=%d)",
              int($self->symbol.size()),
              $self->symbol.data(),
              $self->ea,
              $self->image_index);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend string_match_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_dscu.string_match_t(ea=%a, image_index=%d, "
              "file_index=%" FMT_Z ", file_offset=0x%" FMT_64 "x, "
              "context=\"%s\")",
              $self->ea,
              $self->image_index,
              $self->file_index,
              $self->file_offset,
              $self->context.c_str());
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}



%include <dscu.h>
