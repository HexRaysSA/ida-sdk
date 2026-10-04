// kcu_symbol_match_t::symbol is a std::string_view; without this it reaches a
// script as an opaque proxy rather than as the name. Same as dscu.i does.
%include "std_string_view.i"

%{
#include <loader.hpp>
#include <kcu_minimal.h>
#include <kcu.h>
%}

// the request objects are an internal loader<->plugin protocol, not API
%ignore kcu_req_t;
%ignore kcu_svc_req_t;

%feature("nodirector") kcu_svc_t;

// get_kext_region_indexes() should hand Python a list, not a bool + out-vector
%apply sizevec_t *result_list { sizevec_t *out };

//-------------------------------------------------------------------------
// the encoding constants are C++ spelling aids; a script uses the accessors.
// SWIG would also try to generate setters for them, which does not compile.
%ignore kext_coords_t::KC_SHIFT;
%ignore kext_coords_t::INDEX_MASK;
%ignore kext_coords_t::KC_NONE;

%extend kext_coords_t
{
  bool __eq__(const kext_coords_t &r) const { return *$self == r; }
  bool __ne__(const kext_coords_t &r) const { return *$self != r; }
  // defining __eq__ would otherwise set __hash__ to None, and a KEXT
  // coordinate is the natural key of a per-KEXT dict
  uint32 __hash__() const { return $self->packed; }
  qstring __repr__() const
  {
    qstring tmp;
    if ( $self->is_valid() )
      tmp.sprnt("kext_coords_t(kc=%s, index=%u)",
                kc_type_name($self->get_kc()), $self->get_index());
    else
      tmp = "BADKEXT";
    return tmp;
  }
  // the coordinates read as attributes, the way they did when they were
  // bit-fields of a union
  %pythoncode {
    kc = property(lambda self: self.get_kc())
    """the collection this KEXT belongs to, or kc_none"""
    index = property(lambda self: self.get_index())
    """KEXT index within its collection"""
  }
}

// A qstrvec_t *member* is read through a generated getter returning
// qstrvec_t *, which without this comes back as an opaque proxy -- only an
// out-parameter gets the list typemap from header.i.in. Same shape as
// kernwin.i and lumina.i use; kept in this module rather than in header.i.in,
// where it would apply to every qstrvec_t * in the API.
%typemap(out) qstrvec_t *
{ // %typemap(out) qstrvec_t *
  Py_XDECREF($result);
  $result = qstrvec2pylist(*$1);
}

%template(kext_coords_vec_t) qvector<kext_coords_t>;

//-------------------------------------------------------------------------
%extend kcu_config_t
{
  qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("kcu_config_t(segname_format=\"%s\")",
              $self->segname_format.c_str());
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend kcu_region_info_t
{
  qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("kcu_region_info_t(start=%a, size=0x%" FMT_64 "x, type=%s, kext=%08X, segname=\"%s\", sectname=\"%s\")",
              $self->start, $self->size, kcu_region_type_name($self->type), $self->kext.packed,
              $self->segname.c_str(), $self->sectname.c_str());
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

%template(kcu_region_info_vec_t) qvector<kcu_region_info_t>;

//-------------------------------------------------------------------------
%extend kcu_linked_kc_info_t
{
  qstring __str__() const
  {
    qstring uuid;
    for ( size_t i = 0; i < $self->uuid.size(); i++ )
      uuid.cat_sprnt("%02X", $self->uuid[i]);
    qstring tmp;
    tmp.sprnt("kcu_linked_kc_info_t(kc=%s, loaded=%s, uuid=%s, path=\"%s\")",
              kc_type_name($self->kc), $self->loaded ? "true" : "false",
              uuid.c_str(), $self->path.c_str());
    if ( $self->loaded )
      tmp.cat_sprnt(" @ %a", $self->base);
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

%template(kcu_linked_kc_info_vec_t) qvector<kcu_linked_kc_info_t>;

//-------------------------------------------------------------------------
%extend kcu_kext_dep_t
{
  qstring __str__() const
  {
    qstring tmp = $self->id;
    if ( !$self->version.empty() )
      tmp.cat_sprnt(" %s", $self->version.c_str());
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

%template(kcu_kext_dep_vec_t) qvector<kcu_kext_dep_t>;

//-------------------------------------------------------------------------
// a fixed-size C array would otherwise reach a script as an opaque pointer
%ignore kcu_kext_info_t::uuid;

%template (kcu_kext_uuid_array) wrapped_array_t<uchar,16>;

%extend kcu_kext_info_t
{
  wrapped_array_t<uchar,16> __getUuid()
  {
    return wrapped_array_t<uchar,16>($self->uuid);
  }

  qstring __str__() const
  {
    qstring uuid;
    if ( $self->has_uuid() )
    {
      for ( size_t i = 0; i < sizeof($self->uuid); i++ )
        uuid.cat_sprnt("%02X", $self->uuid[i]);
    }
    qstring tmp;
    tmp.sprnt("kcu_kext_info_t(id=\"%s\", version=\"%s\", path=\"%s\", "
              "executable=\"%s\", ndeps=%" FMT_Z ", nclasses=%" FMT_Z ", "
              "uuid=%s, kinfo_ea=%a, "
              "loadaddr=%a, execsize=0x%" FMT_64 "x, kernel_resource=%s)",
              $self->id.c_str(), $self->version.c_str(), $self->path.c_str(),
              $self->executable.c_str(), $self->deps.size(),
              $self->iokit_classes.size(), uuid.c_str(),
              $self->kinfo_ea, $self->loadaddr, $self->execsize,
              $self->kernel_resource ? "true" : "false");
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
    uuid = property(__getUuid)
    """_PrelinkInterfaceUUID; all-zero when the bundle carries none"""
  }
}

//-------------------------------------------------------------------------
%extend kcu_symbol_match_t
{
  qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("kcu_symbol_match_t(symbol=\"%.*s\", ea=%a, kext=%08X)",
              int($self->symbol.size()), $self->symbol.data(),
              $self->ea, $self->kext.packed);
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

%template(kcu_symbol_match_vec_t) qvector<kcu_symbol_match_t>;

//-------------------------------------------------------------------------
%extend kcu_string_match_t
{
  qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("kcu_string_match_t(ea=%a, kext=%08X, file_offset=%" FMT_64 "X, context=\"%s\")",
              $self->ea, $self->kext.packed, $self->file_offset,
              $self->context.c_str());
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

%template(kcu_string_match_vec_t) qvector<kcu_string_match_t>;

//-------------------------------------------------------------------------
%extend kcu_address_info_t
{
  qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("kcu_address_info_t(region=%s, kext=%08X, kc=%s, file_offset=0x%" FMT_64 "x)",
              qstring().sprnt("kcu_region_info_t(start=%a, size=0x%" FMT_64 "x, type=%s, segname=\"%s\", sectname=\"%s\")",
                              $self->region.start, $self->region.size,
                              kcu_region_type_name($self->region.type),
                              $self->region.segname.c_str(),
                              $self->region.sectname.c_str()).c_str(),
              $self->kext.packed, kc_type_name($self->kc), $self->file_offset);
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend kcu_extref_t
{
  qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("kcu_extref_t(ea=%a, kc=%s, offset=0x%" FMT_64 "x)",
              $self->ea, kc_type_name($self->kc), $self->offset);
    return tmp;
  }
  %pythoncode {
    __repr__ = __str__
  }
}

%template(kcu_extref_vec_t) qvector<kcu_extref_t>;

//-------------------------------------------------------------------------
// kcu_region_info_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) kcu_region_info_vec_t *out (kcu_region_info_vec_t temp)
{
  // %typemap(in,numinputs=0) kcu_region_info_vec_t *out (kcu_region_info_vec_t temp)
  $1 = &temp;
}
%typemap(argout) kcu_region_info_vec_t *out
{
  // %typemap(argout) kcu_region_info_vec_t *out
  Py_XDECREF($result);
  auto *inst = new kcu_region_info_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) kcu_region_info_vec_t *out
{
  // %typemap(freearg) kcu_region_info_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

// `vout` is the same, minus the `result` check: the calls that fill a vout
// return void, so there is no C++ return value to consult.
%apply kcu_region_info_vec_t *out { kcu_region_info_vec_t *vout };
%typemap(argout) kcu_region_info_vec_t *vout
{
  // %typemap(argout) kcu_region_info_vec_t *vout
  Py_XDECREF($result);
  auto *inst = new kcu_region_info_vec_t();
  inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}

//-------------------------------------------------------------------------
// kcu_symbol_match_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) kcu_symbol_match_vec_t *out (kcu_symbol_match_vec_t temp)
{
  // %typemap(in,numinputs=0) kcu_symbol_match_vec_t *out (kcu_symbol_match_vec_t temp)
  $1 = &temp;
}
%typemap(argout) kcu_symbol_match_vec_t *out
{
  // %typemap(argout) kcu_symbol_match_vec_t *out
  Py_XDECREF($result);
  auto *inst = new kcu_symbol_match_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) kcu_symbol_match_vec_t *out
{
  // %typemap(freearg) kcu_symbol_match_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// kcu_string_match_vec_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) kcu_string_match_vec_t *out (kcu_string_match_vec_t temp)
{
  // %typemap(in,numinputs=0) kcu_string_match_vec_t *out (kcu_string_match_vec_t temp)
  $1 = &temp;
}
%typemap(argout) kcu_string_match_vec_t *out
{
  // %typemap(argout) kcu_string_match_vec_t *out
  Py_XDECREF($result);
  auto *inst = new kcu_string_match_vec_t();
  if ( result )
    inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) kcu_string_match_vec_t *out
{
  // %typemap(freearg) kcu_string_match_vec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// kcu_linked_kc_info_vec_t *vout
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) kcu_linked_kc_info_vec_t *vout (kcu_linked_kc_info_vec_t temp)
{
  // %typemap(in,numinputs=0) kcu_linked_kc_info_vec_t *vout (kcu_linked_kc_info_vec_t temp)
  $1 = &temp;
}
%typemap(argout) kcu_linked_kc_info_vec_t *vout
{
  // %typemap(argout) kcu_linked_kc_info_vec_t *vout
  Py_XDECREF($result);
  auto *inst = new kcu_linked_kc_info_vec_t();
  inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) kcu_linked_kc_info_vec_t *vout
{
  // %typemap(freearg) kcu_linked_kc_info_vec_t *vout
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// kcu_extref_vec_t *vout
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) kcu_extref_vec_t *vout (kcu_extref_vec_t temp)
{
  // %typemap(in,numinputs=0) kcu_extref_vec_t *vout (kcu_extref_vec_t temp)
  $1 = &temp;
}
%typemap(argout) kcu_extref_vec_t *vout
{
  // %typemap(argout) kcu_extref_vec_t *vout
  Py_XDECREF($result);
  auto *inst = new kcu_extref_vec_t();
  inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) kcu_extref_vec_t *vout
{
  // %typemap(freearg) kcu_extref_vec_t *vout
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// get_regions() takes the subset to fetch as a sizevec_t, but the call that
// produces one -- get_kext_region_indexes() -- hands Python a plain list.
// This accepts either (and None, as a null pointer, for "every region").
%numbers_list_to_values_vec(sizevec_t, SWIGTYPE_p_qvectorT_size_t_t, PyW_PySeqToSizeVec);

//-------------------------------------------------------------------------
// load_kexts() takes a kext_coords_vec_t, but a caller naturally reaches for
// a list. Accept any Python sequence of kext_coords_t, as well as an actual
// kext_coords_vec_t.
// load_kexts() is overloaded (the flags argument has a default), so the
// dispatcher decides which one to call before any `in` typemap runs. Without
// this it only ever recognizes a kext_coords_vec_t and rejects a sequence.
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) const kext_coords_vec_t &
{
  // %typemap(typecheck) const kext_coords_vec_t &
  void *vp = nullptr;
  $1 = (SWIG_IsOK(SWIG_ConvertPtr($input, &vp, $descriptor(qvector<kext_coords_t> *), 0))
        && vp != nullptr)
     || PySequence_Check($input);
}

%typemap(in) const kext_coords_vec_t & (kext_coords_vec_t temp)
{
  // %typemap(in) const kext_coords_vec_t &
  void *argp = nullptr;
  if ( SWIG_IsOK(SWIG_ConvertPtr($input, &argp, $descriptor(qvector<kext_coords_t> *), 0))
    && argp != nullptr )
  {
    $1 = (kext_coords_vec_t *) argp;
  }
  else
  {
    Py_ssize_t n = PySequence_Check($input) ? PySequence_Size($input) : -1;
    bool ok = n >= 0;
    for ( Py_ssize_t i = 0; i < n && ok; ++i )
    {
      void *ep = nullptr;
      PyObject *item = PySequence_GetItem($input, i); // new reference
      ok = item != nullptr
        && SWIG_IsOK(SWIG_ConvertPtr(item, &ep, $descriptor(kext_coords_t *), 0))
        && ep != nullptr;
      if ( ok )
        temp.push_back(*(kext_coords_t *) ep);
      Py_XDECREF(item);
    }
    if ( !ok )
    {
      PyErr_SetString(PyExc_TypeError, "expected a sequence of kext_coords_t");
      return nullptr;
    }
    $1 = &temp;
  }
}

%include <kcu_minimal.h>
%include <kcu.h>

// BADKEXT is a function-call macro, which SWIG drops; without this the name
// a repr prints is one no script can import. Must come after %include <kcu.h>:
// %pythoncode is emitted where it appears, and kext_coords_t is not defined
// in the generated module until the include above has been processed.
%pythoncode %{
BADKEXT = kext_coords_t()
%}
