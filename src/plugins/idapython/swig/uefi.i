%{
#include <loader.hpp>
#include <uefi.h>
%}

%ignore uefi_req_t;
%ignore uefi_svc_req_t;

// Python uses the helpers returning vectors (get_modules(), ...)
%ignore uefi_module_visitor_t;
%ignore uefi_protocol_visitor_t;
%ignore uefi_interface_visitor_t;
%ignore uefi_member_impl_visitor_t;
%ignore uefi_svc_t::for_each_module;
%ignore uefi_svc_t::for_each_protocol;
%ignore uefi_svc_t::for_each_interface;
%ignore uefi_svc_t::for_each_member_impl;

%feature("nodirector") uefi_svc_t;

//-------------------------------------------------------------------------
// uefi_guid_t: a fixed-size C array would otherwise reach a script as an
// opaque pointer
%ignore uefi_guid_t::data4;
%template(uefi_guid_data4_array) wrapped_array_t<uchar,8>;

// const uefi_guid_t &guid: a uefi_guid_t, or its text
%typemap(in) const uefi_guid_t &guid (uefi_guid_t temp, void *argp = nullptr)
{
  // %typemap(in) const uefi_guid_t &guid
  if ( PyUnicode_Check($input) )
  {
    qstring text;
    if ( !PyUnicode_as_qstring(&text, $input) || !temp.from_str(text.c_str()) )
      SWIG_exception_fail(
              SWIG_ValueError,
              "invalid GUID " "in method '" "$symname" "', argument " "$argnum"" of type 'uefi_guid_t'");
    $1 = &temp;
  }
  else
  {
    int res = SWIG_ConvertPtr($input, &argp, $descriptor(uefi_guid_t *), 0);
    if ( !SWIG_IsOK(res) || argp == nullptr )
      SWIG_exception_fail(
              SWIG_ArgError(res),
              "in method '" "$symname" "', argument " "$argnum"" of type 'uefi_guid_t or str'");
    $1 = (uefi_guid_t *)argp;
  }
}
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) const uefi_guid_t &guid
{
  // %typemap(typecheck) const uefi_guid_t &guid
  $1 = PyUnicode_Check($input)
    || SWIG_IsOK(SWIG_ConvertPtr($input, nullptr, $descriptor(uefi_guid_t *), SWIG_POINTER_NO_NULL));
}

%extend uefi_guid_t
{
  uefi_guid_t() { return new uefi_guid_t(); }
  uefi_guid_t(const uefi_guid_t &guid) { return new uefi_guid_t(guid); }

  wrapped_array_t<uchar,8> __get_data4__()
  {
    return wrapped_array_t<uchar,8>($self->data4);
  }

  // defining __eq__ would otherwise set __hash__ to None, and a GUID is
  // the natural key of a per-protocol dict
  uint32 __hash__() const
  {
    uint32 h = $self->data1 ^ (uint32($self->data2) << 16) ^ $self->data3;
    for ( size_t i = 0; i < sizeof($self->data4); ++i )
      h = h * 31 + $self->data4[i];
    return h;
  }

  qstring __str__() const { return $self->to_str(); }

  qstring __repr__() const
  {
    qstring tmp;
    tmp.sprnt("ida_uefi.uefi_guid_t(\"%s\")", $self->to_str().c_str());
    return tmp;
  }

  %pythoncode {
    data4 = property(__get_data4__)
    """the last 8 bytes of the GUID"""

    def to_uuid(self):
        """Convert the GUID to a uuid.UUID."""
        import uuid
        return uuid.UUID(self.to_str())
  }
}

//-------------------------------------------------------------------------
%template(uefi_module_vec_t) qvector<uefi_module_t>;
%template(uefi_protocol_vec_t) qvector<uefi_protocol_t>;
%template(uefi_interface_vec_t) qvector<uefi_interface_t>;
%template(uefi_member_impl_vec_t) qvector<uefi_member_impl_t>;

//-------------------------------------------------------------------------
// VECTYPE *out, filled by a void function: return the vector
%define %uefi_vector_output(VECTYPE)
%typemap(in,numinputs=0) VECTYPE *out (VECTYPE temp)
{
  // %typemap(in,numinputs=0) VECTYPE *out (VECTYPE temp)
  $1 = &temp;
}
%typemap(argout) VECTYPE *out
{
  // %typemap(argout) VECTYPE *out
  Py_XDECREF($result);
  auto *inst = new VECTYPE();
  inst->swap(*$1);
  $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
}
%typemap(freearg) VECTYPE *out
{
  // %typemap(freearg) VECTYPE *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}
%enddef

%uefi_vector_output(uefi_module_vec_t);
%uefi_vector_output(uefi_protocol_vec_t);
%uefi_vector_output(uefi_interface_vec_t);
%uefi_vector_output(uefi_member_impl_vec_t);

//-------------------------------------------------------------------------
// TYPE *out, filled by a bool function: the result, or None
%define %uefi_object_output(TYPE)
%typemap(in,numinputs=0) TYPE *out (TYPE temp)
{
  // %typemap(in,numinputs=0) TYPE *out (TYPE temp)
  $1 = &temp;
}
%typemap(argout) TYPE *out
{
  // %typemap(argout) TYPE *out
  Py_XDECREF($result);
  if ( result )
  {
    auto *inst = new TYPE(*$1);
    $result = SWIG_NewPointerObj(inst, $1_descriptor, SWIG_POINTER_OWN);
  }
  else
  {
    Py_INCREF(Py_None);
    $result = Py_None;
  }
}
%typemap(freearg) TYPE *out
{
  // %typemap(freearg) TYPE *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}
%enddef

%uefi_object_output(uefi_module_t);
%uefi_object_output(uefi_guid_t);

//-------------------------------------------------------------------------
// eavec_t *out, filled by a void function: a list of addresses
%typemap(in,numinputs=0) eavec_t *out (eavec_t temp)
{
  // %typemap(in,numinputs=0) eavec_t *out (eavec_t temp)
  $1 = &temp;
}
%typemap(argout) eavec_t *out
{
  // %typemap(argout) eavec_t *out
  Py_XDECREF($result);
  $result = PyList_New($1->size());
  for ( size_t i = 0; i < $1->size(); ++i )
    PyList_SetItem($result, i, Py_BuildValue(PY_BV_EA, bvea_t($1->at(i))));
}
%typemap(freearg) eavec_t *out
{
  // %typemap(freearg) eavec_t *out
  // Nothing. We certainly do not want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
%extend uefi_module_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_uefi.uefi_module_t(name=\"%s\", guid=\"%s\", kind=\"%s\", "
              "start=%a, end=%a, entry=%a, ffs_type=%d, flags=0x%x)",
              $self->name.c_str(),
              $self->guid.to_str().c_str(),
              $self->kind.c_str(),
              $self->start,
              $self->end,
              $self->entry,
              $self->ffs_type,
              $self->flags);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend uefi_protocol_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_uefi.uefi_protocol_t(call_ea=%a, iface=%a, kind=%d, "
              "guid_state=%d, guid=\"%s\", name=\"%s\", service=\"%s\", "
              "module=%d)",
              $self->call_ea,
              $self->iface,
              int($self->kind),
              int($self->guid_state),
              $self->guid.to_str().c_str(),
              $self->name.c_str(),
              $self->service.c_str(),
              $self->module);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend uefi_interface_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_uefi.uefi_interface_t(ea=%a, struct_name=\"%s\", "
              "guid=\"%s\", module=%d, flags=0x%x)",
              $self->ea,
              $self->struct_name.c_str(),
              $self->guid.to_str().c_str(),
              $self->module,
              $self->flags);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

//-------------------------------------------------------------------------
%extend uefi_member_impl_t
{
  inline qstring __str__() const
  {
    qstring tmp;
    tmp.sprnt("ida_uefi.uefi_member_impl_t(func=%a, iface=%a, module=%d)",
              $self->func,
              $self->iface,
              $self->module);
    return tmp;
  }

  %pythoncode {
    __repr__ = __str__
  }
}

%include <uefi.h>
