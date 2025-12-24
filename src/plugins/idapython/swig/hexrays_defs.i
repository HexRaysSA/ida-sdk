%{
#include <hexrays.hpp>
%}

//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays_defs.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
// Copyright (C) 2013 ESET
//
// Integrated into IDAPython project by the IDAPython Team <idapython@googlegroups.com>
//---------------------------------------------------------------------

#ifdef __NT__
%include <windows.i>
#endif

// Reused definitions
//-------------------------------------------------------------------------
%define %define_hexrays_lifecycle_object(TypeName)
%feature("ref") TypeName
{
  hexrays_register_python_clearable_instance($this, hxclr_##TypeName);
}
%feature("unref") TypeName
{
  hexrays_deregister_python_clearable_instance($this);
  delete $this;
}
%extend TypeName {
  void _register() { hexrays_register_python_clearable_instance($self, hxclr_##TypeName); }
  void _deregister() { hexrays_deregister_python_clearable_instance($self); }
}
%enddef

//-------------------------------------------------------------------------
%define %monitored_lifecycle_object_t(TypeName)
%extend TypeName {

    int __dbg_get_registered_kind() const
    {
      return hexrays_is_registered_python_clearable_instance(self);
    }

    PyObject *_obj_id() const { return PyLong_FromSize_t(size_t(self)); }

    %pythoncode {
      obj_id = property(_obj_id)

      def _ensure_cond(self, ok, cond_str):
          if not ok:
              raise Exception("Condition \"%s\" not verified" % cond_str)
          return True

      def _ensure_no_obj(self, o, attr, attr_is_acquired):
          if attr_is_acquired and o is not None:
              raise Exception("%s already owns attribute \"%s\" (%s); cannot be modified" % (self, attr, o))
          return True

      def _ensure_ownership_transferrable(self, v):
          if not v.thisown:
              raise Exception("%s is already owned, and cannot be reused" % v)

      def _acquire_ownership(self, v, acquire):
          if acquire and (v is not None) and not isinstance(v, ida_idaapi.integer_types):
              self._ensure_ownership_transferrable(v)
              v.thisown = False
              dereg = getattr(v, "_deregister", None)
              if dereg:
                  dereg()
          return True

      def _maybe_disown_and_deregister(self):
          if self.thisown:
              self.thisown = False
              self._deregister()

      def _own_and_register(self):
          assert(not self.thisown)
          self.thisown = True
          self._register()

      def replace_by(self, o):
          assert(isinstance(o, (cexpr_t, cinsn_t)))
          o._maybe_disown_and_deregister()
          self._replace_by(o)

      def _meminfo(self):
          cpp = self.__dbg_get_meminfo()
          rkind = self.__dbg_get_registered_kind()
          rkind_str = [
                  "(not owned)",
                  "cfuncptr_t",
                  "cinsn_t",
                  "cexpr_t",
                  "cblock_t",
                  "mba_t",
                  "mop_t",
                  "minsn_t",
                  "optinsn_t",
                  "optblock_t",
                  "valrng_t",
                  "udc_filter_t"][rkind]
          return "%s [thisown=%s, owned by IDAPython as=%s]" % (
                  cpp,
                  self.thisown,
                  rkind_str)
      meminfo = property(_meminfo)
    }
};
%enddef

%define %define_node_property_accessors(TNAME, PNAME, PTYPE)
  %extend TNAME {
    PTYPE _get_##PNAME() const { return $self->PNAME; }
    void _set_##PNAME(PTYPE _v) { $self->PNAME = _v; }
  }
%enddef

%define %define_node_cstring_property_accessors(TNAME, PNAME)
  %extend TNAME {
    const char *_get_##PNAME() const { return $self->PNAME; }
    void _set_##PNAME(const char *_v)
    {
      if ( $self->PNAME != nullptr )
      {
        ::qfree($self->PNAME);
        $self->PNAME = nullptr;
      }
      $self->PNAME = ::qstrdup(_v);
    }
  }
%enddef

%define %define_node_obj_property(TNAME, COND, PNAME, DEFVAL, ACQUIRE)
  %extend TNAME {
    %pythoncode {
      @property
      def PNAME(self):
          return self._get_##PNAME() if COND else DEFVAL

      @PNAME.setter
      def PNAME(self, value):
          return (
              self._ensure_cond(COND, #COND)
              and self._ensure_no_obj(self._get_##PNAME(), #PNAME, ACQUIRE)
              and self._acquire_ownership(value, ACQUIRE)
              and self._set_##PNAME(value)
          )
    }
  }
%enddef

%define %define_node_scalar_property(TNAME, COND, PNAME, DEFVAL)
  %extend TNAME {
    %pythoncode {
      @property
      def PNAME(self):
          return self._get_##PNAME() if COND else DEFVAL

      @PNAME.setter
      def PNAME(self, value):
          return self._ensure_cond(COND, #COND) and self._set_##PNAME(value)
    }
  }
%enddef

// ------------------------------
%define %override_node_obj_property(TNAME, COND, PNAME, PTYPE, DEFVAL, ACQUIRE)
  %define_node_property_accessors(TNAME, PNAME, PTYPE);
  %define_node_obj_property(TNAME, COND, PNAME, DEFVAL, ACQUIRE);
  %ignore TNAME::PNAME;
%enddef

%define %override_node_scalar_property(TNAME, COND, PNAME, PTYPE, DEFVAL)
  %define_node_property_accessors(TNAME, PNAME, PTYPE);
  %define_node_scalar_property(TNAME, COND, PNAME, DEFVAL);
  %ignore TNAME::PNAME;
%enddef

%define %override_node_cstring_property(TNAME, COND, PNAME)
  %define_node_cstring_property_accessors(TNAME, PNAME);
  %define_node_obj_property(TNAME, COND, PNAME, None, False);
  %ignore TNAME::PNAME;
%enddef

%typemap(check) const tinfo_t *type {
  // %typemap(check) const tinfo_t *type
}

%typemap(check) ctype_t cexpr_op {
  // %typemap(check) ctype_t cexpr_op
  if ( $1 < cot_empty || $1 > cot_last )
    SWIG_exception_fail(SWIG_ValueError, "invalid op " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%fragment("cvt_cfunc_t", "header")
{
  int cvt_cfunc_t(cfunc_t **out, PyObject *obj)
  {
    cfunc_t *cfunc = 0;
    int res = SWIG_ConvertPtr(obj, (void **) &cfunc, SWIGTYPE_p_cfunc_t, 0 | 0);
    if ( SWIG_IsOK(res) )
    {
      *out = cfunc;
    }
    else
    {
      cfuncptr_t *cfuncptr = 0;
      res = SWIG_ConvertPtr(obj, (void **) &cfuncptr, SWIGTYPE_p_qrefcnt_tT_cfunc_t_t, 0 | 0);
      if ( SWIG_IsOK(res) )
        *out = *cfuncptr;
    }
    return res;
  }
}


%typemap(typecheck, fragment="cvt_cfunc_t", precedence=SWIG_TYPECHECK_POINTER) cfunc_t * {
  // %typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) cfunc_t *
  cfunc_t *cfunc = nullptr;
  const int res$argnum = cvt_cfunc_t(&cfunc, $input);
  _v = SWIG_CheckState(res$argnum);
}

%typemap(in, fragment="cvt_cfunc_t") cfunc_t * {
  // %typemap(in, fragment="cvt_cfunc_t") cfunc_t *
  int res$argnum = cvt_cfunc_t(&$1, $input);
  if ( !SWIG_IsOK(res$argnum) )
    SWIG_exception_fail(SWIG_ArgError(res$argnum), "in method '$symname', argument $argnum of type $1_type");
}

%typemap(check) citem_t *self
{
  if ( $1 == INS_EPILOG )
    SWIG_exception_fail(SWIG_ValueError, "invalid INS_EPILOG " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(check) cinsn_t *self
{
  if ( $1 == INS_EPILOG )
    SWIG_exception_fail(SWIG_ValueError, "invalid INS_EPILOG " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(directorin) (const char *format, ...)
{
  // %typemap(directorin) (const char *format, ...)
  // AFAICT we should only ever be called from C++, so we can assume
  // 'format' is followed with actual parameters, should it require them.
  qstring $input_buf;
  va_list $input_va;
  va_start($input_va, format);
  $input_buf.vsprnt(format, $input_va);
  va_end($input_va);
  $input = SWIG_Python_str_FromChar($input_buf.c_str());
}


%typemap(in,numinputs=0) (mop_t **other) (mop_t *tmp_op)
{
  // %typemap(in,numinputs=0) (mop_t **other)
  $1 = &tmp_op;
}
%typemap(argout) (mop_t **other)
{
  // %typemap(argout) (mop_t **other)
  $result = Py_BuildValue(
          "(OO)",
          $result,
          SWIG_NewPointerObj(SWIG_as_voidptr(result != nullptr ? *$1 : nullptr), SWIGTYPE_p_mop_t, 0 | 0));
}


//-------------------------------------------------------------------------
%typemap(out) cfuncptr_t {}
%typemap(ret) cfuncptr_t
{
  // ret cfuncptr_t
  cfuncptr_t *ni = new cfuncptr_t($1);
  hexrays_register_python_clearable_instance(ni, hxclr_cfuncptr);
  $result = SWIG_NewPointerObj(ni, $&1_descriptor, SWIG_POINTER_OWN | 0);
}


%typemap(out) cfuncptr_t *{}
%typemap(ret) cfuncptr_t *
{
  // ret cfuncptr_t*
  cfuncptr_t *ni = new cfuncptr_t(*($1));
  hexrays_register_python_clearable_instance(ni, hxclr_cfuncptr);
  $result = SWIG_NewPointerObj(ni, $1_descriptor, SWIG_POINTER_OWN | 0);
}

// End of reused definitions

%ignore file_printer_t;

%ignore mba_ranges_t::range_contains;

%ignore qstring_printer_t::qstring_printer_t(const cfunc_t *, qstring &, bool);
%ignore qstring_printer_t::~qstring_printer_t();

%extend qstring_printer_t {

   qstring_printer_t(const cfunc_t *f, bool tags);
   ~qstring_printer_t();

   qstring get_s() {
     return $self->s;
   }

   %pythoncode {
     s = property(lambda self: self.get_s())
   }
};

// Provide trivial qmap facade so basic operations are available.
template<class key_type, class mapped_type> class qmap {
public:
    mapped_type& at(const key_type& _Keyval);
    size_t size() const;
};

%template(hexwarns_t) qvector<hexwarn_t>;
%template(user_numforms_t) qmap<operand_locator_t, number_format_t>;

%{
//-------------------------------------------------------------------------
qstring_printer_t *new_qstring_printer_t(const cfunc_t *f, bool tags)
{
  return new qstring_printer_t(f, * (new qstring()), tags);
}

//-------------------------------------------------------------------------
void delete_qstring_printer_t(qstring_printer_t *qs)
{
  delete &(qs->s);
  delete qs;
}
%}

%rename (debug_hexrays_ctree) py_debug_hexrays_ctree;
%inline %{
void py_debug_hexrays_ctree(int level, const char *msg)
{
  debug_hexrays_ctree(level, msg);
}
%}

%include "hexrays_defs.hpp";

%pythoncode %{
import ida_idaapi
ida_idaapi._listify_types(hexwarns_t)
%}
