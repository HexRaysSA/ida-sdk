%{
#include <hexrays.hpp>
%}
%import "hexrays_defs.i";

%ignore var_ref_t::getv;

%force_declare_SWiG_type(TPopupMenu);
// In py_hexrays*_hooks.hpp we're trying to use SWiG internals
// SWIGTYPE_p_mcallinfo_t. This is defined in hexrays_micro.cpp wrapper
// And this is not automatically visible with  %import "hexrays_micro.i
// unless the real mcallinfo_t * pointer is used somewhere
// This creates dummy function declaration that uses mcallinfo_t* as arguments
%force_declare_SWiG_type(mcallinfo_t);

//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays_ctree.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
// Copyright (C) 2013 ESET
//
// Integrated into IDAPython project by the IDAPython Team <idapython@googlegroups.com>
//---------------------------------------------------------------------

#ifdef __NT__
%include <windows.i>
#endif

%ignore vdui_t::vdui_t;
%ignore cblock_t::find;

%ignore citem_t::op;
%ignore citem_t::find_parent_of(const citem_t *) const;

%ignore cfunc_t::cfunc_t;
%ignore cfunc_t::sv;         // lazy member. Use get_pseudocode() instead
%ignore cfunc_t::boundaries; // lazy member. Use get_boundaries() instead
%ignore cfunc_t::eamap;      // lazy member. Use get_eamap() instead
%ignore cfunc_t::reserved;
%ignore ctree_item_t::verify;
%ignore ccases_t::find_value;
%ignore ccases_t::print;
%ignore ccase_t::set_insn;
%ignore ccase_t::print;
%ignore carglist_t::print;
%ignore cblock_t::remove_gotos;
%ignore casm_t::genasm;
%ignore cblock_t::use_curly_braces;
%ignore casm_t::print;
%ignore cgoto_t::print;
%ignore ctry_t::print;
%ignore ccatch_t::print;

%ignore cexpr_t::is_aliasable;
%ignore cexpr_t::like_boolean;
%ignore cexpr_t::contains_expr;
%ignore cexpr_t::contains_expr;
%ignore cexpr_t::cexpr_t(mba_t *mba, const lvar_t &v);
%ignore cexpr_t::is_type_partial;
%ignore cexpr_t::set_type_partial;
%ignore cexpr_t::is_value_used;
%ignore cexpr_t::find_num_op() const;
%ignore cexpr_t::find_op(ctype_t) const;
%ignore cexpr_t::theother(const cexpr_t *) const;

%rename (_replace_by) cinsn_t::replace_by;
%rename (_replace_by) cexpr_t::replace_by;
%ignore vcall_helper;
%ignore vcreate_helper;

%const_void_pointer_and_size(uchar, bytes, nbytes);

%apply qstrvec_t *out { qstrvec_t *warnings };

%hooks_director_handle_qstrvec_t_output(collect_warnings, warnings);

// The following must:
//  - transfer ownership to the result object, if the argument object had it
//    That's because we don't know when one of those functions create
//    a new object under the hood
%rename (_ll_lnot) lnot;
%rename (_ll_make_ref) make_ref;
%rename (_ll_dereference) dereference;

// The following must:
//  - mark new object as being owned
//  - disown the 'args' object passed as parameter
%rename (_ll_call_helper) call_helper;

// The following must:
//  - mark new object as being owned
%rename (_ll_new_block) new_block;
%rename (_ll_make_num) make_num;
%rename (_ll_create_helper) create_helper;

%delobject create_cfunc;

%extend cfunc_t {
    %immutable argidx;

   PyObject *find_item_coords(const citem_t *item)
   {
     int px = 0;
     int py = 0;
     if ( $self->find_item_coords(item, &px, &py) )
       return Py_BuildValue("(ii)", px, py);
     else
       return Py_BuildValue("(OO)", Py_None, Py_None);
   }

   qstring __str__() const {
     qstring qs;
     qstring_printer_t p($self, qs, 0);
     $self->print_func(p);
     return qs;
   }

   %pythoncode {
       __repr__ = __str__
   }
};

//-------------------------------------------------------------------------
//                             citem_t
//---------------------------------------------------------------------
%extend citem_t {
    // define these two struct members that can be used for casting.
    cinsn_t *cinsn const;
    cexpr_t *cexpr const;

    ctype_t _get_op() const { return self->op; }
    void _set_op(ctype_t v) { self->op = v; }
    %pythoncode {
      def _ensure_no_op(self):
          if self.op not in [cot_empty, cit_empty]:
              raise Exception("%s has op %s; cannot be modified" % (self, self.op))
          return True
      op = property(
              _get_op,
              lambda self, v: self._ensure_no_op() and self._set_op(v))
    }

    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (op=%s)", self, get_ctype_name(self->op));
      return s;
    }
};
%monitored_lifecycle_object_t(citem_t);

%{
cinsn_t *citem_t_cinsn_get(citem_t *item) { return (cinsn_t *) item; }
cexpr_t *citem_t_cexpr_get(citem_t *item) { return (cexpr_t *) item; }
%}

//---------------------------------------------------------------------
//                               cinsn_t
//---------------------------------------------------------------------
%define_hexrays_lifecycle_object(cinsn_t);
%extend cinsn_t {
  static bool insn_is_epilog(const cinsn_t *insn) { return insn == INS_EPILOG; }

  %pythoncode {
    def is_epilog(self):
        return cinsn_t.insn_is_epilog(self)
  }
};


%define %override_cinsn_t_obj_property(CIT_OP, PNAME, PTYPE)
  %override_node_obj_property(cinsn_t, self.op == CIT_OP, PNAME, PTYPE, None, True);
%enddef
%override_cinsn_t_obj_property(cit_block,  cblock,  cblock_t *);
%override_cinsn_t_obj_property(cit_expr,   cexpr,   cexpr_t *);
%override_cinsn_t_obj_property(cit_if,     cif,     cif_t *);
%override_cinsn_t_obj_property(cit_for,    cfor,    cfor_t *);
%override_cinsn_t_obj_property(cit_while,  cwhile,  cwhile_t *);
%override_cinsn_t_obj_property(cit_do,     cdo,     cdo_t *);
%override_cinsn_t_obj_property(cit_switch, cswitch, cswitch_t *);
%override_cinsn_t_obj_property(cit_return, creturn, creturn_t *);
%override_cinsn_t_obj_property(cit_goto,   cgoto,   cgoto_t *);
%override_cinsn_t_obj_property(cit_asm,    casm,    casm_t *);

//-------------------------------------------------------------------------
//                             cexpr_t
//-------------------------------------------------------------------------
%define_hexrays_lifecycle_object(cexpr_t);
%extend cexpr_t {
  var_ref_t* get_v() { if ( self->op == cot_var ) { return &self->v; } else { return nullptr; } }
  void set_v(const var_ref_t *v) { if ( self->op == cot_var ) { self->v = *v; } }
  %pythoncode {
    v = property(lambda self: self.get_v(), lambda self, v: self.set_v(v))
  }
};
%ignore cexpr_t::v;

%define %override_cexpr_t_obj_property(COND, PNAME, PTYPE, DEFVAL, ACQUIRE)
  %override_node_obj_property(cexpr_t, COND, PNAME, PTYPE, DEFVAL, ACQUIRE);
%enddef
%define %override_cexpr_t_scalar_property(COND, PNAME, PTYPE, DEFVAL)
  %override_node_scalar_property(cexpr_t, COND, PNAME, PTYPE, DEFVAL);
%enddef
%define %override_cexpr_t_cstring_property(COND, PNAME)
  %override_node_cstring_property(cexpr_t, COND, PNAME);
%enddef

%override_cexpr_t_obj_property(self.op == cot_num, n, cnumber_t *, None, True);
%override_cexpr_t_obj_property(self.op == cot_fnum, fpc, fnumber_t *, None, True);
%override_cexpr_t_obj_property(op_uses_x(self.op), x, cexpr_t *, None, True);
%override_cexpr_t_obj_property(op_uses_y(self.op), y, cexpr_t *, None, True);
%override_cexpr_t_obj_property(op_uses_z(self.op), z, cexpr_t *, None, True);
%override_cexpr_t_obj_property(self.op == cot_call, a, carglist_t *, None, True);
%override_cexpr_t_obj_property(self.op == cot_insn, insn, cinsn_t *, None, True);
%override_cexpr_t_scalar_property(self.op == cot_memptr or self.op == cot_memref, m, int, 0);
%override_cexpr_t_scalar_property(self.op == cot_ptr or self.op == cot_memptr, ptrsize, int, 0);
%override_cexpr_t_scalar_property(self.op == cot_obj, obj_ea, ea_t, ida_idaapi.BADADDR);
%override_cexpr_t_scalar_property(True, refwidth, int, 0);
%override_cexpr_t_cstring_property(self.op == cot_helper, helper);
%override_cexpr_t_cstring_property(self.op == cot_str, string);

%feature("pythonprepend") cexpr_t::cexpr_t %{
    for arg in args[1:]: # skip copy constructor's arg
        if isinstance(arg, cexpr_t):
            self._ensure_ownership_transferrable(arg)
%}
%feature("pythonappend") cexpr_t::cexpr_t %{
    for arg in args[1:]: # skip copy constructor's arg
        if isinstance(arg, cexpr_t):
            self._acquire_ownership(arg, True)
%}

//-------------------------------------------------------------------------
//                             ctree_item_t
//-------------------------------------------------------------------------
// FIXME: I can't enable setters, because the ctree_item_t doesn't
// have a cleanup() function that would greatly help getting rid of
// objects that were referenced by SWiG proxies, but which have been
// de-owned (see cexpr_t above.)
// #define CTREE_ITEM_MEMBER_REF(type, name)                             \
//   type get_##name() const { return self->##name; }                    \
//   void set_##name(type _v) { self->##name = _v; }                     \
//   %pythoncode {                                                       \
//     name = property(lambda self: self.get_##name(), lambda self, v: self.set_##name(v)) \
//   }
//
// #define CTREE_CONDITIONAL_ITEM_MEMBER_REF(type, name, wanted_citype)  \
//   type get_##name() const { if ( self->citype == wanted_citype ) { return self->##name; } else { return nullptr; } } \
//   void set_##name(type _v) { if ( self->citype == wanted_citype ) { self->##name = _v; } } \
//   %pythoncode {                                                       \
//     name = property(lambda self: self.get_##name(), lambda self, v: self.set_##name(v)) \
//   }

#define CTREE_ITEM_MEMBER_REF(type, name)                               \
  type _get_##name() const { return self->##name; }                     \
  %pythoncode {                                                         \
    name = property(lambda self: self._get_##name())                    \
      }

#define CTREE_CONDITIONAL_ITEM_MEMBER_REF(type, name, wanted_citype)    \
  type _get_##name() const                                              \
  {                                                                     \
    if ( self->citype == wanted_citype )                                \
      return self->##name;                                              \
    else                                                                \
      return nullptr;                                                   \
  }                                                                     \
  %pythoncode {                                                         \
    name = property(lambda self: self._get_##name())                    \
      }


%extend ctree_item_t {
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(citem_t *, it, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cexpr_t*, e, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cinsn_t*, i, VDI_EXPR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(lvar_t*, l, VDI_LVAR);
  CTREE_CONDITIONAL_ITEM_MEMBER_REF(cfunc_t*, f, VDI_FUNC);
  treeloc_t *loc const;
};

%ignore ctree_item_t::loc;

%{
treeloc_t *ctree_item_t_loc_get(ctree_item_t *item) { return item->citype == VDI_TAIL ? &item->loc : nullptr; }
%}

#undef CTREE_CONDITIONAL_ITEM_MEMBER_REF
#undef CTREE_ITEM_MEMBER_REF

//-------------------------------------------------------------------------
/* for qvector instanciations where the class is a pointer (cinsn_t, citem_t) we need
   to fix the at() return type, otherwise swig mistakenly thinks it is "cinsn_t *&" and nonsense ensues. */
%extend qvector< cinsn_t *> {
  cinsn_t *at(size_t n) { return self->at(n); }
};
%extend qvector< citem_t *> {
  citem_t *at(size_t n) { return self->at(n); }
};

// ignore future declarations of at() for these classes
/* %ignore qvector< cinsn_t *>::at(size_t) const; */
/* %ignore qvector< cinsn_t *>::at(size_t); */
/* %ignore qvector< citem_t *>::at(size_t) const; */
/* %ignore qvector< citem_t *>::at(size_t); */
%ignore qvector< citem_t *>::grow;
%ignore qvector< cinsn_t *>::grow;

// hexrays_ctree templates
%template(ctree_items_t) qvector<citem_t *>;
%template(user_labels_t) qmap<int, qstring>;
%template(user_unions_t) qmap<ea_t, intvec_t>;
%template(user_cmts_t) qmap<treeloc_t, citem_cmt_t>;
%template(user_iflags_t) qmap<citem_locator_t, int32>;
%template(cinsnptrvec_t) qvector<cinsn_t *>;
%template(eamap_t) qmap<ea_t, cinsnptrvec_t>;
%template(boundaries_t) qmap<cinsn_t *, rangeset_t>;

// WARNING: The order here is VERY important:
//  1) The '%extend' directive. Note that
//    - the template name must be used, not the typedef (i.e., not 'cfuncptr_t')
//    - to override the destructor, the destructor must have the template parameters.
//  2) The '%ignore' directive.
//    - Again, using the template name, but this time
//    - not qualifying the destructor with template parameters
//  3) The '%template' directive, that will indeed instantiate
//     the template for swig.
%{ void hexrays_deregister_python_clearable_instance(void *ptr); %}
%extend qrefcnt_t<cfunc_t> {
  // The typemap above will take care of registering newly-constructed cfuncptr_t
  // instances. However, there's no such thing as a destructor typemap.
  // Therefore, we need to do the grunt work of de-registering ourselves.
  // Note: The 'void' here is important: Without it, SWIG considers it to
  //       be a different destructor (which, of course, makes a ton of sense.)
  ~qrefcnt_t<cfunc_t>(void)
  {
    hexrays_deregister_python_clearable_instance($self);
    delete $self;
  }
}
%ignore qrefcnt_t<cfunc_t>::~qrefcnt_t(void);
%template(cfuncptr_t) qrefcnt_t<cfunc_t>;
%template(qvector_history_t) qvector<history_item_t>;
%template(history_t) qstack<history_item_t>;
typedef int iterator_word;

%qlist_template(cinsn_list_t, cinsn_t);

%template(qvector_carg_t) qvector<carg_t>;
%template(qvector_ccase_t) qvector<ccase_t>;
%template(qvector_catchexprs_t) qvector<catchexpr_t>;
%template(qvector_ccatchvec_t) qvector<ccatch_t>;
%uncomparable_elements_qvector(cblock_pos_t, cblock_posvec_t);

%template(ui_stroff_ops_t) qvector<ui_stroff_op_t>;

%extend cblock_t {
  cblock_t(void)
  {
    cblock_t *cb = new cblock_t();
    hexrays_register_python_clearable_instance(cb, hxclr_cblock_t);
    return cb;
  }

  ~cblock_t(void)
  {
    hexrays_deregister_python_clearable_instance($self);
    delete $self;
  }

  void _deregister() { hexrays_deregister_python_clearable_instance($self); }
}
%ignore cblock_t::cblock_t;

%extend citem_cmt_t {
    const char *c_str() const { return self->c_str(); }

    const char *__str__() const
    {
      return $self->c_str();
    }
};

void qswap(cinsn_t &a, cinsn_t &b);

%{
//<code(py_hexrays_ctree)>
//</code(py_hexrays_ctree)>
%}

%ignore install_hexrays_callback;
%ignore remove_hexrays_callback;

%ignore decompile_snippet;

%ignore decompile_func(func_t *,hexrays_failure_t *);
%ignore decompile_func(func_t *);

%feature("pythonappend") decompile_func %{
  if val.__deref__() is None:
      val = None
%}

%ignore cexpr_t::get_1num_op(const cexpr_t **, const cexpr_t **) const;
%ignore cexpr_t::find_ptr_or_array(bool) const;

#pragma SWIG nowarn=503

// http://www.swig.org/Doc2.0/SWIGDocumentation.html#Python_nn36
// http://www.swig.org/Doc2.0/SWIGDocumentation.html#Customization_exception_special_variables
%define %possible_director_exc(Method)
%exception Method {
  try {
    $action
  } catch ( Swig::DirectorException & ) {
    // A DirectorException might be raised in deeper layers.
    SWIG_fail;
  }
}
%enddef
%possible_director_exc(ctree_visitor_t::apply_to)
%possible_director_exc(ctree_visitor_t::apply_to_exprs)

%define_Hooks_class(Hexrays);
%ignore Hexrays_Hooks::hooked;

%inline %{
//<inline(py_hexrays_ctree_hooks)>
//</inline(py_hexrays_ctree_hooks)>
%}

%{
//<code(py_hexrays_ctree_hooks)>
//</code(py_hexrays_ctree_hooks)>
%}

%include "hexrays_ctree.hpp";


%pythoncode %{
#<pycode(py_hexrays_ctree)>
#</pycode(py_hexrays_ctree)>
%}

//-------------------------------------------------------------------------
%init %{
//<init(py_hexrays_ctree)>
//</init(py_hexrays_ctree)>
%}
