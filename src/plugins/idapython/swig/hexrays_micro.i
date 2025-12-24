%{
#include <hexrays.hpp>
%}
%pythoncode %{
from ida_hexrays_defs import MMAT_GLBOPT3
%}
%import "hexrays_defs.i";

//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays_micro.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
// Copyright (C) 2013 ESET
//
// Integrated into IDAPython project by the IDAPython Team <idapython@googlegroups.com>
//---------------------------------------------------------------------

#ifdef __NT__
%include <windows.i>
#endif

%define %method_sets_type_and_gains_ownership_of_regular_object_argument(TYPE, METHOD, ARGNAME)
%feature("pythonprepend") TYPE::METHOD %{
    o = ARGNAME
    self._ensure_cond(self.t == mop_z, "self.t == mop_z")
%}
%feature("pythonappend") TYPE::METHOD %{
    self._acquire_ownership(o, True)
%}
%enddef

%ignore lvar_t::is_promoted_arg;
%ignore lvar_t::lvar_t;
%ignore lvar_t::is_partialy_typed;
%ignore lvar_t::set_partialy_typed;
%ignore lvar_t::clr_partialy_typed;
%ignore lvar_t::force_lvar_type;
%ignore vd_interr_t::vd_interr_t(ea_t, const qstring &);

%ignore bitset_t::print;
%ignore bitset_t::extract;
%ignore bitset_t::fill_gaps;
%template(array_of_bitsets) qvector<bitset_t>;

%ignore ivl_t::print;
%ignore ivl_t::allmem;

%ignore mlist_t::has_allmem;

%ignore mba_t::mba_t;
%ignore mba_t::reserved;
%ignore mba_t::vdump_mba;
%ignore mba_t::idaloc2vd(const argloc_t &, int, sval_t);
%ignore mba_t::idaloc2vd(const mba_t *, const argloc_t &, int);
%ignore mba_t::range_contains;
%ignore mba_t::get_stkvar;
%ignore mba_t::arg(int) const;
%ignore mba_t::get_mblock(uint) const;

%feature("nodirector") codegen_t;
%ignore codegen_t::reserved;

%feature("nodirector") simple_graph_t;
%ignore simple_graph_t::simple_graph_t;
%ignore simple_graph_t::~simple_graph_t;
%ignore simple_graph_t::ignore_edge;
%ignore simple_graph_t::iterator;
%ignore hexrays_node_visitor_t;

%feature("nodirector") mbl_graph_t;
%ignore mbl_graph_t::mbl_graph_t;
%ignore mbl_graph_t::~mbl_graph_t;
%ignore mbl_graph_t::ignore_edge;

%define_hexrays_lifecycle_object(minsn_t);
%ignore minsn_t::find_ins_op(const mop_t **, mcode_t) const;
%ignore minsn_t::find_ins_op(const mop_t **) const;
%ignore minsn_t::find_num_op(const mop_t **) const;
%ignore minsn_t::find_opcode(mcode_t) const;
%ignore minsn_t::set_combined;


%ignore mop_t::is_constant(uint64 *) const;
%ignore mop_t::is_constant() const;
%ignore mop_t::get_insn(mcode_t) const;

%define_hexrays_lifecycle_object(mop_t);
%ignore mop_t::_make_strlit(qstring *);
%template(mopvec_t) qvector<mop_t>;
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_cases, _cases)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_callinfo, fi)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_pair, _pair)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, _make_insn, ins)
%method_sets_type_and_gains_ownership_of_regular_object_argument(mop_t, make_insn, ins)

%template(mcallargs_t) qvector<mcallarg_t>;

%ignore block_chains_t::get_reg_chain(mreg_t, int);
%ignore block_chains_t::get_stk_chain(sval_t, int);
%ignore block_chains_t::get_chain(voff_t &, int);
%ignore block_chains_t::get_chain(chain_t &);
%uncomparable_elements_qvector(block_chains_t, block_chains_vec_t);

%ignore mblock_t::mblock_t;

%ignore mblock_t::find_first_use(mlist_t *, const minsn_t *, const minsn_t *, maymust_t=MAY_ACCESS) const;
%ignore mblock_t::find_first_use(mlist_t *, const minsn_t *, const minsn_t *) const;
%ignore mblock_t::find_redefinition(const mlist_t &, const minsn_t *, const minsn_t *, maymust_t) const;
%ignore mblock_t::find_redefinition(const mlist_t &, const minsn_t *, const minsn_t *) const;
%ignore mblock_t::reserved;
%ignore mblock_t::vdump_block;

// Note: we cannot use %delobject here, as that would disown
// the block itself, not the instruction.
%feature("pythonappend") mblock_t::insert_into_block %{
    mn = nm
    mn._maybe_disown_and_deregister()
%}
// Note: we could be using %newobject here, but for the sake of
// symmetry with 'insert_into_block', let's go with "pythonappend".
%feature("pythonprepend") mblock_t::remove_from_block %{
    mn = m
%}
%feature("pythonappend") mblock_t::remove_from_block %{
    if mn:
      mn._own_and_register()
%}
%feature("nodirector") mblock_t;
%extend mblock_t {
   %pythoncode {
     def preds(self):
         """
         Iterates the list of predecessor blocks
         """
         for ser in self.predset:
             yield self.mba.get_mblock(ser)

     def succs(self):
         """
         Iterates the list of successor blocks
         """
         for ser in self.succset:
             yield self.mba.get_mblock(ser)
   }
};

%extend mba_t {
   %pythoncode {
     """
     Deprecated. Please do not use.
     """
     idb_node = property(lambda self: self.deprecated_idb_node)
   }
};

%ignore op_parent_info_t::really_alloc;

%ignore getf_reginsn(const minsn_t *);
%ignore getb_reginsn(const minsn_t *);

%ignore lvar_t::dstr;
%ignore lvar_t::type() const;

%ignore lvar_locator_t::dstr;
%ignore lvar_locator_t::get_scattered() const;

%ignore fnumber_t::dstr;
%ignore range_item_iterator_t;
%ignore mba_item_iterator_t;
%ignore range_chunk_iterator_t;

%ignore hexrays_failure_t::hexrays_failure_t(merror_t,ea_t);

%newobject gen_microcode;
%define_hexrays_lifecycle_object(mba_t);
%const_void_pointer_and_size(uchar, bytes, nbytes);
%const_void_pointer_and_size(void, bytes, _size);

%define_hexrays_lifecycle_object(valrng_t);
%apply uint64 *OUTPUT { uvlr_t *v };    // valrng_t::cvt_to_single_value
%apply uint64 *OUTPUT { uvlr_t *val };  // valrng_t::cvt_to_cmp
%apply int    *OUTPUT { cmpop_t *cmp }; // valrng_t::cvt_to_cmp

%define %def_opt_handler(TypeName, Install, Remove, Hxclr)
%ignore Install;
%ignore Remove;
%extend TypeName {
    void install()
    {
        hexrays_register_python_clearable_instance($self, Hxclr);
        Install($self);
    }
    bool remove()
    {
        hexrays_deregister_python_clearable_instance($self);
        return Remove($self);
    }
    ~TypeName()
    {
      hexrays_deregister_python_clearable_instance($self);
      Remove($self);
      delete $self;
    }
};
%enddef
%def_opt_handler(optinsn_t, install_optinsn_handler, remove_optinsn_handler, hxclr_optinsn_t)
%def_opt_handler(optblock_t, install_optblock_handler, remove_optblock_handler, hxclr_optblock_t)
%def_opt_handler(udc_filter_t, install_udc_filter, remove_udc_filter, hxclr_udc_filter_t)

// udc_filter_t::init() will create a tinfo_t from the user-provided
// declaration. We must also ensure the instance is registered
// even if only init() is called (but install() isn't)
%extend udc_filter_t {
    bool init(const char *decl)
    {
        const bool ok = $self->init(decl);
        if ( ok )
            hexrays_register_python_clearable_instance($self, hxclr_udc_filter_t);
        return ok;
    }
};

%apply uchar { char ignore_micro };
%feature("nodirector") udc_filter_t::apply;

%rename(dereference_uint16) operator uint16*;
%rename(dereference_const_uint16) operator const uint16*;

//-------------------------------------------------------------------------
//                               mop_t
//-------------------------------------------------------------------------

%define %override_mop_t_obj_property(MOP_OP, PNAME, PTYPE)
  %override_node_obj_property(mop_t, self.t == MOP_OP, PNAME, PTYPE, None, True);
%enddef

%define %override_mop_t_scalar_property(MOP_OP, PNAME, PTYPE)
  %override_node_scalar_property(mop_t, self.t == MOP_OP, PNAME, PTYPE, None);
%enddef

%define %override_mop_t_cstring_property(MOP_OP, PNAME)
  %override_node_cstring_property(mop_t, self.t == MOP_OP, PNAME);
%enddef

%extend mop_t {

    mopt_t _get_t() const { return self->t; }
    void _set_t(mopt_t v) { self->t = v; }
    %pythoncode {
      def _ensure_no_t(self):
          if self.t not in [mop_z]:
              raise Exception("%s has type %s; cannot be modified" % (self, self.t))
          return True
      t = property(
              _get_t,
              lambda self, v: self._ensure_no_t() and self._set_t(v))
    }

    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (t=%d)", self, self->t);
      return s;
    }
}

%monitored_lifecycle_object_t(mop_t);

%override_mop_t_obj_property(mop_n, nnn, mnumber_t *);
%override_mop_t_obj_property(mop_d, d, minsn_t *);
%override_mop_t_obj_property(mop_S, s, stkvar_ref_t *);
%override_mop_t_obj_property(mop_f, f, mcallinfo_t *);
%override_mop_t_obj_property(mop_l, l, lvar_ref_t *);
%override_mop_t_obj_property(mop_a, a, mop_addr_t *);
%override_mop_t_obj_property(mop_c, c, mcases_t *);
%override_mop_t_obj_property(mop_fn, fpc, fnumber_t *);
%override_mop_t_obj_property(mop_p, pair, mop_pair_t *);
%override_mop_t_obj_property(mop_sc, scif, scif_t *);
%override_mop_t_obj_property(mop_sc, scif, scif_t *);
%override_mop_t_scalar_property(mop_r, r, mreg_t);
%override_mop_t_scalar_property(mop_v, g, ea_t);
%override_mop_t_scalar_property(mop_b, b, int);
%override_mop_t_cstring_property(mop_str, cstr);
%override_mop_t_cstring_property(mop_h, helper);

//-------------------------------------------------------------------------
//                               minsn_t
//-------------------------------------------------------------------------
%extend minsn_t {
    qstring __dbg_get_meminfo() const
    {
      qstring s;
      s.sprnt("%p (opcode=%d)", self, self->opcode);
      return s;
    }
}
%monitored_lifecycle_object_t(minsn_t);

//-------------------------------------------------------------------------
//                               bitset_t
//-------------------------------------------------------------------------
%extend bitset_t {

    int itv(const_iterator it) { qnotused(self); return *it; }

    %pythoncode {
     __len__ = count
     def __iter__(self):
         it = self.begin()
         for i in range(self.count()):
             yield self.itv(it)
             self.inc(it)
    }
};


// hexrays_micro templates
%template(lvar_mapping_t) qmap<lvar_locator_t, lvar_locator_t>;
%template(qvector_lvar_t) qvector<lvar_t>;
%template(lvar_saved_infos_t) qvector<lvar_saved_info_t>;

%{
//-------------------------------------------------------------------------
static void install_udc_filter(udc_filter_t *instance)
{
  install_microcode_filter(instance, true);
}

//-------------------------------------------------------------------------
static bool remove_udc_filter(udc_filter_t *instance)
{
  return install_microcode_filter(instance, false);
}
%}

#pragma SWIG nowarn=503

%include "hexrays_micro.hpp";
%template(array_of_ivlsets) qvector<ivlset_t>;

%pythoncode %{
#<pycode(py_hexrays_micro)>
#</pycode(py_hexrays_micro)>
%}
