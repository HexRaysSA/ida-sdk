/*!
 *      Hex-Rays Decompiler project
 *      Copyright (c) 1990-2025 Hex-Rays
 *      ALL RIGHTS RESERVED.
 */

/*!
 *  \file hexrays.hpp
 *  \brief There are 2 representations of the binary code in the decompiler:
 *
 *        - microcode: processor instructions are translated into it and then
 *                     the decompiler optimizes and transforms it
 *        - ctree:     ctree is built from the optimized microcode and represents
 *                     AST-like tree with C statements and expressions. It can
 *                     be printed as C code.
 *
 *      Microcode is represented by the following classes:
 *       - mba_t keeps general info about the decompiled code and
 *                     array of basic blocks. usually mba_t is named 'mba'
 *       - mblock_t    a basic block. includes list of instructions
 *       - minsn_t     an instruction. contains 3 operands: left, right, and
 *                     destination
 *       - mop_t       an operand. depending on its type may hold various info
 *                     like a number, register, stack variable, etc.
 *       - mlist_t     list of memory or register locations; can hold vast areas
 *                     of memory and multiple registers. this class is used
 *                     very extensively in the decompiler. it may represent
 *                     list of locations accessed by an instruction or even
 *                     an entire basic block. it is also used as argument of
 *                     many functions. for example, there is a function
 *                     that searches for an instruction that refers to a mlist_t.
 *
 *      See https://hex-rays.com/blog/microcode-in-pictures for a few pictures.
 *
 *      Ctree is represented by:
 *       - cfunc_t     keeps general info about the decompiled code, including a
 *                     pointer to mba_t. deleting cfunc_t will delete
 *                     mba_t too (however, decompiler returns cfuncptr_t,
 *                     which is a reference counting object and deletes the
 *                     underlying function as soon as all references to it go
 *                     out of scope). cfunc_t has 'body', which represents the
 *                     decompiled function body as cinsn_t.
 *       - cinsn_t     a C statement. can be a compound statement or any other
 *                     legal C statements (like if, for, while, return,
 *                     expression-statement, etc). depending on the statement
 *                     type has pointers to additional info. for example, the
 *                     'if' statement has poiner to cif_t, which holds the
 *                     'if' condition, 'then' branch, and optionally 'else'
 *                     branch. Please note that despite of the name cinsn_t
 *                     we say "statements", not "instructions". For us
 *                     instructions are part of microcode, not ctree.
 *       - cexpr_t     a C expression. is used as part of a C statement, when
 *                     necessary. cexpr_t has 'type' field, which keeps the
 *                     expression type.
 *       - citem_t     a base class for cinsn_t and cexpr_t, holds common info
 *                     like the address, label, and opcode.
 *       - cnumber_t   a constant 64-bit number. in addition to its value also
 *                     holds information how to represent it: decimal, hex, or
 *                     as a symbolic constant (enum member). please note that
 *                     numbers are represented by another class (mnumber_t)
 *                     in microcode.

 *      See https://hex-rays.com/blog/hex-rays-decompiler-primer
 *      for more pictures and more details.
 *
 *      Both microcode and ctree use the following class:
 *       - lvar_t      a local variable. may represent a stack or register
 *                     variable. a variable has a name, type, location, etc.
 *                     the list of variables is stored in mba->vars.
 *       - lvar_locator_t holds a variable location (vdloc_t) and its definition
 *                     address.
 *       - vdloc_t     describes a variable location, like a register number,
 *                     a stack offset, or, in complex cases, can be a mix of
 *                     register and stack locations. very similar to argloc_t,
 *                     which is used in ida. the differences between argloc_t
 *                     and vdloc_t are:
 *                       - vdloc_t never uses ARGLOC_REG2
 *                       - vdloc_t uses micro register numbers instead of
 *                         processor register numbers
 *                       - the stack offsets are never negative in vdloc_t, while
 *                         in argloc_t there can be negative offsets
 *
 *      The above are the most important classes in this header file. There are
 *      many auxiliary classes, please see their definitions in the header file.
 *
 *      See also the description of \ref vmpage.
 */

#pragma once
#define __HEXRAYS_HPP

#include <hexrays_defs.hpp>
#include <hexrays_ctree.hpp>
#include <hexrays_micro.hpp>
#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:4265) // virtual functions without virtual destructor
#endif

//--------------------------------------------------------------------------
// PUBLIC HEX-RAYS API
//--------------------------------------------------------------------------

/// Hex-Rays decompiler dispatcher.
/// All interaction with the decompiler is carried out by the intermediary of this dispatcher.
typedef void *hexdsp_t(int code, ...);

/// API call numbers
enum hexcall_t
{
  hx_user_numforms_begin,
  hx_user_numforms_end,
  hx_user_numforms_next,
  hx_user_numforms_prev,
  hx_user_numforms_first,
  hx_user_numforms_second,
  hx_user_numforms_find,
  hx_user_numforms_insert,
  hx_user_numforms_erase,
  hx_user_numforms_clear,
  hx_user_numforms_size,
  hx_user_numforms_free,
  hx_user_numforms_new,
  hx_lvar_mapping_begin,
  hx_lvar_mapping_end,
  hx_lvar_mapping_next,
  hx_lvar_mapping_prev,
  hx_lvar_mapping_first,
  hx_lvar_mapping_second,
  hx_lvar_mapping_find,
  hx_lvar_mapping_insert,
  hx_lvar_mapping_erase,
  hx_lvar_mapping_clear,
  hx_lvar_mapping_size,
  hx_lvar_mapping_free,
  hx_lvar_mapping_new,
  hx_udcall_map_begin,
  hx_udcall_map_end,
  hx_udcall_map_next,
  hx_udcall_map_prev,
  hx_udcall_map_first,
  hx_udcall_map_second,
  hx_udcall_map_find,
  hx_udcall_map_insert,
  hx_udcall_map_erase,
  hx_udcall_map_clear,
  hx_udcall_map_size,
  hx_udcall_map_free,
  hx_udcall_map_new,
  hx_user_cmts_begin,
  hx_user_cmts_end,
  hx_user_cmts_next,
  hx_user_cmts_prev,
  hx_user_cmts_first,
  hx_user_cmts_second,
  hx_user_cmts_find,
  hx_user_cmts_insert,
  hx_user_cmts_erase,
  hx_user_cmts_clear,
  hx_user_cmts_size,
  hx_user_cmts_free,
  hx_user_cmts_new,
  hx_user_iflags_begin,
  hx_user_iflags_end,
  hx_user_iflags_next,
  hx_user_iflags_prev,
  hx_user_iflags_first,
  hx_user_iflags_second,
  hx_user_iflags_find,
  hx_user_iflags_insert,
  hx_user_iflags_erase,
  hx_user_iflags_clear,
  hx_user_iflags_size,
  hx_user_iflags_free,
  hx_user_iflags_new,
  hx_user_unions_begin,
  hx_user_unions_end,
  hx_user_unions_next,
  hx_user_unions_prev,
  hx_user_unions_first,
  hx_user_unions_second,
  hx_user_unions_find,
  hx_user_unions_insert,
  hx_user_unions_erase,
  hx_user_unions_clear,
  hx_user_unions_size,
  hx_user_unions_free,
  hx_user_unions_new,
  hx_user_labels_begin,
  hx_user_labels_end,
  hx_user_labels_next,
  hx_user_labels_prev,
  hx_user_labels_first,
  hx_user_labels_second,
  hx_user_labels_find,
  hx_user_labels_insert,
  hx_user_labels_erase,
  hx_user_labels_clear,
  hx_user_labels_size,
  hx_user_labels_free,
  hx_user_labels_new,
  hx_eamap_begin,
  hx_eamap_end,
  hx_eamap_next,
  hx_eamap_prev,
  hx_eamap_first,
  hx_eamap_second,
  hx_eamap_find,
  hx_eamap_insert,
  hx_eamap_erase,
  hx_eamap_clear,
  hx_eamap_size,
  hx_eamap_free,
  hx_eamap_new,
  hx_boundaries_begin,
  hx_boundaries_end,
  hx_boundaries_next,
  hx_boundaries_prev,
  hx_boundaries_first,
  hx_boundaries_second,
  hx_boundaries_find,
  hx_boundaries_insert,
  hx_boundaries_erase,
  hx_boundaries_clear,
  hx_boundaries_size,
  hx_boundaries_free,
  hx_boundaries_new,
  hx_block_chains_begin,
  hx_block_chains_end,
  hx_block_chains_next,
  hx_block_chains_prev,
  hx_block_chains_get,
  hx_block_chains_find,
  hx_block_chains_insert,
  hx_block_chains_erase,
  hx_block_chains_clear,
  hx_block_chains_size,
  hx_block_chains_free,
  hx_block_chains_new,
  hx_hexrays_alloc,
  hx_hexrays_free,
  hx_valrng_t_clear,
  hx_valrng_t_copy,
  hx_valrng_t_assign,
  hx_valrng_t_compare,
  hx_valrng_t_set_eq,
  hx_valrng_t_set_cmp,
  hx_valrng_t_reduce_size,
  hx_valrng_t_intersect_with,
  hx_valrng_t_unite_with,
  hx_valrng_t_inverse,
  hx_valrng_t_has,
  hx_valrng_t_print,
  hx_valrng_t_dstr,
  hx_valrng_t_cvt_to_single_value,
  hx_valrng_t_cvt_to_cmp,
  hx_get_merror_desc,
  hx_must_mcode_close_block,
  hx_is_mcode_propagatable,
  hx_negate_mcode_relation,
  hx_swap_mcode_relation,
  hx_get_signed_mcode,
  hx_get_unsigned_mcode,
  hx_mcode_modifies_d,
  hx_operand_locator_t_compare,
  hx_vd_printer_t_print,
  hx_file_printer_t_print,
  hx_qstring_printer_t_print,
  hx_dstr,
  hx_is_type_correct,
  hx_is_small_udt,
  hx_is_nonbool_type,
  hx_is_bool_type,
  hx_partial_type_num,
  hx_get_float_type,
  hx_get_int_type_by_width_and_sign,
  hx_get_unk_type,
  hx_dummy_ptrtype,
  hx_get_member_type,
  hx_make_pointer,
  hx_create_typedef,
  hx_get_type,
  hx_set_type,
  hx_vdloc_t_dstr,
  hx_vdloc_t_compare,
  hx_vdloc_t_is_aliasable,
  hx_print_vdloc,
  hx_arglocs_overlap,
  hx_lvar_locator_t_compare,
  hx_lvar_locator_t_dstr,
  hx_lvar_t_dstr,
  hx_lvar_t_is_promoted_arg,
  hx_lvar_t_accepts_type,
  hx_lvar_t_set_lvar_type,
  hx_lvar_t_set_width,
  hx_lvar_t_append_list,
  hx_lvar_t_append_list_,
  hx_lvars_t_find_stkvar,
  hx_lvars_t_find,
  hx_lvars_t_find_lvar,
  hx_restore_user_lvar_settings,
  hx_save_user_lvar_settings,
  hx_modify_user_lvars,
  hx_modify_user_lvar_info,
  hx_locate_lvar,
  hx_restore_user_defined_calls,
  hx_save_user_defined_calls,
  hx_parse_user_call,
  hx_convert_to_user_call,
  hx_install_microcode_filter,
  hx_udc_filter_t_cleanup,
  hx_udc_filter_t_init,
  hx_udc_filter_t_apply,
  hx_bitset_t_bitset_t,
  hx_bitset_t_copy,
  hx_bitset_t_add,
  hx_bitset_t_add_,
  hx_bitset_t_add__,
  hx_bitset_t_sub,
  hx_bitset_t_sub_,
  hx_bitset_t_sub__,
  hx_bitset_t_cut_at,
  hx_bitset_t_shift_down,
  hx_bitset_t_has,
  hx_bitset_t_has_all,
  hx_bitset_t_has_any,
  hx_bitset_t_dstr,
  hx_bitset_t_empty,
  hx_bitset_t_count,
  hx_bitset_t_count_,
  hx_bitset_t_last,
  hx_bitset_t_fill_with_ones,
  hx_bitset_t_fill_gaps,
  hx_bitset_t_has_common,
  hx_bitset_t_intersect,
  hx_bitset_t_is_subset_of,
  hx_bitset_t_compare,
  hx_bitset_t_goup,
  hx_ivl_t_dstr,
  hx_ivl_t_compare,
  hx_ivlset_t_add,
  hx_ivlset_t_add_,
  hx_ivlset_t_addmasked,
  hx_ivlset_t_sub,
  hx_ivlset_t_sub_,
  hx_ivlset_t_has_common,
  hx_ivlset_t_print,
  hx_ivlset_t_dstr,
  hx_ivlset_t_count,
  hx_ivlset_t_has_common_,
  hx_ivlset_t_contains,
  hx_ivlset_t_includes,
  hx_ivlset_t_intersect,
  hx_ivlset_t_compare,
  hx_rlist_t_print,
  hx_rlist_t_dstr,
  hx_mlist_t_addmem,
  hx_mlist_t_print,
  hx_mlist_t_dstr,
  hx_mlist_t_compare,
  hx_get_temp_regs,
  hx_is_kreg,
  hx_reg2mreg,
  hx_mreg2reg,
  hx_get_mreg_name,
  hx_install_optinsn_handler,
  hx_remove_optinsn_handler,
  hx_install_optblock_handler,
  hx_remove_optblock_handler,
  hx_simple_graph_t_compute_dominators,
  hx_simple_graph_t_compute_immediate_dominators,
  hx_simple_graph_t_depth_first_preorder,
  hx_simple_graph_t_depth_first_postorder,
  hx_simple_graph_t_goup,
  hx_mutable_graph_t_resize,
  hx_mutable_graph_t_goup,
  hx_mutable_graph_t_del_edge,
  hx_lvar_ref_t_compare,
  hx_lvar_ref_t_var,
  hx_stkvar_ref_t_compare,
  hx_stkvar_ref_t_get_stkvar,
  hx_fnumber_t_print,
  hx_fnumber_t_dstr,
  hx_mop_t_copy,
  hx_mop_t_assign,
  hx_mop_t_swap,
  hx_mop_t_erase,
  hx_mop_t_print,
  hx_mop_t_dstr,
  hx_mop_t_create_from_mlist,
  hx_mop_t_create_from_ivlset,
  hx_mop_t_create_from_vdloc,
  hx_mop_t_create_from_scattered_vdloc,
  hx_mop_t_create_from_insn,
  hx_mop_t_make_number,
  hx_mop_t_make_fpnum,
  hx_mop_t__make_gvar,
  hx_mop_t_make_gvar,
  hx_mop_t_make_reg_pair,
  hx_mop_t_make_helper,
  hx_mop_t_is_bit_reg,
  hx_mop_t_may_use_aliased_memory,
  hx_mop_t_is01,
  hx_mop_t_is_sign_extended_from,
  hx_mop_t_is_zero_extended_from,
  hx_mop_t_equal_mops,
  hx_mop_t_lexcompare,
  hx_mop_t_for_all_ops,
  hx_mop_t_for_all_scattered_submops,
  hx_mop_t_is_constant,
  hx_mop_t_get_stkoff,
  hx_mop_t_make_low_half,
  hx_mop_t_make_high_half,
  hx_mop_t_make_first_half,
  hx_mop_t_make_second_half,
  hx_mop_t_shift_mop,
  hx_mop_t_change_size,
  hx_mop_t_preserve_side_effects,
  hx_mop_t_apply_ld_mcode,
  hx_mcallarg_t_print,
  hx_mcallarg_t_dstr,
  hx_mcallarg_t_set_regarg,
  hx_mcallinfo_t_lexcompare,
  hx_mcallinfo_t_set_type,
  hx_mcallinfo_t_get_type,
  hx_mcallinfo_t_print,
  hx_mcallinfo_t_dstr,
  hx_mcases_t_compare,
  hx_mcases_t_print,
  hx_mcases_t_dstr,
  hx_vivl_t_extend_to_cover,
  hx_vivl_t_intersect,
  hx_vivl_t_print,
  hx_vivl_t_dstr,
  hx_chain_t_print,
  hx_chain_t_dstr,
  hx_chain_t_append_list,
  hx_chain_t_append_list_,
  hx_block_chains_t_get_chain,
  hx_block_chains_t_print,
  hx_block_chains_t_dstr,
  hx_graph_chains_t_for_all_chains,
  hx_graph_chains_t_release,
  hx_minsn_t_init,
  hx_minsn_t_copy,
  hx_minsn_t_set_combined,
  hx_minsn_t_swap,
  hx_minsn_t_print,
  hx_minsn_t_dstr,
  hx_minsn_t_setaddr,
  hx_minsn_t_optimize_subtree,
  hx_minsn_t_for_all_ops,
  hx_minsn_t_for_all_insns,
  hx_minsn_t__make_nop,
  hx_minsn_t_equal_insns,
  hx_minsn_t_lexcompare,
  hx_minsn_t_is_noret_call,
  hx_minsn_t_is_helper,
  hx_minsn_t_find_call,
  hx_minsn_t_has_side_effects,
  hx_minsn_t_find_opcode,
  hx_minsn_t_find_ins_op,
  hx_minsn_t_find_num_op,
  hx_minsn_t_modifies_d,
  hx_minsn_t_is_between,
  hx_minsn_t_may_use_aliased_memory,
  hx_minsn_t_serialize,
  hx_minsn_t_deserialize,
  hx_getf_reginsn,
  hx_getb_reginsn,
  hx_mblock_t_init,
  hx_mblock_t_print,
  hx_mblock_t_dump,
  hx_mblock_t_vdump_block,
  hx_mblock_t_insert_into_block,
  hx_mblock_t_remove_from_block,
  hx_mblock_t_for_all_insns,
  hx_mblock_t_for_all_ops,
  hx_mblock_t_for_all_uses,
  hx_mblock_t_optimize_insn,
  hx_mblock_t_optimize_block,
  hx_mblock_t_build_lists,
  hx_mblock_t_optimize_useless_jump,
  hx_mblock_t_append_use_list,
  hx_mblock_t_append_def_list,
  hx_mblock_t_build_use_list,
  hx_mblock_t_build_def_list,
  hx_mblock_t_find_first_use,
  hx_mblock_t_find_redefinition,
  hx_mblock_t_is_rhs_redefined,
  hx_mblock_t_find_access,
  hx_mblock_t_get_valranges,
  hx_mblock_t_get_valranges_,
  hx_mblock_t_get_reginsn_qty,
  hx_mba_ranges_t_range_contains,
  hx_mba_t_stkoff_vd2ida,
  hx_mba_t_stkoff_ida2vd,
  hx_mba_t_idaloc2vd,
  hx_mba_t_idaloc2vd_,
  hx_mba_t_vd2idaloc,
  hx_mba_t_vd2idaloc_,
  hx_mba_t_term,
  hx_mba_t_get_curfunc,
  hx_mba_t_set_maturity,
  hx_mba_t_optimize_local,
  hx_mba_t_build_graph,
  hx_mba_t_get_graph,
  hx_mba_t_analyze_calls,
  hx_mba_t_optimize_global,
  hx_mba_t_alloc_lvars,
  hx_mba_t_dump,
  hx_mba_t_vdump_mba,
  hx_mba_t_print,
  hx_mba_t_verify,
  hx_mba_t_mark_chains_dirty,
  hx_mba_t_insert_block,
  hx_mba_t_remove_block,
  hx_mba_t_copy_block,
  hx_mba_t_remove_empty_and_unreachable_blocks,
  hx_mba_t_merge_blocks,
  hx_mba_t_for_all_ops,
  hx_mba_t_for_all_insns,
  hx_mba_t_for_all_topinsns,
  hx_mba_t_find_mop,
  hx_mba_t_create_helper_call,
  hx_mba_t_get_func_output_lists,
  hx_mba_t_arg,
  hx_mba_t_alloc_fict_ea,
  hx_mba_t_map_fict_ea,
  hx_mba_t_serialize,
  hx_mba_t_deserialize,
  hx_mba_t_save_snapshot,
  hx_mba_t_alloc_kreg,
  hx_mba_t_free_kreg,
  hx_mba_t_inline_func,
  hx_mba_t_locate_stkpnt,
  hx_mba_t_set_lvar_name,
  hx_mbl_graph_t_is_accessed_globally,
  hx_mbl_graph_t_get_ud,
  hx_mbl_graph_t_get_du,
  hx_cdg_insn_iterator_t_next,
  hx_codegen_t_clear,
  hx_codegen_t_emit,
  hx_codegen_t_emit_,
  hx_change_hexrays_config,
  hx_get_hexrays_version,
  hx_open_pseudocode,
  hx_close_pseudocode,
  hx_get_widget_vdui,
  hx_decompile_many,
  hx_hexrays_failure_t_desc,
  hx_send_database,
  hx_gco_info_t_append_to_list,
  hx_get_current_operand,
  hx_remitem,
  hx_negated_relation,
  hx_swapped_relation,
  hx_get_op_signness,
  hx_asgop,
  hx_asgop_revert,
  hx_cnumber_t_print,
  hx_cnumber_t_value,
  hx_cnumber_t_assign,
  hx_cnumber_t_compare,
  hx_var_ref_t_compare,
  hx_ctree_visitor_t_apply_to,
  hx_ctree_visitor_t_apply_to_exprs,
  hx_ctree_parentee_t_recalc_parent_types,
  hx_cfunc_parentee_t_calc_rvalue_type,
  hx_citem_locator_t_compare,
  hx_citem_t_contains_expr,
  hx_citem_t_contains_label,
  hx_citem_t_find_parent_of,
  hx_citem_t_find_closest_addr,
  hx_cexpr_t_assign,
  hx_cexpr_t_compare,
  hx_cexpr_t_replace_by,
  hx_cexpr_t_cleanup,
  hx_cexpr_t_put_number,
  hx_cexpr_t_print1,
  hx_cexpr_t_calc_type,
  hx_cexpr_t_equal_effect,
  hx_cexpr_t_is_child_of,
  hx_cexpr_t_contains_operator,
  hx_cexpr_t_get_high_nbit_bound,
  hx_cexpr_t_get_low_nbit_bound,
  hx_cexpr_t_requires_lvalue,
  hx_cexpr_t_has_side_effects,
  hx_cexpr_t_maybe_ptr,
  hx_cexpr_t_dstr,
  hx_cif_t_assign,
  hx_cif_t_compare,
  hx_cloop_t_assign,
  hx_cfor_t_compare,
  hx_cwhile_t_compare,
  hx_cdo_t_compare,
  hx_creturn_t_compare,
  hx_cthrow_t_compare,
  hx_cgoto_t_compare,
  hx_casm_t_compare,
  hx_cinsn_t_assign,
  hx_cinsn_t_compare,
  hx_cinsn_t_replace_by,
  hx_cinsn_t_cleanup,
  hx_cinsn_t_new_insn,
  hx_cinsn_t_create_if,
  hx_cinsn_t_print,
  hx_cinsn_t_print1,
  hx_cinsn_t_is_ordinary_flow,
  hx_cinsn_t_contains_insn,
  hx_cinsn_t_collect_free_breaks,
  hx_cinsn_t_collect_free_continues,
  hx_cinsn_t_dstr,
  hx_cblock_t_compare,
  hx_carglist_t_compare,
  hx_ccase_t_compare,
  hx_ccases_t_compare,
  hx_cswitch_t_compare,
  hx_ccatch_t_compare,
  hx_ctry_t_compare,
  hx_ctree_item_t_get_udm,
  hx_ctree_item_t_get_edm,
  hx_ctree_item_t_get_lvar,
  hx_ctree_item_t_get_ea,
  hx_ctree_item_t_get_label_num,
  hx_ctree_item_t_print,
  hx_ctree_item_t_dstr,
  hx_lnot,
  hx_new_block,
  hx_vcreate_helper,
  hx_vcall_helper,
  hx_make_num,
  hx_make_ref,
  hx_dereference,
  hx_save_user_labels,
  hx_save_user_cmts,
  hx_save_user_numforms,
  hx_save_user_iflags,
  hx_save_user_unions,
  hx_restore_user_labels,
  hx_restore_user_cmts,
  hx_restore_user_numforms,
  hx_restore_user_iflags,
  hx_restore_user_unions,
  hx_cfunc_t_build_c_tree,
  hx_cfunc_t_verify,
  hx_cfunc_t_print_dcl,
  hx_cfunc_t_print_func,
  hx_cfunc_t_get_func_type,
  hx_cfunc_t_get_lvars,
  hx_cfunc_t_get_stkoff_delta,
  hx_cfunc_t_find_label,
  hx_cfunc_t_remove_unused_labels,
  hx_cfunc_t_get_user_cmt,
  hx_cfunc_t_set_user_cmt,
  hx_cfunc_t_get_user_iflags,
  hx_cfunc_t_set_user_iflags,
  hx_cfunc_t_has_orphan_cmts,
  hx_cfunc_t_del_orphan_cmts,
  hx_cfunc_t_get_user_union_selection,
  hx_cfunc_t_set_user_union_selection,
  hx_cfunc_t_save_user_labels,
  hx_cfunc_t_save_user_cmts,
  hx_cfunc_t_save_user_numforms,
  hx_cfunc_t_save_user_iflags,
  hx_cfunc_t_save_user_unions,
  hx_cfunc_t_get_line_item,
  hx_cfunc_t_get_warnings,
  hx_cfunc_t_get_eamap,
  hx_cfunc_t_get_boundaries,
  hx_cfunc_t_get_pseudocode,
  hx_cfunc_t_refresh_func_ctext,
  hx_cfunc_t_gather_derefs,
  hx_cfunc_t_find_item_coords,
  hx_cfunc_t_cleanup,
  hx_close_hexrays_waitbox,
  hx_decompile,
  hx_gen_microcode,
  hx_create_cfunc,
  hx_mark_cfunc_dirty,
  hx_clear_cached_cfuncs,
  hx_has_cached_cfunc,
  hx_get_ctype_name,
  hx_create_field_name,
  hx_install_hexrays_callback,
  hx_remove_hexrays_callback,
  hx_vdui_t_set_locked,
  hx_vdui_t_refresh_view,
  hx_vdui_t_refresh_ctext,
  hx_vdui_t_switch_to,
  hx_vdui_t_get_number,
  hx_vdui_t_get_current_label,
  hx_vdui_t_clear,
  hx_vdui_t_refresh_cpos,
  hx_vdui_t_get_current_item,
  hx_vdui_t_ui_rename_lvar,
  hx_vdui_t_rename_lvar,
  hx_vdui_t_ui_set_call_type,
  hx_vdui_t_ui_set_lvar_type,
  hx_vdui_t_set_lvar_type,
  hx_vdui_t_set_noptr_lvar,
  hx_vdui_t_ui_edit_lvar_cmt,
  hx_vdui_t_set_lvar_cmt,
  hx_vdui_t_ui_map_lvar,
  hx_vdui_t_ui_unmap_lvar,
  hx_vdui_t_map_lvar,
  hx_vdui_t_set_udm_type,
  hx_vdui_t_rename_udm,
  hx_vdui_t_set_global_type,
  hx_vdui_t_rename_global,
  hx_vdui_t_rename_label,
  hx_vdui_t_jump_enter,
  hx_vdui_t_ctree_to_disasm,
  hx_vdui_t_calc_cmt_type,
  hx_vdui_t_edit_cmt,
  hx_vdui_t_edit_func_cmt,
  hx_vdui_t_del_orphan_cmts,
  hx_vdui_t_set_num_radix,
  hx_vdui_t_set_num_enum,
  hx_vdui_t_set_num_stroff,
  hx_vdui_t_invert_sign,
  hx_vdui_t_invert_bits,
  hx_vdui_t_collapse_item,
  hx_vdui_t_collapse_lvars,
  hx_vdui_t_split_item,
  hx_select_udt_by_offset,
  hx_catchexpr_t_compare,
  hx_mba_t_split_block,
  hx_mba_t_remove_blocks,
  hx_cfunc_t_recalc_item_addresses,
  hx_obsolete_int64_emulator_t_mop_value,
  hx_obsolete_int64_emulator_t_minsn_value,
  hx_int64_emulator_t__mop_value,
  hx_int64_emulator_t__minsn_value,
  hx_cfunc_t_serialize,
  hx_cfunc_t_deserialize,
  hx_mblock_t_verify_insn,
  hx_vdui_t_ui_noprop_lvar,
};

typedef size_t iterator_word;

//--------------------------------------------------------------------------
/// Check that your plugin is compatible with hex-rays decompiler.
/// This function must be called before calling any other decompiler function.
/// \param flags reserved, must be 0
/// \return true if the decompiler exists and is compatible with your plugin
inline bool init_hexrays_plugin(int flags=0)
{
  hexdsp_t *dummy;
  return callui(ui_broadcast, HEXRAYS_API_MAGIC, &dummy, flags).i == (HEXRAYS_API_MAGIC >> 32);
}

//--------------------------------------------------------------------------
/// Stop working with hex-rays decompiler.
inline void term_hexrays_plugin()
{
}


//-------------------------------------------------------------------------
struct user_numforms_iterator_t
{
  iterator_word x;
  bool operator==(const user_numforms_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_numforms_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline operand_locator_t const &user_numforms_first(user_numforms_iterator_t p)
{
  return *(operand_locator_t *)HEXDSP(hx_user_numforms_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline number_format_t &user_numforms_second(user_numforms_iterator_t p)
{
  return *(number_format_t *)HEXDSP(hx_user_numforms_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_numforms_t
inline user_numforms_iterator_t user_numforms_find(const user_numforms_t *map, const operand_locator_t &key)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (operand_locator_t, number_format_t) pair into user_numforms_t
inline user_numforms_iterator_t user_numforms_insert(user_numforms_t *map, const operand_locator_t &key, const number_format_t &val)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_numforms_t
inline user_numforms_iterator_t user_numforms_begin(const user_numforms_t *map)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_numforms_t
inline user_numforms_iterator_t user_numforms_end(const user_numforms_t *map)
{
  user_numforms_iterator_t p;
  HEXDSP(hx_user_numforms_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_numforms_iterator_t user_numforms_next(user_numforms_iterator_t p)
{
  HEXDSP(hx_user_numforms_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_numforms_iterator_t user_numforms_prev(user_numforms_iterator_t p)
{
  HEXDSP(hx_user_numforms_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_numforms_t
inline void user_numforms_erase(user_numforms_t *map, user_numforms_iterator_t p)
{
  HEXDSP(hx_user_numforms_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_numforms_t
inline void user_numforms_clear(user_numforms_t *map)
{
  HEXDSP(hx_user_numforms_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_numforms_t
inline size_t user_numforms_size(user_numforms_t *map)
{
  return (size_t)HEXDSP(hx_user_numforms_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_numforms_t instance
inline void user_numforms_free(user_numforms_t *map)
{
  HEXDSP(hx_user_numforms_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_numforms_t instance
inline user_numforms_t *user_numforms_new()
{
  return (user_numforms_t *)HEXDSP(hx_user_numforms_new);
}

//-------------------------------------------------------------------------
struct user_cmts_iterator_t
{
  iterator_word x;
  bool operator==(const user_cmts_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_cmts_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline treeloc_t const &user_cmts_first(user_cmts_iterator_t p)
{
  return *(treeloc_t *)HEXDSP(hx_user_cmts_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline citem_cmt_t &user_cmts_second(user_cmts_iterator_t p)
{
  return *(citem_cmt_t *)HEXDSP(hx_user_cmts_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_cmts_t
inline user_cmts_iterator_t user_cmts_find(const user_cmts_t *map, const treeloc_t &key)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (treeloc_t, citem_cmt_t) pair into user_cmts_t
inline user_cmts_iterator_t user_cmts_insert(user_cmts_t *map, const treeloc_t &key, const citem_cmt_t &val)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_cmts_t
inline user_cmts_iterator_t user_cmts_begin(const user_cmts_t *map)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_cmts_t
inline user_cmts_iterator_t user_cmts_end(const user_cmts_t *map)
{
  user_cmts_iterator_t p;
  HEXDSP(hx_user_cmts_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_cmts_iterator_t user_cmts_next(user_cmts_iterator_t p)
{
  HEXDSP(hx_user_cmts_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_cmts_iterator_t user_cmts_prev(user_cmts_iterator_t p)
{
  HEXDSP(hx_user_cmts_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_cmts_t
inline void user_cmts_erase(user_cmts_t *map, user_cmts_iterator_t p)
{
  HEXDSP(hx_user_cmts_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_cmts_t
inline void user_cmts_clear(user_cmts_t *map)
{
  HEXDSP(hx_user_cmts_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_cmts_t
inline size_t user_cmts_size(user_cmts_t *map)
{
  return (size_t)HEXDSP(hx_user_cmts_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_cmts_t instance
inline void user_cmts_free(user_cmts_t *map)
{
  HEXDSP(hx_user_cmts_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_cmts_t instance
inline user_cmts_t *user_cmts_new()
{
  return (user_cmts_t *)HEXDSP(hx_user_cmts_new);
}

//-------------------------------------------------------------------------
struct user_iflags_iterator_t
{
  iterator_word x;
  bool operator==(const user_iflags_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_iflags_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline citem_locator_t const &user_iflags_first(user_iflags_iterator_t p)
{
  return *(citem_locator_t *)HEXDSP(hx_user_iflags_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline int32 &user_iflags_second(user_iflags_iterator_t p)
{
  return *(int32 *)HEXDSP(hx_user_iflags_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_iflags_t
inline user_iflags_iterator_t user_iflags_find(const user_iflags_t *map, const citem_locator_t &key)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (citem_locator_t, int32) pair into user_iflags_t
inline user_iflags_iterator_t user_iflags_insert(user_iflags_t *map, const citem_locator_t &key, const int32 &val)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_iflags_t
inline user_iflags_iterator_t user_iflags_begin(const user_iflags_t *map)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_iflags_t
inline user_iflags_iterator_t user_iflags_end(const user_iflags_t *map)
{
  user_iflags_iterator_t p;
  HEXDSP(hx_user_iflags_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_iflags_iterator_t user_iflags_next(user_iflags_iterator_t p)
{
  HEXDSP(hx_user_iflags_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_iflags_iterator_t user_iflags_prev(user_iflags_iterator_t p)
{
  HEXDSP(hx_user_iflags_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_iflags_t
inline void user_iflags_erase(user_iflags_t *map, user_iflags_iterator_t p)
{
  HEXDSP(hx_user_iflags_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_iflags_t
inline void user_iflags_clear(user_iflags_t *map)
{
  HEXDSP(hx_user_iflags_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_iflags_t
inline size_t user_iflags_size(user_iflags_t *map)
{
  return (size_t)HEXDSP(hx_user_iflags_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_iflags_t instance
inline void user_iflags_free(user_iflags_t *map)
{
  HEXDSP(hx_user_iflags_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_iflags_t instance
inline user_iflags_t *user_iflags_new()
{
  return (user_iflags_t *)HEXDSP(hx_user_iflags_new);
}

//-------------------------------------------------------------------------
struct user_unions_iterator_t
{
  iterator_word x;
  bool operator==(const user_unions_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_unions_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &user_unions_first(user_unions_iterator_t p)
{
  return *(ea_t *)HEXDSP(hx_user_unions_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline intvec_t &user_unions_second(user_unions_iterator_t p)
{
  return *(intvec_t *)HEXDSP(hx_user_unions_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_unions_t
inline user_unions_iterator_t user_unions_find(const user_unions_t *map, const ea_t &key)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, intvec_t) pair into user_unions_t
inline user_unions_iterator_t user_unions_insert(user_unions_t *map, const ea_t &key, const intvec_t &val)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_unions_t
inline user_unions_iterator_t user_unions_begin(const user_unions_t *map)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_unions_t
inline user_unions_iterator_t user_unions_end(const user_unions_t *map)
{
  user_unions_iterator_t p;
  HEXDSP(hx_user_unions_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_unions_iterator_t user_unions_next(user_unions_iterator_t p)
{
  HEXDSP(hx_user_unions_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_unions_iterator_t user_unions_prev(user_unions_iterator_t p)
{
  HEXDSP(hx_user_unions_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_unions_t
inline void user_unions_erase(user_unions_t *map, user_unions_iterator_t p)
{
  HEXDSP(hx_user_unions_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_unions_t
inline void user_unions_clear(user_unions_t *map)
{
  HEXDSP(hx_user_unions_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_unions_t
inline size_t user_unions_size(user_unions_t *map)
{
  return (size_t)HEXDSP(hx_user_unions_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_unions_t instance
inline void user_unions_free(user_unions_t *map)
{
  HEXDSP(hx_user_unions_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_unions_t instance
inline user_unions_t *user_unions_new()
{
  return (user_unions_t *)HEXDSP(hx_user_unions_new);
}

//-------------------------------------------------------------------------
struct user_labels_iterator_t
{
  iterator_word x;
  bool operator==(const user_labels_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_labels_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline int const &user_labels_first(user_labels_iterator_t p)
{
  return *(int *)HEXDSP(hx_user_labels_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline qstring &user_labels_second(user_labels_iterator_t p)
{
  return *(qstring *)HEXDSP(hx_user_labels_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_labels_t
inline user_labels_iterator_t user_labels_find(const user_labels_t *map, const int &key)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (int, qstring) pair into user_labels_t
inline user_labels_iterator_t user_labels_insert(user_labels_t *map, const int &key, const qstring &val)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_labels_t
inline user_labels_iterator_t user_labels_begin(const user_labels_t *map)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_labels_t
inline user_labels_iterator_t user_labels_end(const user_labels_t *map)
{
  user_labels_iterator_t p;
  HEXDSP(hx_user_labels_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_labels_iterator_t user_labels_next(user_labels_iterator_t p)
{
  HEXDSP(hx_user_labels_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_labels_iterator_t user_labels_prev(user_labels_iterator_t p)
{
  HEXDSP(hx_user_labels_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_labels_t
inline void user_labels_erase(user_labels_t *map, user_labels_iterator_t p)
{
  HEXDSP(hx_user_labels_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_labels_t
inline void user_labels_clear(user_labels_t *map)
{
  HEXDSP(hx_user_labels_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_labels_t
inline size_t user_labels_size(user_labels_t *map)
{
  return (size_t)HEXDSP(hx_user_labels_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_labels_t instance
inline void user_labels_free(user_labels_t *map)
{
  HEXDSP(hx_user_labels_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_labels_t instance
inline user_labels_t *user_labels_new()
{
  return (user_labels_t *)HEXDSP(hx_user_labels_new);
}

//-------------------------------------------------------------------------
struct eamap_iterator_t
{
  iterator_word x;
  bool operator==(const eamap_iterator_t &p) const { return x == p.x; }
  bool operator!=(const eamap_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &eamap_first(eamap_iterator_t p)
{
  return *(ea_t *)HEXDSP(hx_eamap_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline cinsnptrvec_t &eamap_second(eamap_iterator_t p)
{
  return *(cinsnptrvec_t *)HEXDSP(hx_eamap_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in eamap_t
inline eamap_iterator_t eamap_find(const eamap_t *map, const ea_t &key)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, cinsnptrvec_t) pair into eamap_t
inline eamap_iterator_t eamap_insert(eamap_t *map, const ea_t &key, const cinsnptrvec_t &val)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of eamap_t
inline eamap_iterator_t eamap_begin(const eamap_t *map)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of eamap_t
inline eamap_iterator_t eamap_end(const eamap_t *map)
{
  eamap_iterator_t p;
  HEXDSP(hx_eamap_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline eamap_iterator_t eamap_next(eamap_iterator_t p)
{
  HEXDSP(hx_eamap_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline eamap_iterator_t eamap_prev(eamap_iterator_t p)
{
  HEXDSP(hx_eamap_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from eamap_t
inline void eamap_erase(eamap_t *map, eamap_iterator_t p)
{
  HEXDSP(hx_eamap_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear eamap_t
inline void eamap_clear(eamap_t *map)
{
  HEXDSP(hx_eamap_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of eamap_t
inline size_t eamap_size(eamap_t *map)
{
  return (size_t)HEXDSP(hx_eamap_size, map);
}

//-------------------------------------------------------------------------
/// Delete eamap_t instance
inline void eamap_free(eamap_t *map)
{
  HEXDSP(hx_eamap_free, map);
}

//-------------------------------------------------------------------------
/// Create a new eamap_t instance
inline eamap_t *eamap_new()
{
  return (eamap_t *)HEXDSP(hx_eamap_new);
}

//-------------------------------------------------------------------------
struct boundaries_iterator_t
{
  iterator_word x;
  bool operator==(const boundaries_iterator_t &p) const { return x == p.x; }
  bool operator!=(const boundaries_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline cinsn_t *const &boundaries_first(boundaries_iterator_t p)
{
  return *(cinsn_t * *)HEXDSP(hx_boundaries_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline rangeset_t &boundaries_second(boundaries_iterator_t p)
{
  return *(rangeset_t *)HEXDSP(hx_boundaries_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in boundaries_t
inline boundaries_iterator_t boundaries_find(const boundaries_t *map, const cinsn_t * &key)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (cinsn_t *, rangeset_t) pair into boundaries_t
inline boundaries_iterator_t boundaries_insert(boundaries_t *map, const cinsn_t * &key, const rangeset_t &val)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of boundaries_t
inline boundaries_iterator_t boundaries_begin(const boundaries_t *map)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of boundaries_t
inline boundaries_iterator_t boundaries_end(const boundaries_t *map)
{
  boundaries_iterator_t p;
  HEXDSP(hx_boundaries_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline boundaries_iterator_t boundaries_next(boundaries_iterator_t p)
{
  HEXDSP(hx_boundaries_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline boundaries_iterator_t boundaries_prev(boundaries_iterator_t p)
{
  HEXDSP(hx_boundaries_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from boundaries_t
inline void boundaries_erase(boundaries_t *map, boundaries_iterator_t p)
{
  HEXDSP(hx_boundaries_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear boundaries_t
inline void boundaries_clear(boundaries_t *map)
{
  HEXDSP(hx_boundaries_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of boundaries_t
inline size_t boundaries_size(boundaries_t *map)
{
  return (size_t)HEXDSP(hx_boundaries_size, map);
}

//-------------------------------------------------------------------------
/// Delete boundaries_t instance
inline void boundaries_free(boundaries_t *map)
{
  HEXDSP(hx_boundaries_free, map);
}

//-------------------------------------------------------------------------
/// Create a new boundaries_t instance
inline boundaries_t *boundaries_new()
{
  return (boundaries_t *)HEXDSP(hx_boundaries_new);
}

//-------------------------------------------------------------------------
struct lvar_mapping_iterator_t
{
  iterator_word x;
  bool operator==(const lvar_mapping_iterator_t &p) const { return x == p.x; }
  bool operator!=(const lvar_mapping_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline lvar_locator_t const &lvar_mapping_first(lvar_mapping_iterator_t p)
{
  return *(lvar_locator_t *)HEXDSP(hx_lvar_mapping_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline lvar_locator_t &lvar_mapping_second(lvar_mapping_iterator_t p)
{
  return *(lvar_locator_t *)HEXDSP(hx_lvar_mapping_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_find(const lvar_mapping_t *map, const lvar_locator_t &key)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (lvar_locator_t, lvar_locator_t) pair into lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_insert(lvar_mapping_t *map, const lvar_locator_t &key, const lvar_locator_t &val)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_begin(const lvar_mapping_t *map)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_end(const lvar_mapping_t *map)
{
  lvar_mapping_iterator_t p;
  HEXDSP(hx_lvar_mapping_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline lvar_mapping_iterator_t lvar_mapping_next(lvar_mapping_iterator_t p)
{
  HEXDSP(hx_lvar_mapping_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline lvar_mapping_iterator_t lvar_mapping_prev(lvar_mapping_iterator_t p)
{
  HEXDSP(hx_lvar_mapping_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from lvar_mapping_t
inline void lvar_mapping_erase(lvar_mapping_t *map, lvar_mapping_iterator_t p)
{
  HEXDSP(hx_lvar_mapping_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear lvar_mapping_t
inline void lvar_mapping_clear(lvar_mapping_t *map)
{
  HEXDSP(hx_lvar_mapping_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of lvar_mapping_t
inline size_t lvar_mapping_size(lvar_mapping_t *map)
{
  return (size_t)HEXDSP(hx_lvar_mapping_size, map);
}

//-------------------------------------------------------------------------
/// Delete lvar_mapping_t instance
inline void lvar_mapping_free(lvar_mapping_t *map)
{
  HEXDSP(hx_lvar_mapping_free, map);
}

//-------------------------------------------------------------------------
/// Create a new lvar_mapping_t instance
inline lvar_mapping_t *lvar_mapping_new()
{
  return (lvar_mapping_t *)HEXDSP(hx_lvar_mapping_new);
}

//-------------------------------------------------------------------------
struct udcall_map_iterator_t
{
  iterator_word x;
  bool operator==(const udcall_map_iterator_t &p) const { return x == p.x; }
  bool operator!=(const udcall_map_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &udcall_map_first(udcall_map_iterator_t p)
{
  return *(ea_t *)HEXDSP(hx_udcall_map_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline udcall_t &udcall_map_second(udcall_map_iterator_t p)
{
  return *(udcall_t *)HEXDSP(hx_udcall_map_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in udcall_map_t
inline udcall_map_iterator_t udcall_map_find(const udcall_map_t *map, const ea_t &key)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, udcall_t) pair into udcall_map_t
inline udcall_map_iterator_t udcall_map_insert(udcall_map_t *map, const ea_t &key, const udcall_t &val)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of udcall_map_t
inline udcall_map_iterator_t udcall_map_begin(const udcall_map_t *map)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of udcall_map_t
inline udcall_map_iterator_t udcall_map_end(const udcall_map_t *map)
{
  udcall_map_iterator_t p;
  HEXDSP(hx_udcall_map_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline udcall_map_iterator_t udcall_map_next(udcall_map_iterator_t p)
{
  HEXDSP(hx_udcall_map_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline udcall_map_iterator_t udcall_map_prev(udcall_map_iterator_t p)
{
  HEXDSP(hx_udcall_map_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from udcall_map_t
inline void udcall_map_erase(udcall_map_t *map, udcall_map_iterator_t p)
{
  HEXDSP(hx_udcall_map_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear udcall_map_t
inline void udcall_map_clear(udcall_map_t *map)
{
  HEXDSP(hx_udcall_map_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of udcall_map_t
inline size_t udcall_map_size(udcall_map_t *map)
{
  return (size_t)HEXDSP(hx_udcall_map_size, map);
}

//-------------------------------------------------------------------------
/// Delete udcall_map_t instance
inline void udcall_map_free(udcall_map_t *map)
{
  HEXDSP(hx_udcall_map_free, map);
}

//-------------------------------------------------------------------------
/// Create a new udcall_map_t instance
inline udcall_map_t *udcall_map_new()
{
  return (udcall_map_t *)HEXDSP(hx_udcall_map_new);
}

//-------------------------------------------------------------------------
struct block_chains_iterator_t
{
  iterator_word x;
  bool operator==(const block_chains_iterator_t &p) const { return x == p.x; }
  bool operator!=(const block_chains_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get reference to the current set value
inline chain_t &block_chains_get(block_chains_iterator_t p)
{
  return *(chain_t *)HEXDSP(hx_block_chains_get, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in set block_chains_t
inline block_chains_iterator_t block_chains_find(const block_chains_t *set, const chain_t &val)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_find, &p, set, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (chain_t) into set block_chains_t
inline block_chains_iterator_t block_chains_insert(block_chains_t *set, const chain_t &val)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_insert, &p, set, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of block_chains_t
inline block_chains_iterator_t block_chains_begin(const block_chains_t *set)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_begin, &p, set);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of block_chains_t
inline block_chains_iterator_t block_chains_end(const block_chains_t *set)
{
  block_chains_iterator_t p;
  HEXDSP(hx_block_chains_end, &p, set);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline block_chains_iterator_t block_chains_next(block_chains_iterator_t p)
{
  HEXDSP(hx_block_chains_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline block_chains_iterator_t block_chains_prev(block_chains_iterator_t p)
{
  HEXDSP(hx_block_chains_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from block_chains_t
inline void block_chains_erase(block_chains_t *set, block_chains_iterator_t p)
{
  HEXDSP(hx_block_chains_erase, set, &p);
}

//-------------------------------------------------------------------------
/// Clear block_chains_t
inline void block_chains_clear(block_chains_t *set)
{
  HEXDSP(hx_block_chains_clear, set);
}

//-------------------------------------------------------------------------
/// Get size of block_chains_t
inline size_t block_chains_size(block_chains_t *set)
{
  return (size_t)HEXDSP(hx_block_chains_size, set);
}

//-------------------------------------------------------------------------
/// Delete block_chains_t instance
inline void block_chains_free(block_chains_t *set)
{
  HEXDSP(hx_block_chains_free, set);
}

//-------------------------------------------------------------------------
/// Create a new block_chains_t instance
inline block_chains_t *block_chains_new()
{
  return (block_chains_t *)HEXDSP(hx_block_chains_new);
}

//--------------------------------------------------------------------------
inline void *hexrays_alloc(size_t size)
{
  return HEXDSP(hx_hexrays_alloc, size);
}

//--------------------------------------------------------------------------
inline void hexrays_free(void *ptr)
{
  HEXDSP(hx_hexrays_free, ptr);
}

//--------------------------------------------------------------------------
inline int operand_locator_t::compare(const operand_locator_t &r) const
{
  return (int)(size_t)HEXDSP(hx_operand_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool mba_ranges_t::range_contains(ea_t ea) const
{
  return (uchar)(size_t)HEXDSP(hx_mba_ranges_t_range_contains, this, ea) != 0;
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int vd_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)HEXDSP(hx_vd_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int file_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)HEXDSP(hx_file_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int qstring_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)HEXDSP(hx_qstring_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline void remitem(const citem_t *e)
{
  HEXDSP(hx_remitem, e);
}

//--------------------------------------------------------------------------
inline ctype_t negated_relation(ctype_t op)
{
  return (ctype_t)(size_t)HEXDSP(hx_negated_relation, op);
}

//--------------------------------------------------------------------------
inline ctype_t swapped_relation(ctype_t op)
{
  return (ctype_t)(size_t)HEXDSP(hx_swapped_relation, op);
}

//--------------------------------------------------------------------------
inline type_sign_t get_op_signness(ctype_t op)
{
  return (type_sign_t)(size_t)HEXDSP(hx_get_op_signness, op);
}

//--------------------------------------------------------------------------
inline ctype_t asgop(ctype_t cop)
{
  return (ctype_t)(size_t)HEXDSP(hx_asgop, cop);
}

//--------------------------------------------------------------------------
inline ctype_t asgop_revert(ctype_t cop)
{
  return (ctype_t)(size_t)HEXDSP(hx_asgop_revert, cop);
}

//--------------------------------------------------------------------------
inline void cnumber_t::print(qstring *vout, const tinfo_t &type, const citem_t *parent, bool *nice_stroff) const
{
  HEXDSP(hx_cnumber_t_print, this, vout, &type, parent, nice_stroff);
}

//--------------------------------------------------------------------------
inline uint64 cnumber_t::value(const tinfo_t &type) const
{
  uint64 retval;
  HEXDSP(hx_cnumber_t_value, &retval, this, &type);
  return retval;
}

//--------------------------------------------------------------------------
inline void cnumber_t::assign(uint64 v, int nbytes, type_sign_t sign)
{
  HEXDSP(hx_cnumber_t_assign, this, v, nbytes, sign);
}

//--------------------------------------------------------------------------
inline int cnumber_t::compare(const cnumber_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cnumber_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int var_ref_t::compare(const var_ref_t &r) const
{
  return (int)(size_t)HEXDSP(hx_var_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int citem_locator_t::compare(const citem_locator_t &r) const
{
  return (int)(size_t)HEXDSP(hx_citem_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool citem_t::contains_expr(const cexpr_t *e) const
{
  return (uchar)(size_t)HEXDSP(hx_citem_t_contains_expr, this, e) != 0;
}

//--------------------------------------------------------------------------
inline bool citem_t::contains_label() const
{
  return (uchar)(size_t)HEXDSP(hx_citem_t_contains_label, this) != 0;
}

//--------------------------------------------------------------------------
inline const citem_t *citem_t::find_parent_of(const citem_t *item) const
{
  return (const citem_t *)HEXDSP(hx_citem_t_find_parent_of, this, item);
}

//--------------------------------------------------------------------------
inline citem_t *citem_t::find_closest_addr(ea_t _ea)
{
  return (citem_t *)HEXDSP(hx_citem_t_find_closest_addr, this, _ea);
}

//--------------------------------------------------------------------------
inline cexpr_t &cexpr_t::assign(const cexpr_t &r)
{
  return *(cexpr_t *)HEXDSP(hx_cexpr_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cexpr_t::compare(const cexpr_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cexpr_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void cexpr_t::replace_by(cexpr_t *r)
{
  HEXDSP(hx_cexpr_t_replace_by, this, r);
}

//--------------------------------------------------------------------------
inline void cexpr_t::cleanup()
{
  HEXDSP(hx_cexpr_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline void cexpr_t::put_number(cfunc_t *func, uint64 value, int nbytes, type_sign_t sign)
{
  HEXDSP(hx_cexpr_t_put_number, this, func, value, nbytes, sign);
}

//--------------------------------------------------------------------------
inline void cexpr_t::print1(qstring *vout, const cfunc_t *func) const
{
  HEXDSP(hx_cexpr_t_print1, this, vout, func);
}

//--------------------------------------------------------------------------
inline void cexpr_t::calc_type(bool recursive)
{
  HEXDSP(hx_cexpr_t_calc_type, this, recursive);
}

//--------------------------------------------------------------------------
inline bool cexpr_t::equal_effect(const cexpr_t &r) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_equal_effect, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::is_child_of(const citem_t *parent) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_is_child_of, this, parent) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::contains_operator(ctype_t needed_op, int times) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_contains_operator, this, needed_op, times) != 0;
}

//--------------------------------------------------------------------------
inline bit_bound_t cexpr_t::get_high_nbit_bound() const
{
  bit_bound_t retval;
  HEXDSP(hx_cexpr_t_get_high_nbit_bound, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline int cexpr_t::get_low_nbit_bound() const
{
  return (int)(size_t)HEXDSP(hx_cexpr_t_get_low_nbit_bound, this);
}

//--------------------------------------------------------------------------
inline bool cexpr_t::requires_lvalue(const cexpr_t *child) const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_requires_lvalue, this, child) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::has_side_effects() const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_has_side_effects, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::maybe_ptr() const
{
  return (uchar)(size_t)HEXDSP(hx_cexpr_t_maybe_ptr, this) != 0;
}

//--------------------------------------------------------------------------
inline const char *cexpr_t::dstr() const
{
  return (const char *)HEXDSP(hx_cexpr_t_dstr, this);
}

//--------------------------------------------------------------------------
inline cif_t &cif_t::assign(const cif_t &r)
{
  return *(cif_t *)HEXDSP(hx_cif_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cif_t::compare(const cif_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cif_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline cloop_t &cloop_t::assign(const cloop_t &r)
{
  return *(cloop_t *)HEXDSP(hx_cloop_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cfor_t::compare(const cfor_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cfor_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cwhile_t::compare(const cwhile_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cwhile_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cdo_t::compare(const cdo_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cdo_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int creturn_t::compare(const creturn_t &r) const
{
  return (int)(size_t)HEXDSP(hx_creturn_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cgoto_t::compare(const cgoto_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cgoto_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int casm_t::compare(const casm_t &r) const
{
  return (int)(size_t)HEXDSP(hx_casm_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline cinsn_t &cinsn_t::assign(const cinsn_t &r)
{
  return *(cinsn_t *)HEXDSP(hx_cinsn_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cinsn_t::compare(const cinsn_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cinsn_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void cinsn_t::replace_by(cinsn_t *r)
{
  HEXDSP(hx_cinsn_t_replace_by, this, r);
}

//--------------------------------------------------------------------------
inline void cinsn_t::cleanup()
{
  HEXDSP(hx_cinsn_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline cinsn_t &cinsn_t::new_insn(ea_t insn_ea)
{
  return *(cinsn_t *)HEXDSP(hx_cinsn_t_new_insn, this, insn_ea);
}

//--------------------------------------------------------------------------
inline cif_t &cinsn_t::create_if(cexpr_t *cnd)
{
  return *(cif_t *)HEXDSP(hx_cinsn_t_create_if, this, cnd);
}

//--------------------------------------------------------------------------
inline void cinsn_t::print(int indent, vc_printer_t &vp, use_curly_t use_curly) const
{
  HEXDSP(hx_cinsn_t_print, this, indent, &vp, use_curly);
}

//--------------------------------------------------------------------------
inline void cinsn_t::print1(qstring *vout, const cfunc_t *func) const
{
  HEXDSP(hx_cinsn_t_print1, this, vout, func);
}

//--------------------------------------------------------------------------
inline bool cinsn_t::is_ordinary_flow() const
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_is_ordinary_flow, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::contains_insn(ctype_t type, int times) const
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_contains_insn, this, type, times) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::collect_free_breaks(cinsnptrvec_t *breaks)
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_collect_free_breaks, this, breaks) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::collect_free_continues(cinsnptrvec_t *continues)
{
  return (uchar)(size_t)HEXDSP(hx_cinsn_t_collect_free_continues, this, continues) != 0;
}

//--------------------------------------------------------------------------
inline const char *cinsn_t::dstr() const
{
  return (const char *)HEXDSP(hx_cinsn_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int cblock_t::compare(const cblock_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cblock_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int carglist_t::compare(const carglist_t &r) const
{
  return (int)(size_t)HEXDSP(hx_carglist_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccase_t::compare(const ccase_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ccase_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccases_t::compare(const ccases_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ccases_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cswitch_t::compare(const cswitch_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cswitch_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int catchexpr_t::compare(const catchexpr_t &r) const
{
  return (int)(size_t)HEXDSP(hx_catchexpr_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccatch_t::compare(const ccatch_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ccatch_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ctry_t::compare(const ctry_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ctry_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cthrow_t::compare(const cthrow_t &r) const
{
  return (int)(size_t)HEXDSP(hx_cthrow_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ctree_visitor_t::apply_to(citem_t *item, citem_t *parent)
{
  return (int)(size_t)HEXDSP(hx_ctree_visitor_t_apply_to, this, item, parent);
}

//--------------------------------------------------------------------------
inline int ctree_visitor_t::apply_to_exprs(citem_t *item, citem_t *parent)
{
  return (int)(size_t)HEXDSP(hx_ctree_visitor_t_apply_to_exprs, this, item, parent);
}

//--------------------------------------------------------------------------
inline bool ctree_parentee_t::recalc_parent_types()
{
  return (uchar)(size_t)HEXDSP(hx_ctree_parentee_t_recalc_parent_types, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cfunc_parentee_t::calc_rvalue_type(tinfo_t *target, const cexpr_t *e)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_parentee_t_calc_rvalue_type, this, target, e) != 0;
}

//--------------------------------------------------------------------------
inline int ctree_item_t::get_udm(udm_t *udm, tinfo_t *parent, uint64 *p_offset) const
{
  return (int)(size_t)HEXDSP(hx_ctree_item_t_get_udm, this, udm, parent, p_offset);
}

//--------------------------------------------------------------------------
inline int ctree_item_t::get_edm(tinfo_t *parent) const
{
  return (int)(size_t)HEXDSP(hx_ctree_item_t_get_edm, this, parent);
}

//--------------------------------------------------------------------------
inline lvar_t *ctree_item_t::get_lvar() const
{
  return (lvar_t *)HEXDSP(hx_ctree_item_t_get_lvar, this);
}

//--------------------------------------------------------------------------
inline ea_t ctree_item_t::get_ea() const
{
  ea_t retval;
  HEXDSP(hx_ctree_item_t_get_ea, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline int ctree_item_t::get_label_num(int gln_flags) const
{
  return (int)(size_t)HEXDSP(hx_ctree_item_t_get_label_num, this, gln_flags);
}

//--------------------------------------------------------------------------
inline void ctree_item_t::print(qstring *vout) const
{
  HEXDSP(hx_ctree_item_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *ctree_item_t::dstr() const
{
  return (const char *)HEXDSP(hx_ctree_item_t_dstr, this);
}

//--------------------------------------------------------------------------
inline cexpr_t *lnot(cexpr_t *e)
{
  return (cexpr_t *)HEXDSP(hx_lnot, e);
}

//--------------------------------------------------------------------------
inline cinsn_t *new_block()
{
  return (cinsn_t *)HEXDSP(hx_new_block);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) cexpr_t *vcreate_helper(bool standalone, const tinfo_t &type, const char *format, va_list va)
{
  return (cexpr_t *)HEXDSP(hx_vcreate_helper, standalone, &type, format, va);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) cexpr_t *vcall_helper(const tinfo_t &rettype, carglist_t *args, const char *format, va_list va)
{
  return (cexpr_t *)HEXDSP(hx_vcall_helper, &rettype, args, format, va);
}

//--------------------------------------------------------------------------
inline cexpr_t *make_num(uint64 n, cfunc_t *func, ea_t ea, int opnum, type_sign_t sign, int size)
{
  return (cexpr_t *)HEXDSP(hx_make_num, n, func, ea, opnum, sign, size);
}

//--------------------------------------------------------------------------
inline cexpr_t *make_ref(cexpr_t *e)
{
  return (cexpr_t *)HEXDSP(hx_make_ref, e);
}

//--------------------------------------------------------------------------
inline cexpr_t *dereference(cexpr_t *e, int ptrsize, bool is_flt)
{
  return (cexpr_t *)HEXDSP(hx_dereference, e, ptrsize, is_flt);
}

//--------------------------------------------------------------------------
inline void save_user_labels(ea_t func_ea, const user_labels_t *user_labels, const cfunc_t *func)
{
  HEXDSP(hx_save_user_labels, func_ea, user_labels, func);
}

//--------------------------------------------------------------------------
inline void save_user_cmts(ea_t func_ea, const user_cmts_t *user_cmts)
{
  HEXDSP(hx_save_user_cmts, func_ea, user_cmts);
}

//--------------------------------------------------------------------------
inline void save_user_numforms(ea_t func_ea, const user_numforms_t *numforms)
{
  HEXDSP(hx_save_user_numforms, func_ea, numforms);
}

//--------------------------------------------------------------------------
inline void save_user_iflags(ea_t func_ea, const user_iflags_t *iflags)
{
  HEXDSP(hx_save_user_iflags, func_ea, iflags);
}

//--------------------------------------------------------------------------
inline void save_user_unions(ea_t func_ea, const user_unions_t *unions)
{
  HEXDSP(hx_save_user_unions, func_ea, unions);
}

//--------------------------------------------------------------------------
inline user_labels_t *restore_user_labels(ea_t func_ea, const cfunc_t *func)
{
  return (user_labels_t *)HEXDSP(hx_restore_user_labels, func_ea, func);
}

//--------------------------------------------------------------------------
inline user_cmts_t *restore_user_cmts(ea_t func_ea)
{
  return (user_cmts_t *)HEXDSP(hx_restore_user_cmts, func_ea);
}

//--------------------------------------------------------------------------
inline user_numforms_t *restore_user_numforms(ea_t func_ea)
{
  return (user_numforms_t *)HEXDSP(hx_restore_user_numforms, func_ea);
}

//--------------------------------------------------------------------------
inline user_iflags_t *restore_user_iflags(ea_t func_ea)
{
  return (user_iflags_t *)HEXDSP(hx_restore_user_iflags, func_ea);
}

//--------------------------------------------------------------------------
inline user_unions_t *restore_user_unions(ea_t func_ea)
{
  return (user_unions_t *)HEXDSP(hx_restore_user_unions, func_ea);
}

//--------------------------------------------------------------------------
inline void cfunc_t::build_c_tree()
{
  HEXDSP(hx_cfunc_t_build_c_tree, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::verify(allow_unused_labels_t aul, bool even_without_debugger) const
{
  HEXDSP(hx_cfunc_t_verify, this, aul, even_without_debugger);
}

//--------------------------------------------------------------------------
inline void cfunc_t::print_dcl(qstring *vout) const
{
  HEXDSP(hx_cfunc_t_print_dcl, this, vout);
}

//--------------------------------------------------------------------------
inline void cfunc_t::print_func(vc_printer_t &vp) const
{
  HEXDSP(hx_cfunc_t_print_func, this, &vp);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_func_type(tinfo_t *type) const
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_get_func_type, this, type) != 0;
}

//--------------------------------------------------------------------------
inline lvars_t *cfunc_t::get_lvars()
{
  return (lvars_t *)HEXDSP(hx_cfunc_t_get_lvars, this);
}

//--------------------------------------------------------------------------
inline sval_t cfunc_t::get_stkoff_delta()
{
  sval_t retval;
  HEXDSP(hx_cfunc_t_get_stkoff_delta, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline citem_t *cfunc_t::find_label(int label)
{
  return (citem_t *)HEXDSP(hx_cfunc_t_find_label, this, label);
}

//--------------------------------------------------------------------------
inline void cfunc_t::remove_unused_labels()
{
  HEXDSP(hx_cfunc_t_remove_unused_labels, this);
}

//--------------------------------------------------------------------------
inline const char *cfunc_t::get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const
{
  return (const char *)HEXDSP(hx_cfunc_t_get_user_cmt, this, &loc, rt);
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_cmt(const treeloc_t &loc, const char *cmt)
{
  HEXDSP(hx_cfunc_t_set_user_cmt, this, &loc, cmt);
}

//--------------------------------------------------------------------------
inline int32 cfunc_t::get_user_iflags(const citem_locator_t &loc) const
{
  return (int32)(size_t)HEXDSP(hx_cfunc_t_get_user_iflags, this, &loc);
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_iflags(const citem_locator_t &loc, int32 iflags)
{
  HEXDSP(hx_cfunc_t_set_user_iflags, this, &loc, iflags);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::has_orphan_cmts() const
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_has_orphan_cmts, this) != 0;
}

//--------------------------------------------------------------------------
inline int cfunc_t::del_orphan_cmts()
{
  return (int)(size_t)HEXDSP(hx_cfunc_t_del_orphan_cmts, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_user_union_selection(ea_t ea, intvec_t *path)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_get_user_union_selection, this, ea, path) != 0;
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_union_selection(ea_t ea, const intvec_t &path)
{
  HEXDSP(hx_cfunc_t_set_user_union_selection, this, ea, &path);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_labels() const
{
  HEXDSP(hx_cfunc_t_save_user_labels, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_cmts() const
{
  HEXDSP(hx_cfunc_t_save_user_cmts, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_numforms() const
{
  HEXDSP(hx_cfunc_t_save_user_numforms, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_iflags() const
{
  HEXDSP(hx_cfunc_t_save_user_iflags, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::save_user_unions() const
{
  HEXDSP(hx_cfunc_t_save_user_unions, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_line_item(const char *line, int x, bool is_ctree_line, ctree_item_t *phead, ctree_item_t *pitem, ctree_item_t *ptail)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_get_line_item, this, line, x, is_ctree_line, phead, pitem, ptail) != 0;
}

//--------------------------------------------------------------------------
inline hexwarns_t &cfunc_t::get_warnings()
{
  return *(hexwarns_t *)HEXDSP(hx_cfunc_t_get_warnings, this);
}

//--------------------------------------------------------------------------
inline eamap_t &cfunc_t::get_eamap()
{
  return *(eamap_t *)HEXDSP(hx_cfunc_t_get_eamap, this);
}

//--------------------------------------------------------------------------
inline boundaries_t &cfunc_t::get_boundaries()
{
  return *(boundaries_t *)HEXDSP(hx_cfunc_t_get_boundaries, this);
}

//--------------------------------------------------------------------------
inline const strvec_t &cfunc_t::get_pseudocode()
{
  return *(const strvec_t *)HEXDSP(hx_cfunc_t_get_pseudocode, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::refresh_func_ctext()
{
  HEXDSP(hx_cfunc_t_refresh_func_ctext, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::recalc_item_addresses()
{
  HEXDSP(hx_cfunc_t_recalc_item_addresses, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm) const
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_gather_derefs, this, &ci, udm) != 0;
}

//--------------------------------------------------------------------------
inline bool cfunc_t::find_item_coords(const citem_t *item, int *px, int *py)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_find_item_coords, this, item, px, py) != 0;
}

//--------------------------------------------------------------------------
inline bool cfunc_t::serialize(bytevec_t *vout)
{
  return (uchar)(size_t)HEXDSP(hx_cfunc_t_serialize, this, vout) != 0;
}

//--------------------------------------------------------------------------
inline WARN_UNUSED_RESULT cfunc_t *cfunc_t::deserialize(mba_t *mba, const uchar *bytes, size_t nbytes)
{
  return (cfunc_t *)HEXDSP(hx_cfunc_t_deserialize, mba, bytes, nbytes);
}

//--------------------------------------------------------------------------
inline void cfunc_t::cleanup()
{
  HEXDSP(hx_cfunc_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline void close_hexrays_waitbox()
{
  HEXDSP(hx_close_hexrays_waitbox);
}

//--------------------------------------------------------------------------
inline cfuncptr_t decompile(const mba_ranges_t &mbr, hexrays_failure_t *hf, int decomp_flags)
{
  return cfuncptr_t((cfunc_t *)HEXDSP(hx_decompile, &mbr, hf, decomp_flags));
}

//--------------------------------------------------------------------------
inline cfuncptr_t create_cfunc(mba_t *mba)
{
  return cfuncptr_t((cfunc_t *)HEXDSP(hx_create_cfunc, mba));
}

//--------------------------------------------------------------------------
inline bool mark_cfunc_dirty(ea_t ea, bool close_views)
{
  return (uchar)(size_t)HEXDSP(hx_mark_cfunc_dirty, ea, close_views) != 0;
}

//--------------------------------------------------------------------------
inline void clear_cached_cfuncs()
{
  HEXDSP(hx_clear_cached_cfuncs);
}

//--------------------------------------------------------------------------
inline bool has_cached_cfunc(ea_t ea)
{
  return (uchar)(size_t)HEXDSP(hx_has_cached_cfunc, ea) != 0;
}

//--------------------------------------------------------------------------
inline const char *get_ctype_name(ctype_t op)
{
  return (const char *)HEXDSP(hx_get_ctype_name, op);
}

//--------------------------------------------------------------------------
inline qstring create_field_name(const tinfo_t &type, uval_t offset)
{
  qstring retval;
  HEXDSP(hx_create_field_name, &retval, &type, offset);
  return retval;
}

//--------------------------------------------------------------------------
inline bool install_hexrays_callback(hexrays_cb_t *callback, void *ud)
{
  return (uchar)(size_t)HEXDSP(hx_install_hexrays_callback, callback, ud) != 0;
}

//--------------------------------------------------------------------------
inline int remove_hexrays_callback(hexrays_cb_t *callback, void *ud)
{
  auto hrdsp = HEXDSP;
  return hrdsp == nullptr ? 0 : (int)(size_t)hrdsp(hx_remove_hexrays_callback, callback, ud);
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_locked(bool v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_locked, this, v) != 0;
}

//--------------------------------------------------------------------------
inline void vdui_t::refresh_view(bool redo_mba)
{
  HEXDSP(hx_vdui_t_refresh_view, this, redo_mba);
}

//--------------------------------------------------------------------------
inline void vdui_t::refresh_ctext(bool activate)
{
  HEXDSP(hx_vdui_t_refresh_ctext, this, activate);
}

//--------------------------------------------------------------------------
inline void vdui_t::switch_to(cfuncptr_t f, bool activate)
{
  HEXDSP(hx_vdui_t_switch_to, this, &f, activate);
}

//--------------------------------------------------------------------------
inline cnumber_t *vdui_t::get_number()
{
  return (cnumber_t *)HEXDSP(hx_vdui_t_get_number, this);
}

//--------------------------------------------------------------------------
inline int vdui_t::get_current_label()
{
  return (int)(size_t)HEXDSP(hx_vdui_t_get_current_label, this);
}

//--------------------------------------------------------------------------
inline void vdui_t::clear()
{
  HEXDSP(hx_vdui_t_clear, this);
}

//--------------------------------------------------------------------------
inline bool vdui_t::refresh_cpos(input_device_t idv)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_refresh_cpos, this, idv) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::get_current_item(input_device_t idv)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_get_current_item, this, idv) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_rename_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_rename_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_lvar(lvar_t *v, const char *name, bool is_user_name)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_lvar, this, v, name, is_user_name) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_set_call_type(const cexpr_t *e)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_set_call_type, this, e) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_set_lvar_type(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_set_lvar_type, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_lvar_type(lvar_t *v, const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_lvar_type, this, v, &type) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_noptr_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_noptr_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_edit_lvar_cmt(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_edit_lvar_cmt, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_lvar_cmt(lvar_t *v, const char *cmt)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_lvar_cmt, this, v, cmt) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_map_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_map_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_unmap_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_unmap_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ui_noprop_lvar(lvar_t *v)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ui_noprop_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::map_lvar(lvar_t *from, lvar_t *to)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_map_lvar, this, from, to) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_udm_type(tinfo_t &udt_type, int udm_idx)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_udm_type, this, &udt_type, udm_idx) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_udm(tinfo_t &udt_type, int udm_idx)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_udm, this, &udt_type, udm_idx) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_global_type(ea_t ea)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_global_type, this, ea) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_global(ea_t ea)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_global, this, ea) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::rename_label(int label)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_rename_label, this, label) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::jump_enter(input_device_t idv, int omflags)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_jump_enter, this, idv, omflags) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::ctree_to_disasm()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_ctree_to_disasm, this) != 0;
}

//--------------------------------------------------------------------------
inline cmt_type_t vdui_t::calc_cmt_type(size_t lnnum, cmt_type_t cmttype) const
{
  return (cmt_type_t)(size_t)HEXDSP(hx_vdui_t_calc_cmt_type, this, lnnum, cmttype);
}

//--------------------------------------------------------------------------
inline bool vdui_t::edit_cmt(const treeloc_t &loc)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_edit_cmt, this, &loc) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::edit_func_cmt()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_edit_func_cmt, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::del_orphan_cmts()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_del_orphan_cmts, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_num_radix(int base)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_num_radix, this, base) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_num_enum()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_num_enum, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::set_num_stroff()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_set_num_stroff, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::invert_sign()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_invert_sign, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::invert_bits()
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_invert_bits, this) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::collapse_item(bool hide)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_collapse_item, this, hide) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::collapse_lvars(bool hide)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_collapse_lvars, this, hide) != 0;
}

//--------------------------------------------------------------------------
inline bool vdui_t::split_item(bool split)
{
  return (uchar)(size_t)HEXDSP(hx_vdui_t_split_item, this, split) != 0;
}

//--------------------------------------------------------------------------
inline int select_udt_by_offset(const qvector<tinfo_t> *udts, const ui_stroff_ops_t &ops, ui_stroff_applicator_t &applicator)
{
  return (int)(size_t)HEXDSP(hx_select_udt_by_offset, udts, &ops, &applicator);
}

//--------------------------------------------------------------------------
inline void valrng_t::clear()
{
  HEXDSP(hx_valrng_t_clear, this);
}

//--------------------------------------------------------------------------
inline void valrng_t::copy(const valrng_t &r)
{
  HEXDSP(hx_valrng_t_copy, this, &r);
}

//--------------------------------------------------------------------------
inline valrng_t &valrng_t::assign(const valrng_t &r)
{
  return *(valrng_t *)HEXDSP(hx_valrng_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int valrng_t::compare(const valrng_t &r) const
{
  return (int)(size_t)HEXDSP(hx_valrng_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void valrng_t::set_eq(uvlr_t v)
{
  HEXDSP(hx_valrng_t_set_eq, this, v);
}

//--------------------------------------------------------------------------
inline void valrng_t::set_cmp(cmpop_t cmp, uvlr_t _value)
{
  HEXDSP(hx_valrng_t_set_cmp, this, cmp, _value);
}

//--------------------------------------------------------------------------
inline bool valrng_t::reduce_size(int new_size)
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_reduce_size, this, new_size) != 0;
}

//--------------------------------------------------------------------------
inline bool valrng_t::intersect_with(const valrng_t &r)
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_intersect_with, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline bool valrng_t::unite_with(const valrng_t &r)
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_unite_with, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline void valrng_t::inverse()
{
  HEXDSP(hx_valrng_t_inverse, this);
}

//--------------------------------------------------------------------------
inline bool valrng_t::has(uvlr_t v) const
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_has, this, v) != 0;
}

//--------------------------------------------------------------------------
inline void valrng_t::print(qstring *vout) const
{
  HEXDSP(hx_valrng_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *valrng_t::dstr() const
{
  return (const char *)HEXDSP(hx_valrng_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool valrng_t::cvt_to_single_value(uvlr_t *v) const
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_cvt_to_single_value, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool valrng_t::cvt_to_cmp(cmpop_t *cmp, uvlr_t *val) const
{
  return (uchar)(size_t)HEXDSP(hx_valrng_t_cvt_to_cmp, this, cmp, val) != 0;
}

//--------------------------------------------------------------------------
inline ea_t get_merror_desc(qstring *out, merror_t code, mba_t *mba)
{
  ea_t retval;
  HEXDSP(hx_get_merror_desc, &retval, out, code, mba);
  return retval;
}

//--------------------------------------------------------------------------
inline qstring hexrays_failure_t::desc() const
{
  qstring retval;
  HEXDSP(hx_hexrays_failure_t_desc, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline THREAD_SAFE bool must_mcode_close_block(mcode_t mcode, bool including_calls)
{
  return (uchar)(size_t)HEXDSP(hx_must_mcode_close_block, mcode, including_calls) != 0;
}

//--------------------------------------------------------------------------
inline THREAD_SAFE bool is_mcode_propagatable(mcode_t mcode)
{
  return (uchar)(size_t)HEXDSP(hx_is_mcode_propagatable, mcode) != 0;
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t negate_mcode_relation(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_negate_mcode_relation, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t swap_mcode_relation(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_swap_mcode_relation, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t get_signed_mcode(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_get_signed_mcode, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE mcode_t get_unsigned_mcode(mcode_t code)
{
  return (mcode_t)(size_t)HEXDSP(hx_get_unsigned_mcode, code);
}

//--------------------------------------------------------------------------
inline THREAD_SAFE bool mcode_modifies_d(mcode_t mcode)
{
  return (uchar)(size_t)HEXDSP(hx_mcode_modifies_d, mcode) != 0;
}

//--------------------------------------------------------------------------
inline const char *dstr(const tinfo_t *tif)
{
  return (const char *)HEXDSP(hx_dstr, tif);
}

//--------------------------------------------------------------------------
inline bool is_type_correct(const type_t *ptr)
{
  return (uchar)(size_t)HEXDSP(hx_is_type_correct, ptr) != 0;
}

//--------------------------------------------------------------------------
inline bool is_small_udt(const tinfo_t &tif)
{
  return (uchar)(size_t)HEXDSP(hx_is_small_udt, &tif) != 0;
}

//--------------------------------------------------------------------------
inline bool is_nonbool_type(const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_is_nonbool_type, &type) != 0;
}

//--------------------------------------------------------------------------
inline bool is_bool_type(const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_is_bool_type, &type) != 0;
}

//--------------------------------------------------------------------------
inline int partial_type_num(const tinfo_t &type)
{
  return (int)(size_t)HEXDSP(hx_partial_type_num, &type);
}

//--------------------------------------------------------------------------
inline tinfo_t get_float_type(int width)
{
  tinfo_t retval;
  HEXDSP(hx_get_float_type, &retval, width);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign)
{
  tinfo_t retval;
  HEXDSP(hx_get_int_type_by_width_and_sign, &retval, srcwidth, sign);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t get_unk_type(int size)
{
  tinfo_t retval;
  HEXDSP(hx_get_unk_type, &retval, size);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t dummy_ptrtype(int ptrsize, bool isfp)
{
  tinfo_t retval;
  HEXDSP(hx_dummy_ptrtype, &retval, ptrsize, isfp);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t make_pointer(const tinfo_t &type)
{
  tinfo_t retval;
  HEXDSP(hx_make_pointer, &retval, &type);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t create_typedef(const char *name)
{
  tinfo_t retval;
  HEXDSP(hx_create_typedef, &retval, name);
  return retval;
}

//--------------------------------------------------------------------------
inline bool get_type(uval_t id, tinfo_t *tif, type_source_t guess)
{
  return (uchar)(size_t)HEXDSP(hx_get_type, id, tif, guess) != 0;
}

//--------------------------------------------------------------------------
inline bool set_type(uval_t id, const tinfo_t &tif, type_source_t source, bool force)
{
  return (uchar)(size_t)HEXDSP(hx_set_type, id, &tif, source, force) != 0;
}

//--------------------------------------------------------------------------
inline const char *vdloc_t::dstr(int width) const
{
  return (const char *)HEXDSP(hx_vdloc_t_dstr, this, width);
}

//--------------------------------------------------------------------------
inline int vdloc_t::compare(const vdloc_t &r) const
{
  return (int)(size_t)HEXDSP(hx_vdloc_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool vdloc_t::is_aliasable(const mba_t *mb, int size) const
{
  return (uchar)(size_t)HEXDSP(hx_vdloc_t_is_aliasable, this, mb, size) != 0;
}

//--------------------------------------------------------------------------
inline void print_vdloc(qstring *vout, const vdloc_t &loc, int nbytes)
{
  HEXDSP(hx_print_vdloc, vout, &loc, nbytes);
}

//--------------------------------------------------------------------------
inline bool arglocs_overlap(const vdloc_t &loc1, size_t w1, const vdloc_t &loc2, size_t w2)
{
  return (uchar)(size_t)HEXDSP(hx_arglocs_overlap, &loc1, w1, &loc2, w2) != 0;
}

//--------------------------------------------------------------------------
inline int lvar_locator_t::compare(const lvar_locator_t &r) const
{
  return (int)(size_t)HEXDSP(hx_lvar_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline const char *lvar_locator_t::dstr() const
{
  return (const char *)HEXDSP(hx_lvar_locator_t_dstr, this);
}

//--------------------------------------------------------------------------
inline const char *lvar_t::dstr() const
{
  return (const char *)HEXDSP(hx_lvar_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool lvar_t::is_promoted_arg() const
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_is_promoted_arg, this) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::accepts_type(const tinfo_t &t, bool may_change_thisarg)
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_accepts_type, this, &t, may_change_thisarg) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::set_lvar_type(const tinfo_t &t, bool may_fail)
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_set_lvar_type, this, &t, may_fail) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::set_width(int w, int svw_flags)
{
  return (uchar)(size_t)HEXDSP(hx_lvar_t_set_width, this, w, svw_flags) != 0;
}

//--------------------------------------------------------------------------
inline void lvar_t::append_list(const mba_t *mba, mlist_t *lst, bool pad_if_scattered) const
{
  HEXDSP(hx_lvar_t_append_list, this, mba, lst, pad_if_scattered);
}

//--------------------------------------------------------------------------
inline int lvars_t::find_stkvar(sval_t spoff, int width)
{
  return (int)(size_t)HEXDSP(hx_lvars_t_find_stkvar, this, spoff, width);
}

//--------------------------------------------------------------------------
inline lvar_t *lvars_t::find(const lvar_locator_t &ll)
{
  return (lvar_t *)HEXDSP(hx_lvars_t_find, this, &ll);
}

//--------------------------------------------------------------------------
inline int lvars_t::find_lvar(const vdloc_t &location, int width, int defblk) const
{
  return (int)(size_t)HEXDSP(hx_lvars_t_find_lvar, this, &location, width, defblk);
}

//--------------------------------------------------------------------------
inline bool restore_user_lvar_settings(lvar_uservec_t *lvinf, ea_t func_ea)
{
  return (uchar)(size_t)HEXDSP(hx_restore_user_lvar_settings, lvinf, func_ea) != 0;
}

//--------------------------------------------------------------------------
inline void save_user_lvar_settings(ea_t func_ea, const lvar_uservec_t &lvinf)
{
  HEXDSP(hx_save_user_lvar_settings, func_ea, &lvinf);
}

//--------------------------------------------------------------------------
inline bool modify_user_lvars(ea_t entry_ea, user_lvar_modifier_t &mlv)
{
  return (uchar)(size_t)HEXDSP(hx_modify_user_lvars, entry_ea, &mlv) != 0;
}

//--------------------------------------------------------------------------
inline bool modify_user_lvar_info(ea_t func_ea, uint mli_flags, const lvar_saved_info_t &info)
{
  return (uchar)(size_t)HEXDSP(hx_modify_user_lvar_info, func_ea, mli_flags, &info) != 0;
}

//--------------------------------------------------------------------------
inline bool locate_lvar(lvar_locator_t *out, ea_t func_ea, const char *varname)
{
  return (uchar)(size_t)HEXDSP(hx_locate_lvar, out, func_ea, varname) != 0;
}

//--------------------------------------------------------------------------
inline bool restore_user_defined_calls(udcall_map_t *udcalls, ea_t func_ea)
{
  return (uchar)(size_t)HEXDSP(hx_restore_user_defined_calls, udcalls, func_ea) != 0;
}

//--------------------------------------------------------------------------
inline void save_user_defined_calls(ea_t func_ea, const udcall_map_t &udcalls)
{
  HEXDSP(hx_save_user_defined_calls, func_ea, &udcalls);
}

//--------------------------------------------------------------------------
inline bool parse_user_call(udcall_t *udc, const char *decl, bool silent)
{
  return (uchar)(size_t)HEXDSP(hx_parse_user_call, udc, decl, silent) != 0;
}

//--------------------------------------------------------------------------
inline merror_t convert_to_user_call(const udcall_t &udc, codegen_t &cdg)
{
  return (merror_t)(size_t)HEXDSP(hx_convert_to_user_call, &udc, &cdg);
}

//--------------------------------------------------------------------------
inline bool install_microcode_filter(microcode_filter_t *filter, bool install)
{
  auto hrdsp = HEXDSP;
  return hrdsp != nullptr && (uchar)(size_t)hrdsp(hx_install_microcode_filter, filter, install) != 0;
}

//--------------------------------------------------------------------------
inline void udc_filter_t::cleanup()
{
  HEXDSP(hx_udc_filter_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline bool udc_filter_t::init(const char *decl)
{
  return (uchar)(size_t)HEXDSP(hx_udc_filter_t_init, this, decl) != 0;
}

//--------------------------------------------------------------------------
inline merror_t udc_filter_t::apply(codegen_t &cdg)
{
  return (merror_t)(size_t)HEXDSP(hx_udc_filter_t_apply, this, &cdg);
}

//--------------------------------------------------------------------------
inline bitset_t::bitset_t(const bitset_t &m)
{
  HEXDSP(hx_bitset_t_bitset_t, this, &m);
}

//--------------------------------------------------------------------------
inline bitset_t &bitset_t::copy(const bitset_t &m)
{
  return *(bitset_t *)HEXDSP(hx_bitset_t_copy, this, &m);
}

//--------------------------------------------------------------------------
inline bool bitset_t::add(int bit)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_add, this, bit) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::add(int bit, int width)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_add_, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::add(const bitset_t &ml)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_add__, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::sub(int bit)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_sub, this, bit) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::sub(int bit, int width)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_sub_, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::sub(const bitset_t &ml)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_sub__, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::cut_at(int maxbit)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_cut_at, this, maxbit) != 0;
}

//--------------------------------------------------------------------------
inline void bitset_t::shift_down(int shift)
{
  HEXDSP(hx_bitset_t_shift_down, this, shift);
}

//--------------------------------------------------------------------------
inline bool bitset_t::has(int bit) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has, this, bit) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::has_all(int bit, int width) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has_all, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::has_any(int bit, int width) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has_any, this, bit, width) != 0;
}

//--------------------------------------------------------------------------
inline const char *bitset_t::dstr() const
{
  return (const char *)HEXDSP(hx_bitset_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool bitset_t::empty() const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_empty, this) != 0;
}

//--------------------------------------------------------------------------
inline int bitset_t::count() const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_count, this);
}

//--------------------------------------------------------------------------
inline int bitset_t::count(int bit) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_count_, this, bit);
}

//--------------------------------------------------------------------------
inline int bitset_t::last() const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_last, this);
}

//--------------------------------------------------------------------------
inline void bitset_t::fill_with_ones(int maxbit)
{
  HEXDSP(hx_bitset_t_fill_with_ones, this, maxbit);
}

//--------------------------------------------------------------------------
inline bool bitset_t::fill_gaps(int total_nbits)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_fill_gaps, this, total_nbits) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::has_common(const bitset_t &ml) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_has_common, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::intersect(const bitset_t &ml)
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_intersect, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline bool bitset_t::is_subset_of(const bitset_t &ml) const
{
  return (uchar)(size_t)HEXDSP(hx_bitset_t_is_subset_of, this, &ml) != 0;
}

//--------------------------------------------------------------------------
inline int bitset_t::compare(const bitset_t &r) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int bitset_t::goup(int reg) const
{
  return (int)(size_t)HEXDSP(hx_bitset_t_goup, this, reg);
}

//--------------------------------------------------------------------------
inline const char *ivl_t::dstr() const
{
  return (const char *)HEXDSP(hx_ivl_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int ivl_t::compare(const ivl_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ivl_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool ivlset_t::add(const ivl_t &ivl)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_add, this, &ivl) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::add(const ivlset_t &ivs)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_add_, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::addmasked(const ivlset_t &ivs, const ivl_t &mask)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_addmasked, this, &ivs, &mask) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::sub(const ivl_t &ivl)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_sub, this, &ivl) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::sub(const ivlset_t &ivs)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_sub_, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline asize_t ivlset_t::count() const
{
  asize_t retval;
  HEXDSP(hx_ivlset_t_count, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::has_common(const ivlset_t &ivs) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_has_common, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::has_common(const ivl_t &ivl, bool strict) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_has_common_, this, &ivl, strict) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::contains(uint64 off) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_contains, this, off) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::includes(const ivlset_t &ivs) const
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_includes, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline bool ivlset_t::intersect(const ivlset_t &ivs)
{
  return (uchar)(size_t)HEXDSP(hx_ivlset_t_intersect, this, &ivs) != 0;
}

//--------------------------------------------------------------------------
inline int ivlset_t::compare(const ivlset_t &r) const
{
  return (int)(size_t)HEXDSP(hx_ivlset_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void ivlset_t::print(qstring *vout) const
{
  HEXDSP(hx_ivlset_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *ivlset_t::dstr() const
{
  return (const char *)HEXDSP(hx_ivlset_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void rlist_t::print(qstring *vout) const
{
  HEXDSP(hx_rlist_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *rlist_t::dstr() const
{
  return (const char *)HEXDSP(hx_rlist_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool mlist_t::addmem(ea_t ea, asize_t size)
{
  return (uchar)(size_t)HEXDSP(hx_mlist_t_addmem, this, ea, size) != 0;
}

//--------------------------------------------------------------------------
inline void mlist_t::print(qstring *vout) const
{
  HEXDSP(hx_mlist_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *mlist_t::dstr() const
{
  return (const char *)HEXDSP(hx_mlist_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int mlist_t::compare(const mlist_t &r) const
{
  return (int)(size_t)HEXDSP(hx_mlist_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline const mlist_t &get_temp_regs()
{
  return *(const mlist_t *)HEXDSP(hx_get_temp_regs);
}

//--------------------------------------------------------------------------
inline bool is_kreg(mreg_t r)
{
  return (uchar)(size_t)HEXDSP(hx_is_kreg, r) != 0;
}

//--------------------------------------------------------------------------
inline mreg_t reg2mreg(int reg)
{
  return (mreg_t)(size_t)HEXDSP(hx_reg2mreg, reg);
}

//--------------------------------------------------------------------------
inline int mreg2reg(mreg_t reg, int width)
{
  return (int)(size_t)HEXDSP(hx_mreg2reg, reg, width);
}

//--------------------------------------------------------------------------
inline int get_mreg_name(qstring *out, mreg_t reg, int width, void *ud)
{
  return (int)(size_t)HEXDSP(hx_get_mreg_name, out, reg, width, ud);
}

//--------------------------------------------------------------------------
inline void install_optinsn_handler(optinsn_t *opt)
{
  HEXDSP(hx_install_optinsn_handler, opt);
}

//--------------------------------------------------------------------------
inline bool remove_optinsn_handler(optinsn_t *opt)
{
  auto hrdsp = HEXDSP;
  return hrdsp != nullptr && (uchar)(size_t)hrdsp(hx_remove_optinsn_handler, opt) != 0;
}

//--------------------------------------------------------------------------
inline void install_optblock_handler(optblock_t *opt)
{
  HEXDSP(hx_install_optblock_handler, opt);
}

//--------------------------------------------------------------------------
inline bool remove_optblock_handler(optblock_t *opt)
{
  auto hrdsp = HEXDSP;
  return hrdsp != nullptr && (uchar)(size_t)hrdsp(hx_remove_optblock_handler, opt) != 0;
}

//--------------------------------------------------------------------------
inline void simple_graph_t::compute_dominators(array_of_node_bitset_t &domin, bool post) const
{
  HEXDSP(hx_simple_graph_t_compute_dominators, this, &domin, post);
}

//--------------------------------------------------------------------------
inline void simple_graph_t::compute_immediate_dominators(const array_of_node_bitset_t &domin, intvec_t &idomin, bool post) const
{
  HEXDSP(hx_simple_graph_t_compute_immediate_dominators, this, &domin, &idomin, post);
}

//--------------------------------------------------------------------------
inline int simple_graph_t::depth_first_preorder(node_ordering_t *pre) const
{
  return (int)(size_t)HEXDSP(hx_simple_graph_t_depth_first_preorder, this, pre);
}

//--------------------------------------------------------------------------
inline int simple_graph_t::depth_first_postorder(node_ordering_t *post) const
{
  return (int)(size_t)HEXDSP(hx_simple_graph_t_depth_first_postorder, this, post);
}

//--------------------------------------------------------------------------
inline int simple_graph_t::goup(int node) const
{
  return (int)(size_t)HEXDSP(hx_simple_graph_t_goup, this, node);
}

//--------------------------------------------------------------------------
inline int lvar_ref_t::compare(const lvar_ref_t &r) const
{
  return (int)(size_t)HEXDSP(hx_lvar_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline lvar_t &lvar_ref_t::var() const
{
  return *(lvar_t *)HEXDSP(hx_lvar_ref_t_var, this);
}

//--------------------------------------------------------------------------
inline int stkvar_ref_t::compare(const stkvar_ref_t &r) const
{
  return (int)(size_t)HEXDSP(hx_stkvar_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline ssize_t stkvar_ref_t::get_stkvar(udm_t *udm, uval_t *p_idaoff) const
{
  return (ssize_t)HEXDSP(hx_stkvar_ref_t_get_stkvar, this, udm, p_idaoff);
}

//--------------------------------------------------------------------------
inline void fnumber_t::print(qstring *vout) const
{
  HEXDSP(hx_fnumber_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *fnumber_t::dstr() const
{
  return (const char *)HEXDSP(hx_fnumber_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void mop_t::copy(const mop_t &rop)
{
  HEXDSP(hx_mop_t_copy, this, &rop);
}

//--------------------------------------------------------------------------
inline mop_t &mop_t::assign(const mop_t &rop)
{
  return *(mop_t *)HEXDSP(hx_mop_t_assign, this, &rop);
}

//--------------------------------------------------------------------------
inline void mop_t::swap(mop_t &rop)
{
  HEXDSP(hx_mop_t_swap, this, &rop);
}

//--------------------------------------------------------------------------
inline void mop_t::erase()
{
  HEXDSP(hx_mop_t_erase, this);
}

//--------------------------------------------------------------------------
inline void mop_t::print(qstring *vout, int shins_flags) const
{
  HEXDSP(hx_mop_t_print, this, vout, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *mop_t::dstr() const
{
  return (const char *)HEXDSP(hx_mop_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool mop_t::create_from_mlist(mba_t *mba, const mlist_t &lst, sval_t fullsize)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_create_from_mlist, this, mba, &lst, fullsize) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::create_from_ivlset(mba_t *mba, const ivlset_t &ivs, sval_t fullsize)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_create_from_ivlset, this, mba, &ivs, fullsize) != 0;
}

//--------------------------------------------------------------------------
inline void mop_t::create_from_vdloc(mba_t *mba, const vdloc_t &loc, int _size)
{
  HEXDSP(hx_mop_t_create_from_vdloc, this, mba, &loc, _size);
}

//--------------------------------------------------------------------------
inline void mop_t::create_from_scattered_vdloc(mba_t *mba, const char *name, tinfo_t type, const vdloc_t &loc)
{
  HEXDSP(hx_mop_t_create_from_scattered_vdloc, this, mba, name, &type, &loc);
}

//--------------------------------------------------------------------------
inline void mop_t::create_from_insn(const minsn_t *m)
{
  HEXDSP(hx_mop_t_create_from_insn, this, m);
}

//--------------------------------------------------------------------------
inline void mop_t::make_number(uint64 _value, int _size, ea_t _ea, int opnum)
{
  HEXDSP(hx_mop_t_make_number, this, _value, _size, _ea, opnum);
}

//--------------------------------------------------------------------------
inline bool mop_t::make_fpnum(const void *bytes, size_t _size)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_fpnum, this, bytes, _size) != 0;
}

//--------------------------------------------------------------------------
inline void mop_t::_make_gvar(ea_t ea)
{
  HEXDSP(hx_mop_t__make_gvar, this, ea);
}

//--------------------------------------------------------------------------
inline void mop_t::make_gvar(ea_t ea)
{
  HEXDSP(hx_mop_t_make_gvar, this, ea);
}

//--------------------------------------------------------------------------
inline void mop_t::make_reg_pair(int loreg, int hireg, int halfsize)
{
  HEXDSP(hx_mop_t_make_reg_pair, this, loreg, hireg, halfsize);
}

//--------------------------------------------------------------------------
inline void mop_t::make_helper(const char *name)
{
  HEXDSP(hx_mop_t_make_helper, this, name);
}

//--------------------------------------------------------------------------
inline bool mop_t::is_bit_reg(mreg_t reg)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_bit_reg, reg) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::may_use_aliased_memory() const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_may_use_aliased_memory, this) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::is01() const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is01, this) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::is_sign_extended_from(int nbytes) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_sign_extended_from, this, nbytes) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::is_zero_extended_from(int nbytes) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_zero_extended_from, this, nbytes) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::equal_mops(const mop_t &rop, int eqflags) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_equal_mops, this, &rop, eqflags) != 0;
}

//--------------------------------------------------------------------------
inline int mop_t::lexcompare(const mop_t &rop) const
{
  return (int)(size_t)HEXDSP(hx_mop_t_lexcompare, this, &rop);
}

//--------------------------------------------------------------------------
inline int mop_t::for_all_ops(mop_visitor_t &mv, const tinfo_t *type, bool is_target)
{
  return (int)(size_t)HEXDSP(hx_mop_t_for_all_ops, this, &mv, type, is_target);
}

//--------------------------------------------------------------------------
inline int mop_t::for_all_scattered_submops(scif_visitor_t &sv) const
{
  return (int)(size_t)HEXDSP(hx_mop_t_for_all_scattered_submops, this, &sv);
}

//--------------------------------------------------------------------------
inline bool mop_t::is_constant(uint64 *out, bool is_signed) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_is_constant, this, out, is_signed) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::get_stkoff(sval_t *p_vdoff) const
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_get_stkoff, this, p_vdoff) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_low_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_low_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_high_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_high_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_first_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_first_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::make_second_half(int width)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_make_second_half, this, width) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::shift_mop(int offset)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_shift_mop, this, offset) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::change_size(int nsize, side_effect_t sideff)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_change_size, this, nsize, sideff) != 0;
}

//--------------------------------------------------------------------------
inline bool mop_t::preserve_side_effects(mblock_t *blk, minsn_t *top, bool *moved_calls)
{
  return (uchar)(size_t)HEXDSP(hx_mop_t_preserve_side_effects, this, blk, top, moved_calls) != 0;
}

//--------------------------------------------------------------------------
inline void mop_t::apply_ld_mcode(mcode_t mcode, ea_t ea, int newsize)
{
  HEXDSP(hx_mop_t_apply_ld_mcode, this, mcode, ea, newsize);
}

//--------------------------------------------------------------------------
inline void mcallarg_t::print(qstring *vout, int shins_flags) const
{
  HEXDSP(hx_mcallarg_t_print, this, vout, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *mcallarg_t::dstr() const
{
  return (const char *)HEXDSP(hx_mcallarg_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void mcallarg_t::set_regarg(mreg_t mr, int sz, const tinfo_t &tif)
{
  HEXDSP(hx_mcallarg_t_set_regarg, this, mr, sz, &tif);
}

//--------------------------------------------------------------------------
inline int mcallinfo_t::lexcompare(const mcallinfo_t &f) const
{
  return (int)(size_t)HEXDSP(hx_mcallinfo_t_lexcompare, this, &f);
}

//--------------------------------------------------------------------------
inline bool mcallinfo_t::set_type(const tinfo_t &type)
{
  return (uchar)(size_t)HEXDSP(hx_mcallinfo_t_set_type, this, &type) != 0;
}

//--------------------------------------------------------------------------
inline tinfo_t mcallinfo_t::get_type() const
{
  tinfo_t retval;
  HEXDSP(hx_mcallinfo_t_get_type, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline void mcallinfo_t::print(qstring *vout, int size, int shins_flags) const
{
  HEXDSP(hx_mcallinfo_t_print, this, vout, size, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *mcallinfo_t::dstr() const
{
  return (const char *)HEXDSP(hx_mcallinfo_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int mcases_t::compare(const mcases_t &r) const
{
  return (int)(size_t)HEXDSP(hx_mcases_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void mcases_t::print(qstring *vout) const
{
  HEXDSP(hx_mcases_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *mcases_t::dstr() const
{
  return (const char *)HEXDSP(hx_mcases_t_dstr, this);
}

//--------------------------------------------------------------------------
inline bool vivl_t::extend_to_cover(const vivl_t &r)
{
  return (uchar)(size_t)HEXDSP(hx_vivl_t_extend_to_cover, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline uval_t vivl_t::intersect(const vivl_t &r)
{
  uval_t retval;
  HEXDSP(hx_vivl_t_intersect, &retval, this, &r);
  return retval;
}

//--------------------------------------------------------------------------
inline void vivl_t::print(qstring *vout) const
{
  HEXDSP(hx_vivl_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *vivl_t::dstr() const
{
  return (const char *)HEXDSP(hx_vivl_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void chain_t::print(qstring *vout) const
{
  HEXDSP(hx_chain_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *chain_t::dstr() const
{
  return (const char *)HEXDSP(hx_chain_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void chain_t::append_list(const mba_t *mba, mlist_t *list) const
{
  HEXDSP(hx_chain_t_append_list, this, mba, list);
}

//--------------------------------------------------------------------------
inline const chain_t *block_chains_t::get_chain(const chain_t &ch) const
{
  return (const chain_t *)HEXDSP(hx_block_chains_t_get_chain, this, &ch);
}

//--------------------------------------------------------------------------
inline void block_chains_t::print(qstring *vout) const
{
  HEXDSP(hx_block_chains_t_print, this, vout);
}

//--------------------------------------------------------------------------
inline const char *block_chains_t::dstr() const
{
  return (const char *)HEXDSP(hx_block_chains_t_dstr, this);
}

//--------------------------------------------------------------------------
inline int graph_chains_t::for_all_chains(chain_visitor_t &cv, int gca_flags)
{
  return (int)(size_t)HEXDSP(hx_graph_chains_t_for_all_chains, this, &cv, gca_flags);
}

//--------------------------------------------------------------------------
inline void graph_chains_t::release()
{
  HEXDSP(hx_graph_chains_t_release, this);
}

//--------------------------------------------------------------------------
inline void minsn_t::init(ea_t _ea)
{
  HEXDSP(hx_minsn_t_init, this, _ea);
}

//--------------------------------------------------------------------------
inline void minsn_t::copy(const minsn_t &m)
{
  HEXDSP(hx_minsn_t_copy, this, &m);
}

//--------------------------------------------------------------------------
inline void minsn_t::set_combined()
{
  HEXDSP(hx_minsn_t_set_combined, this);
}

//--------------------------------------------------------------------------
inline void minsn_t::swap(minsn_t &m)
{
  HEXDSP(hx_minsn_t_swap, this, &m);
}

//--------------------------------------------------------------------------
inline void minsn_t::print(qstring *vout, int shins_flags) const
{
  HEXDSP(hx_minsn_t_print, this, vout, shins_flags);
}

//--------------------------------------------------------------------------
inline const char *minsn_t::dstr() const
{
  return (const char *)HEXDSP(hx_minsn_t_dstr, this);
}

//--------------------------------------------------------------------------
inline void minsn_t::setaddr(ea_t new_ea)
{
  HEXDSP(hx_minsn_t_setaddr, this, new_ea);
}

//--------------------------------------------------------------------------
inline int minsn_t::optimize_subtree(mblock_t *blk, minsn_t *top, minsn_t *parent, ea_t *converted_call, int optflags)
{
  return (int)(size_t)HEXDSP(hx_minsn_t_optimize_subtree, this, blk, top, parent, converted_call, optflags);
}

//--------------------------------------------------------------------------
inline int minsn_t::for_all_ops(mop_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_minsn_t_for_all_ops, this, &mv);
}

//--------------------------------------------------------------------------
inline int minsn_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_minsn_t_for_all_insns, this, &mv);
}

//--------------------------------------------------------------------------
inline void minsn_t::_make_nop()
{
  HEXDSP(hx_minsn_t__make_nop, this);
}

//--------------------------------------------------------------------------
inline bool minsn_t::equal_insns(const minsn_t &m, int eqflags) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_equal_insns, this, &m, eqflags) != 0;
}

//--------------------------------------------------------------------------
inline int minsn_t::lexcompare(const minsn_t &ri) const
{
  return (int)(size_t)HEXDSP(hx_minsn_t_lexcompare, this, &ri);
}

//--------------------------------------------------------------------------
inline bool minsn_t::is_noret_call(int flags)
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_is_noret_call, this, flags) != 0;
}

//--------------------------------------------------------------------------
inline bool minsn_t::is_helper(const char *name) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_is_helper, this, name) != 0;
}

//--------------------------------------------------------------------------
inline minsn_t *minsn_t::find_call(bool with_helpers) const
{
  return (minsn_t *)HEXDSP(hx_minsn_t_find_call, this, with_helpers);
}

//--------------------------------------------------------------------------
inline bool minsn_t::has_side_effects(bool include_ldx_and_divs) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_has_side_effects, this, include_ldx_and_divs) != 0;
}

//--------------------------------------------------------------------------
inline minsn_t *minsn_t::find_opcode(mcode_t mcode)
{
  return (minsn_t *)HEXDSP(hx_minsn_t_find_opcode, this, mcode);
}

//--------------------------------------------------------------------------
inline const minsn_t *minsn_t::find_ins_op(const mop_t **other, mcode_t op) const
{
  return (const minsn_t *)HEXDSP(hx_minsn_t_find_ins_op, this, other, op);
}

//--------------------------------------------------------------------------
inline const mop_t *minsn_t::find_num_op(const mop_t **other) const
{
  return (const mop_t *)HEXDSP(hx_minsn_t_find_num_op, this, other);
}

//--------------------------------------------------------------------------
inline bool minsn_t::modifies_d() const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_modifies_d, this) != 0;
}

//--------------------------------------------------------------------------
inline bool minsn_t::is_between(const minsn_t *m1, const minsn_t *m2) const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_is_between, this, m1, m2) != 0;
}

//--------------------------------------------------------------------------
inline bool minsn_t::may_use_aliased_memory() const
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_may_use_aliased_memory, this) != 0;
}

//--------------------------------------------------------------------------
inline int minsn_t::serialize(bytevec_t *b) const
{
  return (int)(size_t)HEXDSP(hx_minsn_t_serialize, this, b);
}

//--------------------------------------------------------------------------
inline bool minsn_t::deserialize(const uchar *bytes, size_t nbytes, int format_version)
{
  return (uchar)(size_t)HEXDSP(hx_minsn_t_deserialize, this, bytes, nbytes, format_version) != 0;
}

//--------------------------------------------------------------------------
inline const minsn_t *getf_reginsn(const minsn_t *ins)
{
  return (const minsn_t *)HEXDSP(hx_getf_reginsn, ins);
}

//--------------------------------------------------------------------------
inline const minsn_t *getb_reginsn(const minsn_t *ins)
{
  return (const minsn_t *)HEXDSP(hx_getb_reginsn, ins);
}

//--------------------------------------------------------------------------
inline bool int64_emulator_t::_mop_value(intval64_t *out, const mop_t &mop, vd_failure_t *vf)
{
  return (uchar)(size_t)HEXDSP(hx_int64_emulator_t__mop_value, this, out, &mop, vf) != 0;
}

//--------------------------------------------------------------------------
inline bool int64_emulator_t::_minsn_value(intval64_t *out, const minsn_t &insn, vd_failure_t *vf)
{
  return (uchar)(size_t)HEXDSP(hx_int64_emulator_t__minsn_value, this, out, &insn, vf) != 0;
}

//--------------------------------------------------------------------------
inline void mblock_t::init()
{
  HEXDSP(hx_mblock_t_init, this);
}

//--------------------------------------------------------------------------
inline void mblock_t::print(vd_printer_t &vp) const
{
  HEXDSP(hx_mblock_t_print, this, &vp);
}

//--------------------------------------------------------------------------
inline void mblock_t::dump() const
{
  HEXDSP(hx_mblock_t_dump, this);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(2, 0) void mblock_t::vdump_block(const char *title, va_list va) const
{
  HEXDSP(hx_mblock_t_vdump_block, this, title, va);
}

//--------------------------------------------------------------------------
inline void mblock_t::verify_insn(const minsn_t *m) const
{
  HEXDSP(hx_mblock_t_verify_insn, this, m);
}

//--------------------------------------------------------------------------
inline minsn_t *mblock_t::insert_into_block(minsn_t *nm, minsn_t *om)
{
  return (minsn_t *)HEXDSP(hx_mblock_t_insert_into_block, this, nm, om);
}

//--------------------------------------------------------------------------
inline minsn_t *mblock_t::remove_from_block(minsn_t *m)
{
  return (minsn_t *)HEXDSP(hx_mblock_t_remove_from_block, this, m);
}

//--------------------------------------------------------------------------
inline int mblock_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_for_all_insns, this, &mv);
}

//--------------------------------------------------------------------------
inline int mblock_t::for_all_ops(mop_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_for_all_ops, this, &mv);
}

//--------------------------------------------------------------------------
inline int mblock_t::for_all_uses(mlist_t *list, minsn_t *i1, minsn_t *i2, mlist_mop_visitor_t &mmv)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_for_all_uses, this, list, i1, i2, &mmv);
}

//--------------------------------------------------------------------------
inline int mblock_t::optimize_insn(minsn_t *m, int optflags)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_optimize_insn, this, m, optflags);
}

//--------------------------------------------------------------------------
inline int mblock_t::optimize_block()
{
  return (int)(size_t)HEXDSP(hx_mblock_t_optimize_block, this);
}

//--------------------------------------------------------------------------
inline int mblock_t::build_lists(bool kill_deads)
{
  return (int)(size_t)HEXDSP(hx_mblock_t_build_lists, this, kill_deads);
}

//--------------------------------------------------------------------------
inline int mblock_t::optimize_useless_jump()
{
  return (int)(size_t)HEXDSP(hx_mblock_t_optimize_useless_jump, this);
}

//--------------------------------------------------------------------------
inline void mblock_t::append_use_list(mlist_t *list, const mop_t &op, maymust_t maymust, bitrange_t mask) const
{
  HEXDSP(hx_mblock_t_append_use_list, this, list, &op, maymust, &mask);
}

//--------------------------------------------------------------------------
inline void mblock_t::append_def_list(mlist_t *list, const mop_t &op, maymust_t maymust) const
{
  HEXDSP(hx_mblock_t_append_def_list, this, list, &op, maymust);
}

//--------------------------------------------------------------------------
inline mlist_t mblock_t::build_use_list(const minsn_t &ins, maymust_t maymust) const
{
  mlist_t retval;
  HEXDSP(hx_mblock_t_build_use_list, &retval, this, &ins, maymust);
  return retval;
}

//--------------------------------------------------------------------------
inline mlist_t mblock_t::build_def_list(const minsn_t &ins, maymust_t maymust) const
{
  mlist_t retval;
  HEXDSP(hx_mblock_t_build_def_list, &retval, this, &ins, maymust);
  return retval;
}

//--------------------------------------------------------------------------
inline const minsn_t *mblock_t::find_first_use(mlist_t *list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust) const
{
  return (const minsn_t *)HEXDSP(hx_mblock_t_find_first_use, this, list, i1, i2, maymust);
}

//--------------------------------------------------------------------------
inline const minsn_t *mblock_t::find_redefinition(const mlist_t &list, const minsn_t *i1, const minsn_t *i2, maymust_t maymust) const
{
  return (const minsn_t *)HEXDSP(hx_mblock_t_find_redefinition, this, &list, i1, i2, maymust);
}

//--------------------------------------------------------------------------
inline bool mblock_t::is_rhs_redefined(const minsn_t *ins, const minsn_t *i1, const minsn_t *i2) const
{
  return (uchar)(size_t)HEXDSP(hx_mblock_t_is_rhs_redefined, this, ins, i1, i2) != 0;
}

//--------------------------------------------------------------------------
inline minsn_t *mblock_t::find_access(const mop_t &op, minsn_t **parent, const minsn_t *mend, int fdflags) const
{
  return (minsn_t *)HEXDSP(hx_mblock_t_find_access, this, &op, parent, mend, fdflags);
}

//--------------------------------------------------------------------------
inline bool mblock_t::get_valranges(valrng_t *res, const vivl_t &vivl, int vrflags) const
{
  return (uchar)(size_t)HEXDSP(hx_mblock_t_get_valranges, this, res, &vivl, vrflags) != 0;
}

//--------------------------------------------------------------------------
inline bool mblock_t::get_valranges(valrng_t *res, const vivl_t &vivl, const minsn_t *m, int vrflags) const
{
  return (uchar)(size_t)HEXDSP(hx_mblock_t_get_valranges_, this, res, &vivl, m, vrflags) != 0;
}

//--------------------------------------------------------------------------
inline size_t mblock_t::get_reginsn_qty() const
{
  return (size_t)HEXDSP(hx_mblock_t_get_reginsn_qty, this);
}

//--------------------------------------------------------------------------
inline sval_t mba_t::stkoff_vd2ida(sval_t off) const
{
  sval_t retval;
  HEXDSP(hx_mba_t_stkoff_vd2ida, &retval, this, off);
  return retval;
}

//--------------------------------------------------------------------------
inline sval_t mba_t::stkoff_ida2vd(sval_t off) const
{
  sval_t retval;
  HEXDSP(hx_mba_t_stkoff_ida2vd, &retval, this, off);
  return retval;
}

//--------------------------------------------------------------------------
inline vdloc_t mba_t::idaloc2vd(const argloc_t &loc, int width, sval_t spd)
{
  vdloc_t retval;
  HEXDSP(hx_mba_t_idaloc2vd, &retval, &loc, width, spd);
  return retval;
}

//--------------------------------------------------------------------------
inline vdloc_t mba_t::idaloc2vd(const argloc_t &loc, int width) const
{
  vdloc_t retval;
  HEXDSP(hx_mba_t_idaloc2vd_, &retval, this, &loc, width);
  return retval;
}

//--------------------------------------------------------------------------
inline argloc_t mba_t::vd2idaloc(const vdloc_t &loc, int width, sval_t spd)
{
  argloc_t retval;
  HEXDSP(hx_mba_t_vd2idaloc, &retval, &loc, width, spd);
  return retval;
}

//--------------------------------------------------------------------------
inline argloc_t mba_t::vd2idaloc(const vdloc_t &loc, int width) const
{
  argloc_t retval;
  HEXDSP(hx_mba_t_vd2idaloc_, &retval, this, &loc, width);
  return retval;
}

//--------------------------------------------------------------------------
inline void mba_t::term()
{
  HEXDSP(hx_mba_t_term, this);
}

//--------------------------------------------------------------------------
inline func_t *mba_t::get_curfunc() const
{
  return (func_t *)HEXDSP(hx_mba_t_get_curfunc, this);
}

//--------------------------------------------------------------------------
inline merror_t mba_t::set_maturity(mba_maturity_t mat)
{
  return (merror_t)(size_t)HEXDSP(hx_mba_t_set_maturity, this, mat);
}

//--------------------------------------------------------------------------
inline int mba_t::optimize_local(int locopt_bits)
{
  return (int)(size_t)HEXDSP(hx_mba_t_optimize_local, this, locopt_bits);
}

//--------------------------------------------------------------------------
inline merror_t mba_t::build_graph()
{
  return (merror_t)(size_t)HEXDSP(hx_mba_t_build_graph, this);
}

//--------------------------------------------------------------------------
inline mbl_graph_t *mba_t::get_graph()
{
  return (mbl_graph_t *)HEXDSP(hx_mba_t_get_graph, this);
}

//--------------------------------------------------------------------------
inline int mba_t::analyze_calls(int acflags)
{
  return (int)(size_t)HEXDSP(hx_mba_t_analyze_calls, this, acflags);
}

//--------------------------------------------------------------------------
inline merror_t mba_t::optimize_global()
{
  return (merror_t)(size_t)HEXDSP(hx_mba_t_optimize_global, this);
}

//--------------------------------------------------------------------------
inline void mba_t::alloc_lvars()
{
  HEXDSP(hx_mba_t_alloc_lvars, this);
}

//--------------------------------------------------------------------------
inline void mba_t::dump() const
{
  HEXDSP(hx_mba_t_dump, this);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) void mba_t::vdump_mba(bool _verify, const char *title, va_list va) const
{
  HEXDSP(hx_mba_t_vdump_mba, this, _verify, title, va);
}

//--------------------------------------------------------------------------
inline void mba_t::print(vd_printer_t &vp) const
{
  HEXDSP(hx_mba_t_print, this, &vp);
}

//--------------------------------------------------------------------------
inline void mba_t::verify(bool always) const
{
  HEXDSP(hx_mba_t_verify, this, always);
}

//--------------------------------------------------------------------------
inline void mba_t::mark_chains_dirty()
{
  HEXDSP(hx_mba_t_mark_chains_dirty, this);
}

//--------------------------------------------------------------------------
inline mblock_t *mba_t::insert_block(int bblk)
{
  return (mblock_t *)HEXDSP(hx_mba_t_insert_block, this, bblk);
}

//--------------------------------------------------------------------------
inline mblock_t *mba_t::split_block(mblock_t *blk, minsn_t *start_insn)
{
  return (mblock_t *)HEXDSP(hx_mba_t_split_block, this, blk, start_insn);
}

//--------------------------------------------------------------------------
inline bool mba_t::remove_block(mblock_t *blk)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_remove_block, this, blk) != 0;
}

//--------------------------------------------------------------------------
inline bool mba_t::remove_blocks(int start_blk, int end_blk)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_remove_blocks, this, start_blk, end_blk) != 0;
}

//--------------------------------------------------------------------------
inline mblock_t *mba_t::copy_block(mblock_t *blk, int new_serial, int cpblk_flags)
{
  return (mblock_t *)HEXDSP(hx_mba_t_copy_block, this, blk, new_serial, cpblk_flags);
}

//--------------------------------------------------------------------------
inline bool mba_t::remove_empty_and_unreachable_blocks()
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_remove_empty_and_unreachable_blocks, this) != 0;
}

//--------------------------------------------------------------------------
inline bool mba_t::merge_blocks()
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_merge_blocks, this) != 0;
}

//--------------------------------------------------------------------------
inline int mba_t::for_all_ops(mop_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_ops, this, &mv);
}

//--------------------------------------------------------------------------
inline int mba_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_insns, this, &mv);
}

//--------------------------------------------------------------------------
inline int mba_t::for_all_topinsns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_topinsns, this, &mv);
}

//--------------------------------------------------------------------------
inline mop_t *mba_t::find_mop(op_parent_info_t *ctx, ea_t ea, bool is_dest, const mlist_t &list)
{
  return (mop_t *)HEXDSP(hx_mba_t_find_mop, this, ctx, ea, is_dest, &list);
}

//--------------------------------------------------------------------------
inline minsn_t *mba_t::create_helper_call(ea_t ea, const char *helper, const tinfo_t *rettype, const mcallargs_t *callargs, const mop_t *out)
{
  return (minsn_t *)HEXDSP(hx_mba_t_create_helper_call, this, ea, helper, rettype, callargs, out);
}

//--------------------------------------------------------------------------
inline void mba_t::get_func_output_lists(mlist_t *return_regs, mlist_t *spoiled, const tinfo_t &type, ea_t call_ea, bool tail_call)
{
  HEXDSP(hx_mba_t_get_func_output_lists, this, return_regs, spoiled, &type, call_ea, tail_call);
}

//--------------------------------------------------------------------------
inline lvar_t &mba_t::arg(int n)
{
  return *(lvar_t *)HEXDSP(hx_mba_t_arg, this, n);
}

//--------------------------------------------------------------------------
inline ea_t mba_t::alloc_fict_ea(ea_t real_ea)
{
  ea_t retval;
  HEXDSP(hx_mba_t_alloc_fict_ea, &retval, this, real_ea);
  return retval;
}

//--------------------------------------------------------------------------
inline ea_t mba_t::map_fict_ea(ea_t fict_ea) const
{
  ea_t retval;
  HEXDSP(hx_mba_t_map_fict_ea, &retval, this, fict_ea);
  return retval;
}

//--------------------------------------------------------------------------
inline void mba_t::serialize(bytevec_t *vout) const
{
  HEXDSP(hx_mba_t_serialize, this, vout);
}

//--------------------------------------------------------------------------
inline WARN_UNUSED_RESULT mba_t *mba_t::deserialize(const uchar *bytes, size_t nbytes)
{
  return (mba_t *)HEXDSP(hx_mba_t_deserialize, bytes, nbytes);
}

//--------------------------------------------------------------------------
inline void mba_t::save_snapshot(const char *description)
{
  HEXDSP(hx_mba_t_save_snapshot, this, description);
}

//--------------------------------------------------------------------------
inline mreg_t mba_t::alloc_kreg(size_t size, bool check_size)
{
  return (mreg_t)(size_t)HEXDSP(hx_mba_t_alloc_kreg, this, size, check_size);
}

//--------------------------------------------------------------------------
inline void mba_t::free_kreg(mreg_t reg, size_t size)
{
  HEXDSP(hx_mba_t_free_kreg, this, reg, size);
}

//--------------------------------------------------------------------------
inline merror_t mba_t::inline_func(codegen_t &cdg, int blknum, mba_ranges_t &ranges, int decomp_flags, int inline_flags)
{
  return (merror_t)(size_t)HEXDSP(hx_mba_t_inline_func, this, &cdg, blknum, &ranges, decomp_flags, inline_flags);
}

//--------------------------------------------------------------------------
inline const stkpnt_t *mba_t::locate_stkpnt(ea_t ea) const
{
  return (const stkpnt_t *)HEXDSP(hx_mba_t_locate_stkpnt, this, ea);
}

//--------------------------------------------------------------------------
inline bool mba_t::set_lvar_name(lvar_t &v, const char *name, int flagbits)
{
  return (uchar)(size_t)HEXDSP(hx_mba_t_set_lvar_name, this, &v, name, flagbits) != 0;
}

//--------------------------------------------------------------------------
inline mba_t *gen_microcode(const mba_ranges_t &mbr, hexrays_failure_t *hf, const mlist_t *retlist, int decomp_flags, mba_maturity_t reqmat)
{
  return (mba_t *)HEXDSP(hx_gen_microcode, &mbr, hf, retlist, decomp_flags, reqmat);
}

//--------------------------------------------------------------------------
inline bool mbl_graph_t::is_accessed_globally(const mlist_t &list, int b1, int b2, const minsn_t *m1, const minsn_t *m2, access_type_t access_type, maymust_t maymust) const
{
  return (uchar)(size_t)HEXDSP(hx_mbl_graph_t_is_accessed_globally, this, &list, b1, b2, m1, m2, access_type, maymust) != 0;
}

//--------------------------------------------------------------------------
inline graph_chains_t *mbl_graph_t::get_ud(gctype_t gctype)
{
  return (graph_chains_t *)HEXDSP(hx_mbl_graph_t_get_ud, this, gctype);
}

//--------------------------------------------------------------------------
inline graph_chains_t *mbl_graph_t::get_du(gctype_t gctype)
{
  return (graph_chains_t *)HEXDSP(hx_mbl_graph_t_get_du, this, gctype);
}

//--------------------------------------------------------------------------
inline merror_t cdg_insn_iterator_t::next(insn_t *ins)
{
  return (merror_t)(size_t)HEXDSP(hx_cdg_insn_iterator_t_next, this, ins);
}

//--------------------------------------------------------------------------
inline void codegen_t::clear()
{
  HEXDSP(hx_codegen_t_clear, this);
}

//--------------------------------------------------------------------------
inline minsn_t *codegen_t::emit(mcode_t code, int width, uval_t l, uval_t r, uval_t d, int offsize)
{
  return (minsn_t *)HEXDSP(hx_codegen_t_emit, this, code, width, l, r, d, offsize);
}

//--------------------------------------------------------------------------
inline minsn_t *codegen_t::emit(mcode_t code, const mop_t *l, const mop_t *r, const mop_t *d)
{
  return (minsn_t *)HEXDSP(hx_codegen_t_emit_, this, code, l, r, d);
}

//--------------------------------------------------------------------------
inline bool change_hexrays_config(const char *directive)
{
  return (uchar)(size_t)HEXDSP(hx_change_hexrays_config, directive) != 0;
}

//--------------------------------------------------------------------------
inline const char *get_hexrays_version()
{
  return (const char *)HEXDSP(hx_get_hexrays_version);
}

//--------------------------------------------------------------------------
inline vdui_t *open_pseudocode(ea_t ea, int flags)
{
  return (vdui_t *)HEXDSP(hx_open_pseudocode, ea, flags);
}

//--------------------------------------------------------------------------
inline bool close_pseudocode(TWidget *f)
{
  return (uchar)(size_t)HEXDSP(hx_close_pseudocode, f) != 0;
}

//--------------------------------------------------------------------------
inline vdui_t *get_widget_vdui(TWidget *f)
{
  return (vdui_t *)HEXDSP(hx_get_widget_vdui, f);
}

//--------------------------------------------------------------------------
inline bool decompile_many(const char *outfile, const eavec_t *funcaddrs, int flags)
{
  return (uchar)(size_t)HEXDSP(hx_decompile_many, outfile, funcaddrs, flags) != 0;
}

//--------------------------------------------------------------------------
inline void send_database(const hexrays_failure_t &err, bool silent)
{
  HEXDSP(hx_send_database, &err, silent);
}

//--------------------------------------------------------------------------
inline bool gco_info_t::append_to_list(mlist_t *list, const mba_t *mba) const
{
  return (uchar)(size_t)HEXDSP(hx_gco_info_t_append_to_list, this, list, mba) != 0;
}

//--------------------------------------------------------------------------
inline bool get_current_operand(gco_info_t *out)
{
  return (uchar)(size_t)HEXDSP(hx_get_current_operand, out) != 0;
}
#ifdef __NT__
#pragma warning(pop)
#endif
