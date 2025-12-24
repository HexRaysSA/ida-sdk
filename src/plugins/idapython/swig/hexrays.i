%{
#include <hexrays.hpp>
%}

%force_declare_SWiG_type(TPopupMenu);

//---------------------------------------------------------------------
// SWIG bindings for Hexray Decompiler's hexrays.hpp
//
// Author: EiNSTeiN_ <einstein@g3nius.org>
// Copyright (C) 2013 ESET
//
// Integrated into IDAPython project by the IDAPython Team <idapython@googlegroups.com>
//---------------------------------------------------------------------

#ifdef __NT__
%include <windows.i>
#endif

%ignore boundaries_find;
%rename (boundaries_find) py_boundaries_find;
%ignore boundaries_insert;
%rename (boundaries_insert) py_boundaries_insert;
%ignore term_hexrays_plugin;
%rename (term_hexrays_plugin) py_term_hexrays_plugin;

%{
//<code(py_hexrays)>
//</code(py_hexrays)>
%}

%ignore init_hexrays_plugin;
%rename(init_hexrays_plugin) py_init_hexrays_plugin;

%ignore get_widget_vdui;
%rename (get_widget_vdui) py_get_widget_vdui;

%inline %{
//<inline(py_hexrays)>
//</inline(py_hexrays)>
%}

%pythoncode %{
#<pycode(py_hexrays)>
#</pycode(py_hexrays)>
%}

%import "hexrays_defs.i";
%import "hexrays_ctree.i";
%import "hexrays_micro.i";
%include "hexrays.hpp";
