#!/usr/bin/env python3

import os

################################################################################
# Python Extapi Generator Script
################################################################################
# If you need a new function exposed by our auto generated header, add
# its defintion to one of the global variables below and re-run the script.

## Python global variables
GLOBVARS = {
    "Py_NoSiteFlag":             "int",
    "_Py_NoneStruct":            "PyObject *",
    "_Py_FalseStruct":           "PyObject *",
    "_Py_TrueStruct":            "PyObject *",
    "PyExc_NotImplementedError": "PyObject *",
    "PyExc_KeyboardInterrupt":   "PyObject *",
    "PyExc_TypeError":           "PyObject *",
    "PyExc_ValueError":          "PyObject *",
    "PyBool_Type":               "PyTypeObject",
    "PyFloat_Type":               "PyTypeObject",
    "PyLong_Type":               "PyTypeObject",
    "PyList_Type":               "PyTypeObject",
}

## Python functions
# Format is "name": [ retval, [ arg_types ], [ arg_names ] ]
FUNCTIONS = {
"PyEval_SetTrace":                [ "void",                 [ "Py_tracefunc",     "PyObject *",                                                                                                                                              ],
                                                            [ "func",             "obj",                                                                                                                                                     ], ],
"PyRun_SimpleStringFlags":        [ "int",                  [ "const char *",     "PyCompilerFlags *",                                                                                                                                       ],
                                                            [ "command",          "flags",                                                                                                                                                   ], ],
"PyRun_StringFlags":              [ "PyObject *",           [ "const char *",     "int",                "PyObject *",         "PyObject *",         "PyCompilerFlags *",                                                                     ],
                                                            [ "str",              "start",              "globals",            "locals",             "flags",                                                                                 ], ],
"Py_CompileStringExFlags":        [ "PyObject *",           [ "const char *",     "const char *",       "int",                "PyCompilerFlags *",  "int",                                                                                   ],
                                                            [ "str",              "filename",           "start",              "flags",              "optimize",                                                                              ], ],
"PyFunction_New":                 [ "PyObject *",           [ "PyObject *",       "PyObject *",                                                                                                                                              ],
                                                            [ "code",             "globals",                                                                                                                                                 ], ],
"PyFunction_GetCode":             [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "op",                                                                                                                                                                          ], ],
"_PyLong_AsByteArray":            [ "int",                  [ "PyLongObject *",   "unsigned char *",    "size_t",             "int",                "int",                "int",                                                             ],
                                                            [ "v",                "bytes",              "n",                  "little_endian",      "is_signed",          "with_exceptions",                                                 ], ],
"PyEval_ThreadsInitialized":      [ "int",                  [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyEval_InitThreads":             [ "void",                 [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyBytes_AsString":               [ "char *",               [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyBytes_AsStringAndSize":        [ "int",                  [ "PyObject *",       "char **",            "Py_ssize_t *",                                                                                                                      ],
                                                            [ "obj",              "buffer",             "length",                                                                                                                            ], ],
"PyBytes_FromStringAndSize":      [ "PyObject *",           [ "const char *",     "Py_ssize_t",                                                                                                                                              ],
                                                            [ "v",                "len",                                                                                                                                                     ], ],
"PyBytes_Size":                   [ "Py_ssize_t",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyCallable_Check":               [ "int",                  [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyCapsule_GetPointer":           [ "void *",               [ "PyObject *",       "const char *",                                                                                                                                            ],
                                                            [ "capsule",          "name",                                                                                                                                                    ], ],
"PyCapsule_IsValid":              [ "int",                  [ "PyObject *",       "const char *",                                                                                                                                            ],
                                                            [ "capsule",          "name",                                                                                                                                                    ], ],
"PyCapsule_New":                  [ "PyObject *",           [ "void *",           "const char *",       "PyCapsule_Destructor",                                                                                                              ],
                                                            [ "pointer",          "name",               "destructor",                                                                                                                        ], ],
"PyDict_Contains":                [ "int",                  [ "PyObject *",       "PyObject *",                                                                                                                                              ],
                                                            [ "p",                "key",                                                                                                                                                     ], ],
"PyDict_GetItemString":           [ "PyObject *",           [ "PyObject *",       "const char *",                                                                                                                                            ],
                                                            [ "p",                "key",                                                                                                                                                     ], ],
"PyDict_Items":                   [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "p",                                                                                                                                                                           ], ],
"PyDict_SetItem":                 [ "int",                  [ "PyObject *",       "PyObject *",         "PyObject *",                                                                                                                        ],
                                                            [ "p",                "key",                "val",                                                                                                                               ], ],
"PyDict_SetItemString":           [ "int",                  [ "PyObject *",       "const char *",       "PyObject *",                                                                                                                        ],
                                                            [ "p",                "key",                "val",                                                                                                                               ], ],
"PyErr_Clear":                    [ "void",                 [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyErr_Fetch":                    [ "void",                 [ "PyObject **",      "PyObject **",        "PyObject **",                                                                                                                       ],
                                                            [ "ptype",            "pvalue",             "ptraceback",                                                                                                                        ], ],
"PyErr_Occurred":                 [ "PyObject *",           [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyErr_Print":                    [ "void",                 [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyErr_Restore":                  [ "void",                 [ "PyObject *",       "PyObject *",         "PyObject *",                                                                                                                        ],
                                                            [ "type",             "value",              "traceback",                                                                                                                         ], ],
"PyErr_SetString":                [ "void",                 [ "PyObject *",       "const char *",                                                                                                                                            ],
                                                            [ "type",             "message",                                                                                                                                                 ], ],
"PyEval_EvalCode":                [ "PyObject *",           [ "PyObject *",       "PyObject *",         "PyObject *",                                                                                                                        ],
                                                            [ "co",               "globals",            "locals",                                                                                                                            ], ],
"PyEval_EvalCodeEx":              [ "PyObject *",           [ "PyObject *",       "PyObject *",         "PyObject *", "PyObject * const*", "int",  "PyObject * const*", "int",  "PyObject * const*", "int",  "PyObject *", "PyObject *"      ],
                                                            [ "co",               "globals",            "locals",     "args",              "argc", "kwds",              "kwdc", "defs",              "defc", "kwdefs",     "closure"         ], ],
"PyEval_ReleaseThread":           [ "void",                 [ "PyThreadState *",                                                                                                                                                             ],
                                                            [ "tstate",                                                                                                                                                                      ], ],
"PyFloat_AsDouble":               [ "double",               [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "pyfloat",                                                                                                                                                                     ], ],
"PyFloat_FromDouble":             [ "PyObject *",           [ "double",                                                                                                                                                                      ],
                                                            [ "v",                                                                                                                                                                           ], ],
"PyGILState_Ensure":              [ "PyGILState_STATE",     [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyGILState_GetThisThreadState":  [ "PyThreadState *",      [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyGILState_Release":             [ "void",                 [ "PyGILState_STATE",                                                                                                                                                            ],
                                                            [ "s",                                                                                                                                                                           ], ],
"PyImport_AddModule":             [ "PyObject *",           [ "const char *",                                                                                                                                                                ],
                                                            [ "name",                                                                                                                                                                        ], ],
"PyImport_ImportModule":          [ "PyObject *",           [ "const char *",                                                                                                                                                                ],
                                                            [ "name",                                                                                                                                                                        ], ],
"PyList_Append":                  [ "int",                  [ "PyObject *",       "PyObject *",                                                                                                                                              ],
                                                            [ "list",             "item",                                                                                                                                                    ], ],
"PyList_GetItem":                 [ "PyObject *",           [ "PyObject *",       "Py_ssize_t",                                                                                                                                              ],
                                                            [ "list",             "index",                                                                                                                                                   ], ],
"PyList_Insert":                  [ "int",                  [ "PyObject *",       "Py_ssize_t",         "PyObject *",                                                                                                                        ],
                                                            [ "list",             "index",              "item",                                                                                                                              ], ],
"PyList_New":                     [ "PyObject *",           [ "Py_ssize_t",                                                                                                                                                                  ],
                                                            [ "len",                                                                                                                                                                         ], ],
"PyList_SetItem":                 [ "int",                  [ "PyObject *",       "Py_ssize_t",         "PyObject *",                                                                                                                        ],
                                                            [ "list",             "index",              "item",                                                                                                                              ], ],
"PyList_Size":                    [ "Py_ssize_t",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "list",                                                                                                                                                                        ], ],
"PyLong_AsLong":                  [ "long",                 [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "obj",                                                                                                                                                                         ], ],
"PyLong_AsLongLong":              [ "long long",            [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "obj",                                                                                                                                                                         ], ],
"PyLong_AsUnsignedLong":          [ "unsigned long",        [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "pylong",                                                                                                                                                                      ], ],
"PyLong_AsUnsignedLongLong":      [ "unsigned long long",   [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "pylong",                                                                                                                                                                      ], ],
"PyLong_FromLong":                [ "PyObject *",           [ "long",                                                                                                                                                                        ],
                                                            [ "v",                                                                                                                                                                           ], ],
"PyLong_FromLongLong":            [ "PyObject *",           [ "long long",                                                                                                                                                                   ],
                                                            [ "v",                                                                                                                                                                           ], ],
"PyLong_FromSize_t":              [ "PyObject *",           [ "size_t",                                                                                                                                                                      ],
                                                            [ "v",                                                                                                                                                                           ], ],
"PyLong_FromSsize_t":             [ "PyObject *",           [ "Py_ssize_t",                                                                                                                                                                  ],
                                                            [ "v",                                                                                                                                                                           ], ],
"PyLong_FromUnsignedLongLong":    [ "PyObject *",           [ "unsigned long long",                                                                                                                                                          ],
                                                            [ "v",                                                                                                                                                                           ], ],
"PyModule_GetDict":               [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "module",                                                                                                                                                                      ], ],
"PyNumber_And":                   [ "PyObject *",           [ "PyObject *",       "PyObject *",                                                                                                                                              ],
                                                            [ "o1",               "o2",                                                                                                                                                      ], ],
"PyNumber_Check":                 [ "int",                  [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyObject_CallFunction":          [ "PyObject *",           [ "PyObject *",       "const char *",       "...",                                                                                                                               ],
                                                            [ "callable",         "format",             "...",                                                                                                                               ], ],
"PyObject_CallFunctionObjArgs":   [ "PyObject *",           [ "PyObject *",       "...",                                                                                                                                                     ],
                                                            [ "callable",         "..."                                                                                                                                                      ], ],
"PyObject_CallMethod":            [ "PyObject *",           [ "PyObject *",       "const char *",       "const char *",       "...",                                                                                                         ],
                                                            [ "obj",              "name",               "format",             "...",                                                                                                         ], ],
"PyObject_CallObject":            [ "PyObject *",           [ "PyObject *",       "PyObject *",                                                                                                                                              ],
                                                            [ "callable",         "args",                                                                                                                                                    ], ],
"PyObject_Dir":                   [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyObject_GetAttrString":         [ "PyObject *",           [ "PyObject *",       "const char *",                                                                                                                                            ],
                                                            [ "o",                "attr_name",                                                                                                                                               ], ],
"PyObject_HasAttrString":         [ "int",                  [ "PyObject *",       "const char *",                                                                                                                                            ],
                                                            [ "o",                "attr_name",                                                                                                                                               ], ],
"PyObject_IsInstance":            [ "int",                  [ "PyObject *",       "PyObject *",                                                                                                                                              ],
                                                            [ "inst",             "cls",                                                                                                                                                     ], ],
"PyObject_SetAttrString":         [ "int",                  [ "PyObject *",       "const char *",       "PyObject *",                                                                                                                        ],
                                                            [ "o",                "attr_name",          "v",                                                                                                                                 ], ],
"PyObject_Str":                   [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyObject_RichCompareBool":       [ "int",                  [ "PyObject *",       "PyObject *",         "int",                                                                                                                               ],
                                                            [ "o1",               "o2",                 "opid",                                                                                                                              ], ],
"PySequence_Check":               [ "int",                  [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PySequence_GetItem":             [ "PyObject *",           [ "PyObject *",       "Py_ssize_t",                                                                                                                                              ],
                                                            [ "o",                "i",                                                                                                                                                       ], ],
"PySequence_Size":                [ "Py_ssize_t",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PySys_GetObject":                [ "PyObject *",           [ "const char *",                                                                                                                                                                ],
                                                            [ "name",                                                                                                                                                                        ], ],
"PySys_SetPath":                  [ "void",                 [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PySys_SetObject":                [ "int",                  [ "const char *",     "PyObject *",                                                                                                                                              ],
                                                            [ "name",             "v",                                                                                                                                                       ], ],
"PyThreadState_Get":              [ "PyThreadState *",      [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"PyTuple_GetItem":                [ "PyObject *",           [ "PyObject *",       "Py_ssize_t",                                                                                                                                              ],
                                                            [ "p",                "pos",                                                                                                                                                     ], ],
"PyTuple_New":                    [ "PyObject *",           [ "Py_ssize_t",                                                                                                                                                                  ],
                                                            [ "len",                                                                                                                                                                         ], ],
"PyTuple_SetItem":                [ "int",                  [ "PyObject *",       "Py_ssize_t",         "PyObject *",                                                                                                                        ],
                                                            [ "p",                "pos",                "o",                                                                                                                                 ], ],
"PyTuple_Size":                   [ "Py_ssize_t",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "p",                                                                                                                                                                           ], ],
"PyType_GetFlags":                [ "unsigned long",        [ "PyTypeObject *",                                                                                                                                                              ],
                                                            [ "type",                                                                                                                                                                        ], ],
"PyType_IsSubtype":               [ "int",                  [ "PyTypeObject *",   "PyTypeObject *",                                                                                                                                          ],
                                                            [ "a",                "b",                                                                                                                                                       ], ],
"PyUnicode_AsUTF8String":         [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "unicode",                                                                                                                                                                     ], ],
"PyUnicode_FromString":           [ "PyObject *",           [ "const char *",                                                                                                                                                                ],
                                                            [ "str",                                                                                                                                                                         ], ],
"PyUnicode_FromStringAndSize":    [ "PyObject *",           [ "const char *",     "Py_ssize_t",                                                                                                                                              ],
                                                            [ "str",              "size",                                                                                                                                                    ], ],
"Py_BuildValue":                  [ "PyObject *",           [ "const char *",     "...",                                                                                                                                                     ],
                                                            [ "format",           "...",                                                                                                                                                     ], ],
"Py_Finalize":                    [ "void",                 [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"Py_GetVersion":                  [ "const char *",         [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"Py_InitializeEx":                [ "void",                 [ "int",                                                                                                                                                                         ],
                                                            [ "initsigs",                                                                                                                                                                    ], ],
"Py_IsInitialized":               [ "int",                  [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"_Py_Dealloc":                    [ "void",                 [                                                                                                                                                                                ],
                                                            [                                                                                                                                                                                ], ],
"Py_DecRef":                      [ "void",                 [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"Py_IncRef":                      [ "void",                 [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"Py_CompileStringExFlags":        [ "PyObject *",           [ "const char *",     "const char *",       "int",                "PyCompilerFlags *",  "int",                                                                                   ],
                                                            [ "str",              "filename",           "start",              "flags",              "optimize",                                                                              ], ],
"PySequence_Length":              [ "Py_ssize_t",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
"PyErr_Format":                   [ "PyObject *",           [ "PyObject *",       "const char *",       "...",                                                                                                                               ],
                                                            [ "exception",        "format",             "...",                                                                                                                               ], ],
"PyObject_Repr":                  [ "PyObject *",           [ "PyObject *",                                                                                                                                                                  ],
                                                            [ "o",                                                                                                                                                                           ], ],
}

# Not in limited API
UNSTABLE_SYMS = [
    "PyEval_SetTrace", "PyRun_SimpleStringFlags", "PyRun_StringFlags", "Py_CompileStringExFlags",
    "PyFunction_New", "PyFunction_GetCode", "_PyLong_AsByteArray", "Py_NoSiteFlag",
]

DEPRECATIONS = {
    "PyEval_InitThreads": "3.9",
    "PyEval_ThreadsInitialized": "3.9",
    "PySys_SetPath": "3.11",
    "Py_NoSiteFlag": "3.12",
}



def type_to_fmt(arg_type: str) -> str:
    return {
        'size_t':               '%" FMT_Z "',
        'unsigned long long':   "%llu",
        'long long':            "%lld",
        'Py_ssize_t':           '%" FMT_ZS "',
        'long':                 "%ld",
        'unsigned long':        "%lu",
        'double':               "%f",
        'int':                  "%d",
        'PyGILState_STATE':     "%u",
        'PyTypeObject *':       "%p",
        'PyLongObject *':       "%p",
        'PyObject *':           "%p",
        'char **':              "%p",
        'PyCapsule_Destructor': "%p",
        'PyObject * const*':    "%p",
        'void *':               "%p",
        'PyThreadState *':      "%p",
        'Py_tracefunc':         "%p",
        'PyCompilerFlags *':    "%p",
        'const char *':         "%s",
        'Py_ssize_t *':         "%p",
        'unsigned char *':      "%p",
        'PyObject **':          "%p",
        'PyTypeObject':         "%p",
        "void":                 "",
        "char *":               r'\"%s\"',
    }[arg_type]

def update_file(file_path: str, what: str, contents: list[str]):
    ls = open(file_path, "r").readlines()
    start = end = 0
    for i in range(len(ls)):
        ls[i] = ls[i].strip("\r\n")
        if f"// AUTO GENERATED EXTAPI START {what}" in ls[i]:
            assert start == 0
            start = i
        elif f"// AUTO GENERATED EXTAPI END {what}" in ls[i]:
            assert end == 0
            end = i

    assert start != end and start != 0 and end != 0
    ls = ls[:start + 1] + contents + ls[end:]
    open(f"{file_path}", "w").write("\n".join(ls))

def main():
    out_struct = []
    out_stubs = []
    out_binds = []
    out_globals = []
    out_undefs = []
    
    
    out_typedefs = []
    
    for sym in sorted(FUNCTIONS.keys()) + sorted(GLOBVARS.keys()):
        if sym in FUNCTIONS.keys():
            ret_type, arg_types, arg_names = FUNCTIONS[sym]
        else:
            ret_type = GLOBVARS[sym]
            arg_types = []
            arg_names = []
    
        if sym in FUNCTIONS:
            x = f"typedef {ret_type} {sym}_t({', '.join(arg_types)});"
            x = x.replace(" * ", " *")
            out_typedefs.append(x)
        else:
            x = f"typedef {ret_type} {sym}_t;"
            x = x.replace(" * ", " *")
            out_typedefs.append(x)
    
        if sym in FUNCTIONS:
            out_struct.append(f"  {sym}_t *{sym}_ptr;")
        else:
            x = f"  {sym}_t *{sym}_ptr;"
            x = x.replace("* *", " **")
            out_struct.append(x)
    
        tmp = []
        typ_nam = ", ".join(f"{t} {n}" for (t, n) in zip(arg_types, arg_names))
        sig = f"static inline {ret_type} {sym}({typ_nam})"
        sig = sig.replace("* ", "*")
    
    
        notes = []
        if sym in UNSTABLE_SYMS:
            notes.append("not in limited API")
        if sym in DEPRECATIONS.keys():
            notes.append(f"deprecated in {DEPRECATIONS[sym]}")
        if len(notes) > 0:
            comment = " /* " + ", ".join(notes) + " */"
        else:
            comment = ""
        out_binds.append(f"  BIND_SYMBOL_WEAK(\"{sym}\", {sym}_t, {sym}_ptr);{comment}")
        if sym in GLOBVARS:
             out_undefs.append(f"#undef {sym}")
    
        # We cannot forward variadic functions, so we don't generate stubs for them
        if len(arg_names) >= 2 and arg_names[-1] == "...":
            continue
        tmp.append(f"{sig}")
        tmp.append("{")
    ##
        ats = ", ".join([ type_to_fmt(a) for a in arg_types ])
        ans = ", ".join(arg_names)
        rty = type_to_fmt(ret_type)
        comma = ", " if len(ats) > 1 else ""
        if ret_type == "void":
            tmp.append(f"  if ( TRACE_REDIRECTED_API )")
            tmp.append(f"    msg(\"{sym}({ats})\\n\"{comma}{ans});")
            tmp.append(f"  PYAPI({sym})({', '.join(arg_names)});")
        else:
            tmp.append(f"  {ret_type} r = PYAPI({sym})({', '.join(arg_names)});")
            tmp.append(f"  if ( TRACE_REDIRECTED_API )")
            tmp.append(f"    msg(\"{sym}({ats}) = {rty}\\n\"{comma}{ans}, r);")
            tmp.append(f"  return r;")
        tmp.append(f"}}")
    
    
        if sym in FUNCTIONS:
            out_stubs.append("\n".join(tmp))
        else:
            out_globals.append(f"#define {sym} (*get_extapi()->{sym}_ptr)")
    
    script_path = os.path.dirname(os.path.abspath(__file__))

    update_file(os.path.join(script_path, "extapi.hpp"), "TYPEDEFS", out_typedefs)
    update_file(os.path.join(script_path, "extapi.hpp"), "STRUCTDEFS", out_struct)
    update_file(os.path.join(script_path, "extapi.cpp"), "BINDALL", out_binds)
    update_file(os.path.join(script_path, "py-include", "Python_dynload.h"), "STUBDEFS", out_stubs)
    update_file(os.path.join(script_path, "py-include", "Python_dynload.h"), "GLOBALDEFS", out_globals)



if __name__ == "__main__":
    main()
