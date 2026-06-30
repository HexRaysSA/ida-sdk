
recipe = {
    "stkpnts" : {
        "params" : {
            "stkpnts" : { "rename" : "_sps", },
        },
    },
    "create_hint" : {
        "params" : {
            "hint" : { "suppress_for_call" : True, },
            "important_lines" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "Hexrays_Hooks::handle_create_hint_output",
            "convertor_pass_args" : True,
        }
    },
    "build_callinfo" : {
        "params" : {
            "callinfo" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "Hexrays_Hooks::handle_build_callinfo_output",
            "convertor_pass_args" : True,
        }
    },
    "collect_warnings" : {
        "params" : {
            "warnings" : { "suppress_for_call" : True, "genhooks_ignore" : True, }
        },
        # "return" part handled by SWIG typemaps in hexrays.i
        # (%apply qstrvec_t *out / %hooks_director_handle_qstrvec_t_output).
        # The suppress_for_call is only used by the doxy pypass to move
        # the parameter documentation to the return value section.
        # genhooks_ignore prevents genhooks from suppressing the parameter
        # in the generated C++ code (SWIG handles that).
    },
}

default_rtype = "int"
