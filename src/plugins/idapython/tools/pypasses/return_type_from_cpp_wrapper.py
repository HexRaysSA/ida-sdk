
import ast
import re

import pypasses

def process(tree, opts, logger):

    class func_info_t(object):
        def __init__(self, name, body):
            self.name    = name
            self.body    = body

    def collect():
        with open(opts.cpp_wrapper) as fin:
            text = fin.read()

        re_wrap   = re.compile(r".*PyObject *\*_wrap_([^\(]*)\(.*\) *{")
        re_string = re.compile(r"([\"'])(?:\\?.)*?\1")
        re_curly  = re.compile(r"[{}]")

        # remove strings, (to avoid being confused by "{" "}" inside strings)
        text = re_string.sub("", text)

        functions = {}

        def _find_body(text, pos):
            count = 0
            while True:
                m = re_curly.search(text, pos)
                if not m:
                    break

                if m.group()[0] == "{":
                    if count == 0:
                        start = m.start()
                    count += 1
                else:
                    if count == 0:
                        break
                    count -= 1
                    if count == 0:
                        return start, m.end()

                pos = m.end()
            raise Exception("Cannot find body")

        start = 0
        while text:
            m = re_wrap.search(text, start)
            if not m:
                break
            fun_name = m.group(1)
            start, end = _find_body(text, m.start())
            body = text[start:end]

            functions[f"{opts.idapython_module_name}.{fun_name}"] = func_info_t(fun_name, body)
            start = end

        return functions

    #
    # First, collect functions
    #
    functions = collect()

    #
    # Then, patch the return types
    #
    # The `_maybe_*_result` helpers (defined in the generated wrappers) all
    # return Py_None when the C++ status indicates failure, so the matching
    # annotation must be `Union[<payload>, None]`. Non-`_maybe_` helpers
    # always produce a value.
    def _opt(name):
        return ast.parse(f"Union[{name}, None]", mode="eval").body

    class source_transformer_t(pypasses.base_transformer_t):

        PATTERNS = (
            ("resultobj = _maybe_sized_cstring_result(", _opt("str")),
            ("resultobj = _maybe_cstring_result(", _opt("str")),
            ("resultobj = _maybe_binary_result(", _opt("bytes")),
            ("resultobj = _maybe_cstring_result_on_charptr_using_allocated_buf(", _opt("str")),
            ("resultobj = _maybe_cstring_result_on_charptr_using_qbuf(", _opt("str")),
            ("resultobj = _maybe_byte_array_as_hex_or_none_result(", _opt("str")),
            ("resultobj = _maybe_byte_array_or_none_result(", _opt("bytes")),
            ("resultobj = _sized_cstring_result(", ast.Name("str"))
        )

        def __init__(self, module_name, cpp_functions):
            super(source_transformer_t, self).__init__(module_name)
            self.cpp_functions = cpp_functions

        def visit_FunctionDef(self, node):
            path = ".".join(self.current_path + [node.name])
            got = self.cpp_functions.get(path, None)
            if got is None and len(self.current_path) > 1:
                # For class methods, SWIG joins class and method
                # with underscore: "mod.cls_method" not "mod.cls.method"
                alt = self.current_path[0] + "." \
                    + "_".join(self.current_path[1:] + [node.name])
                got = self.cpp_functions.get(alt, None)
            if got is not None:
                for pattern, ret_type in self.PATTERNS:
                    if got.body.find(pattern) >= 0:
                        node.returns = ret_type
                        break
            return node

    transformer = source_transformer_t(opts.idapython_module_name, functions)
    transformer.visit(tree)

    return tree
