
import ast

import pypasses

# In the case of C++ functions/methods with default paramater values:
#
#     tinfo_code_t tinfo_t::del_edm_by_value(
#           uint64 value,
#           uint etf_flags=0,
#           bmask64_t bmask=DEFMASK64,
#           uchar serial=0);
#
# SWiG will treat every single default-valued argument as an overload
# of the function, create multiple C++ implementations, and perform
# dispatch there.
# On the Python side, SWiG will create:
#
# class tinfo_t(...):
#     ...
#     def del_edm_by_value(self, *args):
#         return _ida_typeinf.tinfo_t_del_edm_by_value(*args)
#
# While that looks good, it is a problem for us because this is not "real"
# overloading, and we would prefer the method to have the signature:
#
#     def del_edm_by_value(self, value: int, etf_flags: int=0, bmask: int=DEFMASK64, serial: int=0):
#
# ...and that's exactly how we'll define it in the overrides.
# (Naturally, that means this pass needs to happen _after_ the prototype-overriding/fixing one(s))
#
# ---
#
# However, the _body_ of `del_edm_by_value` in the Python side, will
# remain:
#
#     def del_edm_by_value(self, value: int, etf_flags: int=0, bmask: int=DEFMASK64, serial: int=0):
#         return _ida_typeinf.tinfo_t_del_edm_by_value(*args)
#
# ...which will cause an error.
#
# We want to spot such occurrences, and prepare an `args`
# tuple with all the arguments:
#
#     def del_edm_by_value(self, value: int, etf_flags: int=0, bmask: int=DEFMASK64, serial: int=0):
#         args = value, etf_flags, bmask, serial
#         return _ida_typeinf.tinfo_t_del_edm_by_value(*args)
#
# The starred call may be nested in generated setup code, such as a context
# manager around a modal UI call.
#

def process(tree, opts, top_logger):

    class source_transformer_t(pypasses.base_transformer_t):

        class starred_args_finder_t(ast.NodeVisitor):
            def __init__(self):
                self.found = False

            def visit_FunctionDef(self, node):
                pass

            def visit_Lambda(self, node):
                pass

            def visit_Starred(self, node):
                if isinstance(node.value, ast.Name) and node.value.id == "args":
                    self.found = True

        def _is_string_literal(self, node):
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        return True
            return False

        def visit_FunctionDef(self, node):

            logger = top_logger.getChild(node.name)

            # We want to match things such as:
            #
            #   def del_edm_by_value(self, value: int, etf_flags: int=0, bmask: int=DEFMASK64, serial: int=0)
            #       return _ida_typeinf.tinfo_t_get_edm_by_value(self, *args)
            #
            #   def my_function(something: sometype, otherthing: othertype=-2)
            #       return ...(*args)
            #
            real_arg = None
            for arg in node.args.args:
                if arg.arg != "self":
                    logger.debug(f"Found 'real' argument \"{arg.arg}\". Needs investigating.")
                    real_arg = arg
                    break

            if real_arg and node.args.vararg is None:
                finder = self.starred_args_finder_t()
                for statement in node.body:
                    finder.visit(statement)
                if finder.found:
                    logger.debug("Found a starred 'args' call. Let's create it!")
                    insert_idx = 1 if self._is_string_literal(node.body[0]) else 0
                    elts = []
                    for arg in node.args.args:
                        if arg.arg != "self":
                            elts.append(ast.Name(arg.arg))
                    targets = [ast.Name("args", ast.Store())]
                    value = ast.Tuple(elts, ast.Load())
                    assign = ast.Assign(targets, value)
                    node.body.insert(insert_idx, assign)
                    # logger.debug(f">>>> {ast.dump(node, indent=4)}")

            self.generic_visit(node)
            return node

    transformer = source_transformer_t(opts.idapython_module_name)
    transformer.visit(tree)

    return tree
