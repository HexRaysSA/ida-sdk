
import ast
import os

import pypasses


def _build_param_rename_map(old_args, new_args):
    """Return {old_name: new_name} for positionally-aligned parameters whose
    names differ between the original signature and the override. Returns
    None if the signatures don't line up positionally — in that case
    renaming references in the body would be unsafe."""
    rename = {}
    for old_list, new_list in [
            (old_args.posonlyargs, new_args.posonlyargs),
            (old_args.args, new_args.args),
            (old_args.kwonlyargs, new_args.kwonlyargs)]:
        if len(old_list) != len(new_list):
            return None
        for old_a, new_a in zip(old_list, new_list):
            if old_a.arg != new_a.arg:
                rename[old_a.arg] = new_a.arg
    for old_a, new_a in [(old_args.vararg, new_args.vararg),
                         (old_args.kwarg,  new_args.kwarg)]:
        if (old_a is None) != (new_a is None):
            return None
        if old_a is not None and old_a.arg != new_a.arg:
            rename[old_a.arg] = new_a.arg
    return rename


class _rename_names_t(ast.NodeTransformer):
    def __init__(self, rename_map):
        self.rename_map = rename_map

    def visit_Name(self, node):
        new_name = self.rename_map.get(node.id)
        if new_name is not None:
            node.id = new_name
        return node


def process(tree, opts, logger):

    if not os.path.isfile(opts.pydoc_overrides):
        return tree

    #
    # Collect prototypes from the overrides
    #
    class overrides_visitor_t(pypasses.base_visitor_t):

        def __init__(self, module_name):
            super(overrides_visitor_t, self).__init__(module_name)
            self.prototypes = {}

        def _register_proto(self, node):
            path = ".".join(self.current_path + [node.name])
            logger.debug(f"Registering \"{path}\": {node}")
            self.prototypes[path] = node

        def visit_FunctionDef(self, node):
            self._register_proto(node)
            return super(overrides_visitor_t, self).visit_FunctionDef(node)


    with open(opts.pydoc_overrides) as fin:
        overrides_tree = ast.parse(fin.read(), filename=opts.pydoc_overrides)
    overrides = overrides_visitor_t(opts.idapython_module_name)
    overrides.visit(overrides_tree)

    #
    # And apply it to the input
    #
    class source_transformer_t(pypasses.base_transformer_t):
        def __init__(self, module_name, prototypes):
            super(source_transformer_t, self).__init__(module_name)
            self.prototypes = prototypes

        def visit_FunctionDef(self, node):
            path = ".".join(self.current_path + [node.name])
            found = self.prototypes.get(path, None)
            if found is not None:
                logger.debug(f"Found override for \"{path}\"")
                rename_map = _build_param_rename_map(node.args, found.args)
                if rename_map:
                    renamer = _rename_names_t(rename_map)
                    node.body = [renamer.visit(stmt) for stmt in node.body]
                node.args = found.args
                node.returns = found.returns
            self.generic_visit(node)
            return node

    transformer = source_transformer_t(opts.idapython_module_name, overrides.prototypes)
    transformer.visit(tree)

    return tree
