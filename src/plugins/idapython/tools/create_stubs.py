"""
Tool for generating type stubs for IDA Python modules.
Generates accurate type hints by parsing IDA Pro source files.
The IDA build to introspect is located automatically in this repo's
bin/ output directory, so IDA must have been built first.

Run with `python -P create_stubs.py [output_dir]`.
"""
import os
import platform
import sys
from typing import Optional

_IDALIB_NAMES = {
    "Windows": "idalib.dll",
    "Linux": "libidalib.so",
    "Darwin": "libidalib.dylib",
}

def find_idadir() -> Optional[str]:
    """Find an IDA binaries directory in this repo's bin/ output.

    A directory qualifies if it contains the idalib shared library and the
    deployed IDAPython modules. Debug builds are preferred over optimized
    ones, but the generated stubs are the same no matter which build they
    are generated from.
    """
    idalib_name = _IDALIB_NAMES[platform.system()]
    repo_root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), *[os.pardir] * 5))
    bin_dir = os.path.join(repo_root, "bin")
    candidates = []
    if os.path.isdir(bin_dir):
        for name in sorted(os.listdir(bin_dir)):
            d = os.path.join(bin_dir, name)
            if os.path.isfile(os.path.join(d, idalib_name)) \
              and os.path.isfile(os.path.join(d, "python", "idaapi.py")):
                candidates.append(d)
    candidates.sort(key=lambda d: d.endswith("_opt"))
    return candidates[0] if candidates else None

_idadir = find_idadir()
if _idadir is None:
    raise SystemExit("no IDA build with IDAPython found in bin/; build IDA first")
# `import idapro` locates the idalib to load through IDADIR
os.environ["IDADIR"] = _idadir

import idapro

import ida_allins, idaapi, ida_auto, ida_bitrange, ida_bytes
import ida_dbg, idadex, ida_dirtree, ida_diskio, ida_dscu, ida_entry, ida_expr
import ida_fixup, ida_fpro, ida_frame, ida_funcs, ida_gdl, ida_graph
import ida_hexrays, ida_idaapi, ida_ida, ida_idc, ida_idd, ida_idp
import ida_ieee, ida_kernwin, ida_libfuncs, ida_lines, ida_loader, ida_lumina
import ida_mergemod, ida_merge, ida_moves, ida_nalt, ida_name, ida_netnode
import ida_offset, ida_pro, ida_problems, ida_range, ida_regfinder, ida_registry
import ida_search, ida_segment, ida_segregs, ida_srclang, ida_strlist
import ida_tryblks, ida_typeinf, ida_ua, ida_undo, idautils, ida_xref, idc
import lumina_model

import ast
import inspect
import re
from typing import Any, Dict, List, Set, Tuple

def find_ida_python_dir() -> Optional[str]:
    """Find the IDAPython modules directory of the introspected IDA build."""
    idadir = find_idadir()
    return os.path.join(idadir, "python") if idadir else None

def read_source_file(module_name: str) -> Optional[str]:
    """Read IDA Pro source file for type information."""
    python_dir = find_ida_python_dir()
    if not python_dir:
        return None

    source_path = os.path.join(python_dir, f"{module_name}.py")
    if os.path.exists(source_path):
        try:
            with open(source_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            pass
    return None

def extract_function_signatures(source_code: str) -> Dict[Tuple[Optional[str], str], str]:
    """Extract function return types from source code, scoped by class.

    Returns a mapping of (class_name, func_name) -> cleaned return type string.
    Module-level functions are stored under (None, func_name). Methods that
    appear in multiple classes (e.g. SWIG container method `push_back`) are
    kept distinct, so each class gets its own correct return type.
    """
    signatures: Dict[Tuple[Optional[str], str], str] = {}
    if not source_code:
        return signatures

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return signatures

    def visit(node, current_class: Optional[str]):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.returns is None:
                    continue
                try:
                    rt_text = ast.unparse(child.returns).strip()
                except Exception:
                    continue
                # Strip outer quotes (string-form forward references)
                if len(rt_text) >= 2 and rt_text[0] == rt_text[-1] and rt_text[0] in ("'", '"'):
                    rt_text = rt_text[1:-1]
                signatures[(current_class, child.name)] = clean_return_type(rt_text)

    visit(tree, None)
    return signatures


def lookup_source_signature(
    source_signatures: Dict[Tuple[Optional[str], str], str],
    cls: Optional[type],
    name: str,
) -> Optional[str]:
    """Look up a return type for `name`, walking the MRO so that inherited
    methods resolve to their declaring class's signature."""
    if not source_signatures:
        return None
    if cls is not None:
        for base in cls.__mro__:
            sig = source_signatures.get((base.__name__, name))
            if sig is not None:
                return sig
    return source_signatures.get((None, name))

# Map IDA-SDK / C-style typedef names to their Python equivalents. SWIG
# exposes these by their C names; without translation they would appear in
# stubs as unresolved identifiers. Shared between clean_return_type and
# clean_type_annotation so parameter and property types are normalized too.
_C_TYPEDEF_MAPPINGS: Dict[str, str] = {
    'ea_t': 'int',
    'sel_t': 'int',
    'tid_t': 'int',
    'nodeidx_t': 'int',
    'flags_t': 'int',
    'flags64_t': 'int',
    'bgcolor_t': 'int',
    'size_t': 'int',
    'ssize_t': 'int',
    'asize_t': 'int',
    'adiff_t': 'int',
    'time_t': 'int',
    'merror_t': 'int',
    'error_t': 'int',
    'drc_t': 'int',
    'dterr_t': 'int',
    'tinfo_code_t': 'int',
    'intval64_t': 'int',
    'int8': 'int', 'int16': 'int', 'int32': 'int', 'int64': 'int',
    'uint8': 'int', 'uint16': 'int', 'uint32': 'int', 'uint64': 'int',
    'uchar': 'int', 'ushort': 'int', 'uint': 'int', 'ulong': 'int', 'ulonglong': 'int',
    'schar': 'int',
    'char': 'int',
    # IDA's `type_t` is a single byte holding a BT_* code — exposed as `bytes`
    # for compatibility with qtype/p_list buffers in SWIG.
    'type_t': 'bytes',
    # Bare iterator typedefs leaked from `qvector< T >::const_iterator`-shaped
    # annotations that lost their `::` qualifier somewhere upstream.
    'iterator': 'Any',
    'const_iterator': 'Any',
    'node_iterator': 'Any',
    # Thread ID, FILE handles — opaque integral / Any types in Python.
    'thid_t': 'int',
    'FILE': 'Any',
}


def _has_unbracketed_char(s: str, ch: str) -> bool:
    """True if `ch` appears at depth 0 in <>/()/[] nesting.

    Used by `clean_return_type` to distinguish C++ multi-token cruft
    (commas/spaces between tokens) from Python generic types where the
    same characters legitimately appear inside brackets.
    """
    depth = 0
    for c in s:
        if c in '<([':
            depth += 1
        elif c in '>)]':
            depth = max(0, depth - 1)
        elif c == ch and depth == 0:
            return True
    return False


def clean_return_type(return_type: str) -> str:
    """Clean up return type annotations."""
    if not return_type:
        return "Any"

    return_type = return_type.strip('\'"')

    type_mappings = {
        'func_t *': 'Optional[func_t]',
        'range_t *': 'Optional[range_t]',
        'insn_t *': 'Optional[insn_t]',
        'PyObject *': 'Any',
        'bool': 'bool',
        'str': 'str',
        'int': 'int',
        'void': 'None',
        'None': 'None',
        **_C_TYPEDEF_MAPPINGS,
    }

    # Handle "const" anywhere in the type first, before other processing
    return_type = re.sub(r'\bconst\b\s*', '', return_type).strip()

    # Handle "enum" types like "enum tty_control_t" -> "tty_control_t"
    if return_type.startswith('enum '):
        return_type = return_type[5:].strip()

    # Handle multiple return values like "size_t *, flags64_t *, opinfo_t *, size_t" -> "Any"
    # Only fires on top-level commas; commas inside [], (), or <> belong to
    # generic types like `Union[int, float, bytes]` or `Tuple[int, str]` and
    # must be preserved.
    if _has_unbracketed_char(return_type, ',') and (
        '*' in return_type or _has_unbracketed_char(return_type, ' ')
    ):
        return 'Any'

    # Handle pointer-to-reference like "cinsn_t *&" -> "cinsn_t"
    if return_type.endswith(' *&'):
        return_type = return_type[:-3].strip()
    elif return_type.endswith(' *'):
        base_type = return_type[:-2].strip()
        if base_type in ['func_t', 'range_t', 'insn_t', 'segment_t', 'struc_t']:
            return f'Optional[{base_type}]'
        elif base_type == 'PyObject':
            return 'Any'
        else:
            # Strip the pointer; fall through so the base type is run through
            # the typedef mapping below (e.g., `uchar *` -> `uchar` -> `int`).
            return_type = base_type

    if return_type in type_mappings:
        return type_mappings[return_type]

    if 'const &' in return_type:
        return_type = return_type.replace('const &', '').strip() or "Any"
    elif return_type.endswith(' &'):
        # Handle reference types like "block_chains_t &" -> "block_chains_t"
        return_type = return_type[:-2].strip()

    # Handle C++ template types like "qvector< ivlset_t >" -> "qvector"
    if '<' in return_type and '>' in return_type:
        return_type = return_type.split('<')[0].strip()

    # Handle space-separated C++ types like "unsigned int" -> "int". Only
    # fires on top-level spaces; spaces inside brackets belong to Python
    # generics (e.g. `Union[int, float, bytes]`).
    if _has_unbracketed_char(return_type, ' '):
        # Map common multi-word types
        multiword_mappings = {
            'unsigned int': 'int',
            'signed int': 'int',
            'long long': 'int',
            'unsigned long': 'int',
            'signed long': 'int',
            'unsigned short': 'int',
            'signed short': 'int',
            'unsigned char': 'int',
            'signed char': 'int',
            'unsigned long long': 'int',
            'signed long long': 'int'
        }
        return_type = multiword_mappings.get(return_type, 'Any')

    # Handle C++ namespaced types like "rangeset_t::iterator" -> last segment.
    # SWIG iterator types have no Python equivalent so collapse them to Any.
    if '::' in return_type:
        last = return_type.split('::')[-1]
        if last in ('iterator', 'const_iterator'):
            return 'Any'
        return_type = last

    # Final typedef mapping pass: catches IDA SDK C typedefs (uchar -> int,
    # type_t -> bytes, etc.) that survived the pointer/reference/template
    # stripping above as bare identifiers.
    return_type = _C_TYPEDEF_MAPPINGS.get(return_type, return_type)

    return return_type if return_type else "Any"

def clean_type_annotation(type_str: str) -> str:
    """Clean up type annotations."""
    if not type_str:
        return "Any"

    class_match = re.match(r"<class '([^']+)'>", str(type_str))
    if class_match:
        return class_match.group(1)

    type_str = str(type_str).strip('\'"')

    # Handle C-style pointer types like "TWidget *" -> "TWidget", "html_line_cb_t **" -> "html_line_cb_t"
    if type_str.endswith(' **'):
        type_str = type_str[:-3].strip()
    elif type_str.endswith(' *'):
        type_str = type_str[:-2].strip()

    # Handle C-style const types like "lochist_entry_t const" -> "lochist_entry_t"
    if type_str.endswith(' const'):
        type_str = type_str[:-6].strip()

    # Handle "const type" -> "type"
    if type_str.startswith('const '):
        type_str = type_str[6:].strip()

    # Handle "type const" patterns more broadly
    type_str = re.sub(r'\s+const\b', '', type_str)

    # Handle C++ namespaced types like "processor_t::regval_getter_t" -> "regval_getter_t"
    if '::' in type_str:
        type_str = type_str.split('::')[-1]

    # Handle C++ reference types like "rrel_t &" -> "rrel_t"
    if type_str.endswith(' &'):
        type_str = type_str[:-2].strip()

    # Handle C++ template types like "qvector< long long >" -> "qvector"
    if '<' in type_str and '>' in type_str:
        type_str = type_str.split('<')[0].strip()

    # Handle space-separated C++ types
    if ' ' in type_str:
        # Map common multi-word types
        multiword_mappings = {
            'unsigned int': 'int',
            'signed int': 'int',
            'long long': 'int',
            'unsigned long': 'int',
            'signed long': 'int',
            'unsigned short': 'int',
            'signed short': 'int',
            'unsigned char': 'int',
            'signed char': 'int',
            'unsigned long long': 'int',
            'signed long long': 'int'
        }
        type_str = multiword_mappings.get(type_str, 'Any')

    mappings = {
        'NoneType': 'None',
        'builtin_function_or_method': 'Callable[..., Any]',
        'method': 'Callable[..., Any]',
        'function': 'Callable[..., Any]',
        'property': 'Any',
        'PyObject': 'Any',  # Handle PyObject types
        # `void` after pointer stripping: in a parameter slot a `void *` is
        # "any pointer", which Python idiomatically types as Any (not None).
        # Return-side `void` is handled by clean_return_type's type_mappings.
        'void': 'Any',
    }
    type_str = mappings.get(type_str, type_str)

    # Final typedef mapping (uchar -> int, type_t -> bytes, ...) so parameter
    # and property types reflect their Python runtime equivalents instead of
    # leaving SWIG's bare C typedef names dangling.
    return _C_TYPEDEF_MAPPINGS.get(type_str, type_str)

# Patterns matched against a method's docstring to recover return types for
# slot wrappers (object.__str__, etc.) where inspect.signature gives no
# annotation. The patterns map standard Python documentation conventions to
# the types those conventions describe — not specific method names — so they
# generalize beyond IDA-specific code.
_RETURN_TYPE_DOC_PATTERNS: List[Tuple[Any, str]] = [
    (re.compile(r'\bReturn\s+str\b'), 'str'),
    (re.compile(r'\bReturn\s+repr\b'), 'str'),
    (re.compile(r'\bReturn\s+bytes\b'), 'bytes'),
    (re.compile(r'\bReturn\s+hash\b'), 'int'),
    (re.compile(r'\bReturn\s+len\b'), 'int'),
    (re.compile(r'\bReturn\s+bool\b'), 'bool'),
    (re.compile(r'\bReturn\s+int\b'), 'int'),
    (re.compile(r'\bReturn\s+float\b'), 'float'),
    (re.compile(r'\bReturn\s+self\s*(==|!=|<=|>=|<|>)'), 'bool'),
    (re.compile(r'^True if self', re.MULTILINE), 'bool'),
    (re.compile(r'\bDefault object formatter\b'), 'str'),
]


# SWIG emits this header followed by a numbered list of overload signatures
# whenever a Python method binds multiple C++ overloads.
_SWIG_OVERLOAD_HEADER_RE = re.compile(r'This function has the following signatures:')
_SWIG_OVERLOAD_LINE_RE = re.compile(r'^\s*\d+\.\s+(\w+)\s*\((.*?)\)\s*->\s*(.+?)\s*$')

_PYTHON_KEYWORDS = frozenset({
    'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break',
    'class', 'continue', 'def', 'del', 'elif', 'else', 'except', 'finally',
    'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal',
    'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield',
})


def _split_top_level_commas(s: str) -> List[str]:
    """Split on commas that are at depth 0 in <>/()/[] nesting."""
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for c in s:
        if c in '<([':
            depth += 1
        elif c in '>)]':
            depth = max(0, depth - 1)
        elif c == ',' and depth == 0:
            piece = ''.join(current).strip()
            if piece:
                parts.append(piece)
            current = []
            continue
        current.append(c)
    piece = ''.join(current).strip()
    if piece:
        parts.append(piece)
    return parts


def _clean_default_value(s: str) -> str:
    """Translate a SWIG default-value expression to a stub-safe form.

    Common SWIG forms (true/false/nullptr) and bare numeric/string literals
    pass through to their Python equivalents; anything else (function calls,
    free identifiers we can't resolve) becomes `...` per stub conventions.
    """
    s = s.strip()
    mapping = {'true': 'True', 'false': 'False', 'nullptr': 'None', 'NULL': 'None'}
    if s in mapping:
        return mapping[s]
    if re.fullmatch(r'-?\d+(\.\d+)?', s):
        return s
    if (len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"')):
        return s
    return '...'


def _clean_overload_param(part: str) -> str:
    """Clean a single 'name: type[=default]' fragment from a SWIG overload."""
    name, _, rest = part.partition(':')
    name = name.strip()
    if not name:
        # Type-only fragment (defensive — SWIG normally always emits a name)
        return f"_: {clean_type_annotation(rest.strip())}" if rest.strip() else "_: Any"

    if name in _PYTHON_KEYWORDS:
        name = name + '_'

    if not rest.strip():
        return f"{name}: Any"

    type_part, eq, default = rest.partition('=')
    cleaned_typ = clean_type_annotation(type_part.strip())
    if eq:
        return f"{name}: {cleaned_typ} = {_clean_default_value(default)}"
    return f"{name}: {cleaned_typ}"


def _clean_overload_params(params_str: str) -> str:
    parts = _split_top_level_commas(params_str)
    return ', '.join(_clean_overload_param(p) for p in parts)


# Matches the per-overload section header that SWIG sometimes emits below
# the listing: `# 0: add(...) -> bool`, `# 1: ...`, etc.
_SWIG_OVERLOAD_SECTION_RE = re.compile(r'^#\s*(\d+):\s*[^\n]*$', re.MULTILINE)
# Matches a numbered overload signature line in a SWIG/idapy docstring.
_SWIG_OVERLOAD_LINE_RE_M = re.compile(
    r'^\s*\d+\.\s+(\w+)\s*\((.*?)\)\s*->\s*(.+?)\s*$', re.MULTILINE
)


def parse_swig_overloads(doc: Optional[str]) -> Optional[List[Tuple[str, str, str]]]:
    """Parse a SWIG overload docstring into [(params, return_type, per_doc), ...].

    Two docstring shapes appear in IDA's bindings:

    1. SWIG default: numbered listing followed by `# N: <sig>` prose blocks.
    2. idapy-style: optional preamble, the "This function has..." header,
       then a numbered listing where each item may have indented continuation
       prose that runs until the next numbered line.

    For both shapes each overload's prose is recovered. Any preamble text
    before the SWIG header is prepended to every overload's doc — that text
    typically describes the method as a whole and is useful at every call
    site regardless of which overload type-resolves.

    Returns None if the docstring is not in either form, or if fewer than
    two distinct signatures are extracted.
    """
    if not doc or not _SWIG_OVERLOAD_HEADER_RE.search(doc):
        return None

    # Preamble: any prose before the "This function has..." header.
    header_match = _SWIG_OVERLOAD_HEADER_RE.search(doc)
    preamble = doc[:header_match.start()].strip() if header_match else ''

    # Collect numbered signatures with their byte offsets, so we can later
    # slice inline-continuation prose between them when no `# N:` block exists.
    raw_overloads: List[Tuple[str, str]] = []
    numbered_matches: List[Any] = []
    for m in _SWIG_OVERLOAD_LINE_RE_M.finditer(doc):
        try:
            cleaned_params = _clean_overload_params(m.group(2))
            cleaned_ret = clean_return_type(m.group(3).strip())
        except Exception:
            continue
        raw_overloads.append((cleaned_params, cleaned_ret))
        numbered_matches.append(m)

    if len(raw_overloads) < 2:
        return None

    # Prefer `# N:` section prose; fall back to inline continuation prose.
    section_matches = list(_SWIG_OVERLOAD_SECTION_RE.finditer(doc))
    per_doc: Dict[int, str] = {}
    if section_matches:
        for i, m in enumerate(section_matches):
            start = m.end()
            end = section_matches[i + 1].start() if i + 1 < len(section_matches) else len(doc)
            per_doc[i] = doc[start:end].strip()
    else:
        for i, m in enumerate(numbered_matches):
            start = m.end()
            end = numbered_matches[i + 1].start() if i + 1 < len(numbered_matches) else len(doc)
            per_doc[i] = doc[start:end].strip()

    # Combine, deduping identical (params, ret) pairs but keeping the doc of
    # the first occurrence so each emitted @overload retains its own prose.
    results: List[Tuple[str, str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for i, (p, r) in enumerate(raw_overloads):
        key = (p, r)
        if key in seen:
            continue
        seen.add(key)
        ov_doc = per_doc.get(i, '')
        if preamble:
            ov_doc = preamble + ('\n\n' + ov_doc if ov_doc else '')
        results.append((p, r, ov_doc))

    return results


def infer_return_type_from_doc(doc: Optional[str]) -> Optional[str]:
    """Best-effort return-type inference from a method's docstring.

    Returns a Python type name (`str`, `int`, `bool`, ...) when the docstring
    matches a documented Python data-model phrasing, else None.
    """
    if not doc:
        return None
    for pat, rt in _RETURN_TYPE_DOC_PATTERNS:
        if pat.search(doc):
            return rt
    return None


def get_function_signature(func, func_name: str, is_method: bool = False, source_return_type: Optional[str] = None) -> str:
    """Get function signature with type information.

    `source_return_type`, when provided, overrides the return type derived from
    `inspect.signature`. The caller is responsible for resolving it with class
    scope (see `lookup_source_signature`).
    """
    try:
        sig = inspect.signature(func)
        params = []

        for param_name, param in sig.parameters.items():
            if is_method and param_name == 'self':
                continue

            if param.kind == inspect.Parameter.VAR_POSITIONAL:
                params.append(f"*{param_name}: Any")
                continue
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                params.append(f"**{param_name}: Any")
                continue

            if param.annotation != inspect.Parameter.empty:
                type_hint = clean_type_annotation(param.annotation)
            else:
                type_hint = "Any"

            if param.default != inspect.Parameter.empty:
                if param.default is None:
                    param_str = f"{param_name}: {type_hint} = None"
                elif isinstance(param.default, (int, float, bool, str)):
                    param_str = f"{param_name}: {type_hint} = {repr(param.default)}"
                else:
                    param_str = f"{param_name}: {type_hint} = ..."
            else:
                param_str = f"{param_name}: {type_hint}"

            params.append(param_str)

        if is_method:
            params_str = f"self, {', '.join(params)}" if params else "self"
        else:
            params_str = ', '.join(params) if params else ""

        if source_return_type:
            return_type = source_return_type
        elif sig.return_annotation != inspect.Parameter.empty:
            return_type = clean_return_type(clean_type_annotation(sig.return_annotation))
        else:
            return_type = infer_return_type_from_doc(getattr(func, '__doc__', None)) or "Any"

        # Ensure return type is not empty
        if not return_type or return_type.isspace():
            return_type = "Any"

        # Apply final cleaning to all return types
        return_type = clean_return_type(return_type)
        return f"def {func_name}({params_str}) -> {return_type}: ..."

    except (ValueError, TypeError, OSError):
        return_type = (
            source_return_type
            or infer_return_type_from_doc(getattr(func, '__doc__', None))
            or "Any"
        )

        # Ensure return type is not empty
        if not return_type or return_type.isspace():
            return_type = "Any"

        # Apply final cleaning to all return types
        return_type = clean_return_type(return_type)

        if is_method:
            return f"def {func_name}(self, *args: Any, **kwargs: Any) -> {return_type}: ..."
        else:
            return f"def {func_name}(*args: Any, **kwargs: Any) -> {return_type}: ..."

def format_docstring(docstring: str, indent: str = "    ") -> List[str]:
    """Format docstring with proper indentation and escape sequences."""
    if not docstring:
        return []

    lines = docstring.split('\n')
    if len(lines) == 1:
        return [f'{indent}r"""{lines[0]}"""']

    result = [f'{indent}r"""{lines[0]}']
    for line in lines[1:]:
        result.append(f'{indent}{line}')
    result.append(f'{indent}"""')
    return result

def analyze_class(cls, source_signatures: Dict[Tuple[Optional[str], str], str] = None) -> Dict[str, Any]:
    """Analyze class for stub generation."""
    analysis = {
        'methods': {},
        'properties': {},
        'class_variables': {},
        'inheritance': [],
        'docstring': cls.__doc__
    }

    for base in cls.__mro__[1:]:
        if base != object:
            analysis['inheritance'].append(base.__name__)

    # Merge __annotations__ from MRO (subclass overrides parent) so that
    # SWIG-style typed properties like `start_ea: ida_idaapi.ea_t = property(...)`
    # carry their declared type into the stub instead of degrading to Any.
    class_annotations: Dict[str, Any] = {}
    for base in reversed(cls.__mro__):
        class_annotations.update(getattr(base, '__annotations__', None) or {})

    for name in dir(cls):
        if name.startswith('_') and not name.startswith('__'):
            continue

        try:
            attr = getattr(cls, name)

            if name in ['thisown', '__dict__', '__weakref__', '__class__']:
                continue

            try:
                static_attr = inspect.getattr_static(cls, name)
                if isinstance(static_attr, property):
                    declared = class_annotations.get(name)
                    if declared is not None:
                        prop_type = clean_type_annotation(
                            declared if isinstance(declared, str) else getattr(declared, '__name__', str(declared))
                        )
                        # Fall back to Any if cleaning produced something that
                        # isn't a usable Python type name (e.g. SWIG C-array
                        # annotations like "qstring [T::N]" leak a stray "]").
                        if not re.fullmatch(r'(Optional\[[\w.]+\]|[\w.]+)', prop_type):
                            prop_type = "Any"
                    else:
                        prop_type = "Any"
                    analysis['properties'][name] = {
                        'type': prop_type,
                        'doc': static_attr.__doc__
                    }
                    continue
            except:
                pass

            if callable(attr):
                src_rt = lookup_source_signature(source_signatures, cls, name)
                method_doc = getattr(attr, '__doc__', None)
                method_info = {
                    'signature': get_function_signature(attr, name, is_method=True, source_return_type=src_rt),
                    'doc': method_doc,
                }
                overloads = parse_swig_overloads(method_doc)
                if overloads:
                    method_info['overloads'] = overloads
                analysis['methods'][name] = method_info
            elif not name.startswith('__'):
                analysis['class_variables'][name] = {
                    'type': clean_type_annotation(type(attr).__name__),
                    'value': attr if len(str(attr)) < 50 else None
                }

        except Exception:
            return_type = lookup_source_signature(source_signatures, cls, name) or "Any"
            analysis['methods'][name] = {
                'signature': f"def {name}(self, *args: Any, **kwargs: Any) -> {return_type}: ...",
                'doc': None
            }

    # SWIG containers set `__iter__ = ida_idaapi._bounded_getitem_iterator`,
    # which yields `self[i]` for each i. Whenever a class has both __iter__
    # and __getitem__, refine __iter__'s return type to Iterator[<element>],
    # so `for x in vec: x.<member>` autocompletes correctly.
    if '__iter__' in analysis['methods'] and '__getitem__' in analysis['methods']:
        gi_sig = analysis['methods']['__getitem__']['signature']
        m = re.search(r'->\s*(.+?)\s*:\s*\.\.\.\s*$', gi_sig)
        if m:
            elem_type = m.group(1).strip()
            if elem_type and elem_type != 'Any':
                old_iter = analysis['methods']['__iter__']
                analysis['methods']['__iter__'] = {
                    'signature': f"def __iter__(self) -> Iterator[{elem_type}]: ...",
                    'doc': old_iter.get('doc'),
                }

    return analysis

def generate_stub(module_name: str) -> str:
    """Generate stub content for a module."""
    try:
        module = __import__(module_name)
    except ImportError as e:
        return f"# Error importing {module_name}: {e}\n"

    source_code = read_source_file(module_name)
    source_signatures = extract_function_signatures(source_code) if source_code else {}

    lines = []
    lines.append("from typing import Any, Optional, List, Dict, Tuple, Callable, Union, Iterator, overload")
    lines.append("")

    # Names that are imported from typing and should not be generated as stubs
    typing_imports = {'Any', 'Optional', 'List', 'Dict', 'Tuple', 'Callable', 'Union', 'Iterator', 'overload'}

    if module.__doc__:
        lines.extend(format_docstring(module.__doc__, ""))
        lines.append("")

    module_members = {}
    for name in dir(module):
        if name.startswith('_'):
            continue
        try:
            module_members[name] = getattr(module, name)
        except:
            continue

    # Detect type aliases by checking if a name in the module is assigned to a built-in type
    type_aliases = {}
    builtin_types = {int, str, float, bool, bytes, bytearray, list, dict, set, tuple, type(None)}
    for name, obj in module_members.items():
        if inspect.isclass(obj) and obj in builtin_types:
            # This is a type alias to a built-in type (e.g., ea_t = int)
            type_aliases[name] = obj.__name__

    classes = {}
    for name, obj in module_members.items():
        if inspect.isclass(obj) and name not in type_aliases:
            classes[name] = analyze_class(obj, source_signatures)

    for class_name, analysis in classes.items():
        if analysis['inheritance']:
            valid_bases = []
            for base in analysis['inheritance'][:3]:
                if base in classes or base in ['object', 'Exception']:
                    valid_bases.append(base)
            inheritance = f"({', '.join(valid_bases)})" if valid_bases else ""
        else:
            inheritance = ""

        lines.append(f"class {class_name}{inheritance}:")

        if analysis['docstring']:
            lines.extend(format_docstring(analysis['docstring']))

        for var_name, var_info in analysis['class_variables'].items():
            value_comment = f"  # {var_info['value']}" if var_info['value'] is not None else ""
            lines.append(f"    {var_name}: {var_info['type']}{value_comment}")

        for prop_name, prop_info in analysis['properties'].items():
            lines.append(f"    @property")
            lines.append(f"    def {prop_name}(self) -> {prop_info['type']}: ...")

        method_count = 0
        for method_name, method_info in analysis['methods'].items():
            overloads = method_info.get('overloads')
            if overloads:
                for params, ret, ov_doc in overloads:
                    self_params = f"self, {params}" if params else "self"
                    lines.append("    @overload")
                    if ov_doc:
                        lines.append(f"    def {method_name}({self_params}) -> {ret}:")
                        lines.extend(format_docstring(ov_doc, "        "))
                        lines.append("        ...")
                    else:
                        lines.append(f"    def {method_name}({self_params}) -> {ret}: ...")
            else:
                # Remove the '...' from the signature and add it after docstring
                signature = method_info['signature']
                if signature.endswith(": ..."):
                    signature = signature[:-5] + ":"
                lines.append(f"    {signature}")
                if method_info['doc']:
                    lines.extend(format_docstring(method_info['doc'], "        "))
                lines.append("        ...")
            method_count += 1

        if method_count == 0 and not analysis['properties'] and not analysis['class_variables']:
            lines.append("    ...")

        lines.append("")

    for name, obj in module_members.items():
        if not inspect.isclass(obj) and callable(obj) and name not in typing_imports:
            obj_doc = getattr(obj, '__doc__', None)
            overloads = parse_swig_overloads(obj_doc)
            if overloads:
                for params, ret, ov_doc in overloads:
                    lines.append("@overload")
                    if ov_doc:
                        lines.append(f"def {name}({params}) -> {ret}:")
                        lines.extend(format_docstring(ov_doc))
                        lines.append("    ...")
                    else:
                        lines.append(f"def {name}({params}) -> {ret}: ...")
                lines.append("")
                continue
            # Remove the '...' from the signature and add it after docstring
            src_rt = lookup_source_signature(source_signatures, None, name)
            signature = get_function_signature(obj, name, source_return_type=src_rt)
            if signature.endswith(": ..."):
                signature = signature[:-5] + ":"
            lines.append(signature)
            if obj_doc:
                lines.extend(format_docstring(obj_doc))
            lines.append("    ...")
            lines.append("")

    # Output type aliases first
    for alias_name, builtin_name in type_aliases.items():
        lines.append(f"{alias_name} = {builtin_name}")

    # Then output other module-level variables
    for name, obj in module_members.items():
        if not inspect.isclass(obj) and not callable(obj) and name not in type_aliases:
            type_name = clean_type_annotation(type(obj).__name__)
            value_comment = f"  # {obj}" if obj is not None and len(str(obj)) < 50 else ""
            lines.append(f"{name}: {type_name}{value_comment}")

    return "\n".join(lines)

def main():
    """Generate all stub files."""
    print(f"Found IDA Python directory: {find_ida_python_dir()}")

    modules = [
        "ida_allins", "idaapi", "ida_auto", "ida_bitrange", "ida_bytes",
        "ida_dbg", "idadex", "ida_dirtree", "ida_diskio", "ida_dscu", "ida_entry", "ida_expr",
        "ida_fixup", "ida_fpro", "ida_frame", "ida_funcs", "ida_gdl", "ida_graph",
        "ida_hexrays", "ida_idaapi", "ida_ida", "ida_idc", "ida_idd", "ida_idp",
        "ida_ieee", "ida_kernwin", "ida_libfuncs", "ida_lines", "ida_loader", "ida_lumina",
        "ida_mergemod", "ida_merge", "ida_moves", "ida_nalt", "ida_name", "ida_netnode",
        "ida_offset", "ida_problems", "ida_pro", "ida_range", "ida_regfinder", "ida_registry",
        "ida_search", "ida_segment", "ida_segregs", "ida_srclang", "ida_strlist",
        "ida_tryblks", "ida_typeinf", "ida_ua", "ida_undo", "idautils", "ida_xref", "idc",
        "lumina_model"
    ]

    output_dir = sys.argv[1] if len(sys.argv) > 1 else "stubs"
    os.makedirs(output_dir, exist_ok=True)

    print(f"Generating stubs for {len(modules)} modules...")
    success_count = 0
    error_count = 0

    for module_name in modules:
        try:
            stub_content = generate_stub(module_name)
            output_path = os.path.join(output_dir, f"{module_name}.pyi")
            with open(output_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(stub_content)
            print(f"✓ Generated {module_name}.pyi")
            success_count += 1
        except Exception as e:
            print(f"✗ Error generating {module_name}: {e}")
            error_count += 1

    print(f"\nCompleted: {success_count} successful, {error_count} errors")

if __name__ == "__main__":
    main()
