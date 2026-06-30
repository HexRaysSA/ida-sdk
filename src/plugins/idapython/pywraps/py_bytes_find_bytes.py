#<pycode(py_bytes_find_bytes)>

import typing

import ida_idaapi
import ida_nalt
import ida_range

def find_bytes(
        bs: typing.Union[bytes, str],
        range_start: int,
        range_size: typing.Optional[int] = None,
        range_end: typing.Optional[int] = ida_idaapi.BADADDR,
        mask: typing.Optional[bytes] = None,
        flags: typing.Optional[int] = BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW,
        radix: typing.Optional[int] = 16,
        strlit_encoding: typing.Optional[typing.Union[int, str]] = PBSENC_DEF1BPU) -> int:
    """
    Search for bytes in the program.

    The pattern can be either a textual binary pattern (`str`) or a raw
    `bytes` buffer optionally combined with `mask`. A textual pattern is
    a space-separated sequence of hex bytes, `?` wildcards, and quoted
    string literals. A `?` may also stand in for a single hex nibble
    inside a 2-char hex byte token (e.g. `A?` or `?5`), as long as the
    token is whitespace/comma-delimited on both sides. Examples (pattern
    contents, without surrounding Python quotes):
      * `B8 ? ? ? ? 90`  -- byte `0xB8`, four wildcards, byte `0x90`
                            (`mov eax, imm32; nop` with any immediate)
      * `48 8? ?? 24`    -- 0x48, any byte starting with 0x8, any byte,
                            0x24 (e.g. matches `mov [rsp+...]` family)
      * `"Hello", 0`     -- the bytes of "Hello" followed by a null byte

    The search range can be specified three ways. From highest to lowest
    precedence:
      * by size, via `range_size` (then `range_end = range_start + range_size`)
      * by `range_t` passed as `range_start` (its `start_ea` and `end_ea`
        become the search range's start and end addresses)
      * by end address, via `range_end`

    The function returns `ida_idaapi.BADADDR` when no further match is
    found. To iterate over all matches in a window:
      * forward (default): after a match at `ea`, set `range_start = ea + 1`
        and call again.
      * backward (`BIN_SEARCH_BACKWARD`): the window is unchanged but the
        highest-address match is returned; after a match at `ea`, set
        `range_end = ea` and call again.

    :param bs: the pattern. If `str`, parsed as a textual binary pattern
               (see the intro above for the syntax); quoted string literals
               inside it are converted to bytes per `strlit_encoding`. If
               `bytes`, used literally and combined with `mask` if provided.
    :param range_start: start address of the search range (inclusive); or
               a `range_t` (see precedence list above).
    :param range_size: size of the search range (see precedence list above).
    :param range_end: end address of the search range (exclusive). The
               entire pattern must fit within the range, i.e. a match is
               accepted only when `match_ea + len(pattern) <= range_end`.
               Defaults to `BADADDR`.
    :param mask: optional byte mask, applied when `bs` is `bytes`. A non-zero
               mask byte means the corresponding pattern byte must match;
               a zero mask byte makes that position a wildcard. Ignored for
               textual patterns (the mask is derived from `?` wildcards in
               the pattern).
    :param flags: combination of `BIN_SEARCH_*` flags. Direction is
               controlled by `BIN_SEARCH_FORWARD` (default) or
               `BIN_SEARCH_BACKWARD`. Case sensitivity only affects quoted
               string literals in a textual pattern: they match
               case-insensitively by default; pass `BIN_SEARCH_CASE` to
               require exact case. Hex byte tokens are unaffected (they
               are literal byte values, not text). Use `BIN_SEARCH_BITMASK`
               for bit-granular `mask` interpretation. Note: these are
               *not* interchangeable with `ida_search.SEARCH_*` (which
               belong to the legacy `find_text`/`find_imm` API).
    :param radix: numeric base for tokens in a textual pattern (8, 10, or 16).
    :param strlit_encoding: encoding (name or index) used to convert quoted
               string literals inside a textual pattern into bytes.
    :returns: address of the next match, or `ida_idaapi.BADADDR` if no match.
    """

    if isinstance(range_start, ida_range.range_t):
        range_start, range_end = range_start.start_ea, range_start.end_ea

    patterns = compiled_binpat_vec_t()
    if isinstance(bs, str):
        if isinstance(strlit_encoding, str):
            strlit_encoding_i = ida_nalt.add_encoding(strlit_encoding)
            if strlit_encoding_i > 0:
                strlit_encoding = strlit_encoding_i
            else:
                raise Exception("Unknown encoding: \"%s\"" % strlit_encoding)
        parse_result = parse_binpat_str(
            patterns,
            range_start,
            bs,
            radix,
            strlit_encoding)
        if parse_result is False or (isinstance(parse_result, str) and len(parse_result) > 0):
            raise Exception("Could not parse pattern: %s" % (parse_result or "unknown error",))
        # If parse_binpat_str produced any per-nibble masks (e.g. from "A?" / "?5"),
        # request bit-wise matching. Skipped for purely 0x00/0xFF masks so legacy
        # textual patterns produce identical behavior (including identical error
        # paths when `flags` is misused).
        for _p in patterns:
            if any(m not in (0, 0xFF) for m in bytes(_p.mask)):
                flags |= BIN_SEARCH_BITMASK
                break
    else:
        p0 = patterns.push_back()
        p0.bytes = __to_bytevec(bs)
        if mask is not None:
            p0.mask = __to_bytevec(mask)

    if range_size is not None:
        range_end = range_start + range_size

    ea, _ = bin_search(range_start, range_end, patterns, flags)
    return ea


def find_string(
        _str: str,
        range_start: int,
        range_end: typing.Optional[int] = ida_idaapi.BADADDR,
        range_size: typing.Optional[int] = None,
        strlit_encoding: typing.Optional[typing.Union[int, str]] = PBSENC_DEF1BPU,
        flags: typing.Optional[int] = BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW) -> int:
    """
    Search for an occurrence of a string in the program.

    Convenience wrapper around `find_bytes()` that quotes `_str` and
    delegates the search. The string is encoded according to
    `strlit_encoding` before matching, so the same call can locate ASCII,
    UTF-16, or any other registered encoding.

    The search range can be specified three ways. From highest to lowest
    precedence: `range_size`, `range_t` passed as `range_start`, or
    `range_end`.

    The function returns `ida_idaapi.BADADDR` when no further match is
    found. To iterate over all matches in a window:
      * forward (default): after a match at `ea`, set `range_start = ea + 1`
        and call again.
      * backward (`BIN_SEARCH_BACKWARD`): the window is unchanged but the
        highest-address match is returned; after a match at `ea`, set
        `range_end = ea` and call again.

    :param _str: the string to look for (plain text -- no quoting needed;
                 embedded double quotes are escaped automatically).
    :param range_start: start address of the search range (inclusive); or
                 a `range_t` (see precedence list above).
    :param range_end: end address of the search range (exclusive). The
                 entire encoded string must fit within the range, i.e. a
                 match is accepted only when
                 `match_ea + len(encoded_str) <= range_end`. Defaults to
                 `BADADDR`.
    :param range_size: size of the search range (see precedence list above).
    :param strlit_encoding: encoding (name or index) used to convert `_str`
                 into bytes.
    :param flags: combination of `BIN_SEARCH_*` flags. Direction is
                 controlled by `BIN_SEARCH_FORWARD` (default) or
                 `BIN_SEARCH_BACKWARD`. By default the match is
                 case-insensitive; pass `BIN_SEARCH_CASE` to require exact
                 case. Note: these are *not* interchangeable with
                 `ida_search.SEARCH_*` (which belong to the legacy
                 `find_text`/`find_imm` API).
    :returns: address of the next match, or `ida_idaapi.BADADDR` if no match.
    """
    escaped = _str.replace('"', r"\22")
    return find_bytes(
        '"' + escaped + '"',
        range_start,
        range_end=range_end,
        range_size=range_size,
        flags=flags,
        strlit_encoding=strlit_encoding)


#</pycode(py_bytes_find_bytes)>
