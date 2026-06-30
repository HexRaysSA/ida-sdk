"""
summary: search the IDA indexer for a name (substring match)

description:
  Demonstrates how to use the IDA indexer API to search for functions,
  named locations, local types, segments, and function comments that
  contain a given query string.

  The indexer performs fast substring matching across all indexed data
  simultaneously. Each result exposes the matched name, the sub-index
  that produced it (e.g. SUBIDX_FUNCTIONS or SUBIDX_SEGMENTS), its
  score, and the effective address when applicable.

  The example also shows how to narrow a search to a single sub-index
  when only one category of results is needed.

  Note: the indexer must be enabled for the current database. Open the
  database with -dENABLE_INDEXER=YES to enable it, or check
  indexer_is_enabled() at runtime.

keywords: indexer, search, functions, names, segments, types, comments

level: beginner
"""

import idaapi
import ida_kernwin
import ida_indexer


SUBIDX_NAMES = {
    ida_indexer.SUBIDX_FUNCTIONS:                    "function",
    ida_indexer.SUBIDX_LTYPES:                       "local type",
    ida_indexer.SUBIDX_NAMES:                        "name",
    ida_indexer.SUBIDX_SEGMENTS:                     "segment",
    ida_indexer.SUBIDX_FUNCTION_COMMENTS:            "func comment",
    ida_indexer.SUBIDX_REPEATABLE_FUNCTION_COMMENTS: "func rep-comment",
}


def print_results(header, results):
    print(header)
    if results is None or results.size() == 0:
        print("  (no results)")
        return
    for i in range(results.size()):
        name   = results.get_name(i)
        score  = results.get_score(i)
        ea     = results.get_ea(i)
        subidx = results.get_subindex(i)
        ea_str = "n/a" if ea == idaapi.BADADDR else "0x%x" % ea
        subidx_str = SUBIDX_NAMES.get(subidx, "unknown(%d)" % subidx)
        print("  [%2d] score=%3d  ea=%-18s  %-18s  %s" % (
            i, score, ea_str, subidx_str, name))


def main():
    if not ida_indexer.indexer_is_enabled():
        print("Indexer is not enabled for this database.")
        print("Reopen the database with -dENABLE_INDEXER=YES to enable it.")
        return

    query = ida_kernwin.ask_str("", 0, "Enter a search query:")
    if not query:
        return

    cfg = ida_indexer.match_config_t()
    cfg.mode = ida_indexer.STR_MATCH
    cfg.max_results = 20

    # Search across all sub-indexes at once
    results = ida_indexer.indexer_match_all(query, cfg)
    print_results(
        "\n=== Substring search for '%s' (all sub-indexes) ===" % query,
        results)

    # Narrow to the functions sub-index only
    results = ida_indexer.indexer_match(
        ida_indexer.SUBIDX_FUNCTIONS, query, cfg)
    print_results(
        "\n=== Substring search for '%s' (functions only) ===" % query,
        results)


main()
