/*
 *  Indexer search plugin example
 *
 *  Demonstrates how to use the IDA indexer API (indexer.hpp) to search
 *  functions, named locations, local types, segments, and function
 *  comments.
 *
 *  When invoked (Edit > Plugins > Indexer Search, or Ctrl-Alt-I):
 *    1. Checks whether the indexer is enabled for the current database.
 *    2. Prompts the user to enter a query string.
 *    3. Searches all sub-indexes and prints results to the Output window.
 *    4. Then narrows the same search to the functions sub-index only.
 *
 *  To enable the indexer, open the database with:
 *    idat -dENABLE_INDEXER=YES <binary>
 */

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <indexer.hpp>

//--------------------------------------------------------------------------
// Map a sub-index identifier to a human-readable label.
static const char *subidx_label(subindex_typeid_t subidx)
{
  switch ( subidx )
  {
    case SUBIDX_FUNCTIONS:                    return "function";
    case SUBIDX_LTYPES:                       return "local type";
    case SUBIDX_NAMES:                        return "name";
    case SUBIDX_SEGMENTS:                     return "segment";
    case SUBIDX_FUNCTION_COMMENTS:            return "func comment";
    case SUBIDX_REPEATABLE_FUNCTION_COMMENTS: return "func rep-comment";
    default:                                  return "unknown";
  }
}

//--------------------------------------------------------------------------
// Print every result in `results` to the Output window.
// Ownership of `results` stays with the caller.
static void print_results(
        const char *header,
        const search_result_data_t *results)
{
  msg("%s\n", header);
  if ( results == nullptr || results->empty() )
  {
    msg("  (no results)\n");
    return;
  }
  for ( size_t i = 0; i < results->size(); ++i )
  {
    ea_t ea = results->get_ea(i);
    if ( ea == BADADDR )
      msg("  [%2zu] score=%3d  ea=%-18s  %-18s  %s\n",
          i,
          results->get_score(i),
          "n/a",
          subidx_label(results->get_subindex(i)),
          results->get_name(i).data());
    else
      msg("  [%2zu] score=%3d  ea=0x%-16" FMT_EA "x  %-18s  %s\n",
          i,
          results->get_score(i),
          ea,
          subidx_label(results->get_subindex(i)),
          results->get_name(i).data());
  }
}

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  if ( !indexer_is_enabled() )
  {
    warning("The indexer is not enabled for this database.\n"
            "Reopen the database with -dENABLE_INDEXER=YES to enable it.");
    return true;
  }

  qstring query;
  if ( !ask_str(&query, 0, "Enter search query:") || query.empty() )
    return true;

  match_config_t cfg;
  cfg.mode        = STR_MATCH;
  cfg.max_results = 20;

  // Search across all sub-indexes at once
  {
    qstring header;
    header.sprnt(
      "=== Substring search for \"%s\" (all sub-indexes) ===",
      query.c_str());
    search_result_data_t *results = indexer_match_all(query, cfg);
    print_results(header.c_str(), results);
    delete results;
  }

  // Narrow to the functions sub-index only
  {
    qstring header;
    header.sprnt(
      "=== Substring search for \"%s\" (functions only) ===",
      query.c_str());
    search_result_data_t *results = indexer_match(SUBIDX_FUNCTIONS, query, cfg);
    print_results(header.c_str(), results);
    delete results;
  }

  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "Search functions, names, types, segments and comments "
    "using the IDA indexer API.",
  nullptr,
  "Indexer Search",     // short name shown in Edit > Plugins
  "Ctrl-Alt-I",         // preferred hotkey
};
