/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 */

/*! \file indexer.hpp

  \brief Indexer API: search functions, names, local types, segments and
  function comments.

  The indexer maintains a data structure optimized for substring matching,
  allowing queries to be answered quickly regardless of database size.
  Substring matching is further accelerated using multiple threads.

*/

#ifndef INDEXER_HPP
#define INDEXER_HPP

#include <pro.h>
#include <bytes.hpp>
#include <name.hpp>

//-------------------------------------------------------------------------
/// Numeric identifier for a sub-index category. See #builtin_idxes_t.
using subindex_typeid_t = size_t;

/// \brief Identifiers for the built-in indexer sub-categories.
enum builtin_idxes_t ENUM_SIZE(subindex_typeid_t)
{
  INVALID_SUBIDX_ID = 0,                       ///< Invalid / unset value.
  SUBIDX_FUNCTIONS,                            ///< Functions (mangled and demangled names).
  SUBIDX_LTYPES,                               ///< Local types defined in the IDB.
  SUBIDX_NAMES,                                ///< Names in the name list (both mangled and demangled)
  SUBIDX_SEGMENTS,                             ///< Segment names.
  SUBIDX_FUNCTION_COMMENTS,                    ///< Non-repeatable function comments.
  SUBIDX_REPEATABLE_FUNCTION_COMMENTS,         ///< Repeatable function comments.
#ifdef __KERNEL__
  SUBIDX_MAX,
#endif
};

/// \brief A half-open character range [start, end) within a result name
/// string, indicating which characters were matched by the query (or are
/// most relevant to with fuzzy matching).
struct match_range_t
{
  size_t start; ///< Index of the first matched character.
  size_t end;   ///< One past the last matched character.
};
DECLARE_TYPE_AS_MOVABLE(match_range_t);

//-------------------------------------------------------------------------

// Indexer API
//-------------------------------------------------------------------------

/// Matching algorithm used by the indexer.
enum match_mode_t
{
  STR_MATCH, ///< Substring match (default). Fast and exact.
  FUZZY,     ///< Fuzzy match. Tolerates typos and abbreviations.
             ///< \warning Experimental - results and scoring may change in future versions.
};

/// Configuration for an indexer search.
struct match_config_t
{
  size_t cb = sizeof(match_config_t); ///< Size of this structure. Used for forward compatibility.
  match_mode_t mode      = match_mode_t::STR_MATCH; ///< Matching algorithm to use.
  int score_cutoff       = 0;   ///< Minimum score, in percent (fuzzy mode only). Results below this threshold are discarded.
  int max_results        = 500; ///< Maximum number of results to return.
};
DECLARE_TYPE_AS_MOVABLE(match_config_t);

/// Opaque handle owning a set of search results returned by the indexer.
/// The caller is responsible for deleting the object.
/// Results are accessed by index in [0, size()).
struct search_result_data_t
{
  virtual ~search_result_data_t() {}
  /// Number of results.
  virtual size_t size() const = 0;
  /// Name of result at \p index.
  virtual std::string_view get_name(size_t index) const = 0;
  /// Name of result at \p index, as a qstring reference.
  virtual const qstring &get_name_str(size_t index) const = 0;
  /// Match score of result at \p index, in percent [0, 100].
  virtual int get_score(size_t index) const = 0;
  /// Effective address of result at \p index, or BADADDR for local types.
  virtual ea_t get_ea(size_t index) const = 0;
  /// Netnode index of result at \p index.
  virtual nodeidx_t get_netnode_idx(size_t index) const = 0;
  /// Local type ordinal of result at \p index, or 0 if not a local type.
  virtual int get_ltype_ordinal(size_t index) const = 0;
  /// BT_* type code of the local type at \p index (valid when get_ltype_ordinal() != 0).
  virtual type_t get_ltype_type(size_t index) const = 0;
  /// Sub-index that produced result at \p index (e.g. SUBIDX_FUNCTIONS).
  virtual subindex_typeid_t get_subindex(size_t index) const = 0;
  /// Number of matched character ranges for result at \p index.
  virtual size_t get_match_ranges_count(size_t index) const = 0;
  /// Returns the \p range_idx'th matched range for result at \p index.
  virtual match_range_t get_match_range(size_t index, size_t range_idx) const = 0;
  /// For function-comment results, the range within get_name_str() that holds the
  /// matched comment line. Returns {0, 0} for all other result types.
  virtual match_range_t get_match_line_range([[maybe_unused]] size_t index) const { return {0, 0}; }

  bool empty() const { return size() == 0; }
};

/// Returns true if the indexer is enabled for the current database.
/// The indexer is controlled by the ENABLE_INDEXER configuration option and
/// requires the database to have been opened with indexing support.
idaman bool ida_export indexer_is_enabled();

/// Search all sub-indexes for \p query using \p config.
/// \return a heap-allocated result set; the caller must delete it.
///         Returns nullptr if the indexer is not enabled.
idaman search_result_data_t *ida_export indexer_match_all(
        const qstring &query,
        const match_config_t &config);

/// Search a single sub-index identified by \p subindex_id for \p query.
/// \return a heap-allocated result set; the caller must delete it.
///         Returns nullptr if the indexer is not enabled or \p subindex_id is invalid.
idaman search_result_data_t *ida_export indexer_match(
        subindex_typeid_t subindex_id,
        const qstring &query,
        const match_config_t &config);

#endif // INDEXER_HPP
