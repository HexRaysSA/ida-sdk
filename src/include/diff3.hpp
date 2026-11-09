/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
 *      ALL RIGHTS RESERVED.
 */

#ifndef _DIFF3_HPP
#define _DIFF3_HPP

/*! \file diff3.hpp

        \brief 3-way diff for anchored info

        NOTE: this functionality is available in IDA Teams (not IDA Pro)

        Since names, comments, functions, etc, are tied to addresses,
        we need this kind of diff engine. Other kinds of diff engines
        will be necessary too (for example: dirtrees, types, and text)

*/

// The diffing algorithms in this file match information tied to addresses.
// So, if addresses do not match, the information will be considered to be different.

//-------------------------------------------------------------------------
/// A range of the difference source.
/// This is just a pair of start and end positions.
/// The end position is excluded, as usual.
struct diff_range_t
{
  diffpos_t start;
  diffpos_t end;
  diff_range_t(diffpos_t s=0, diffpos_t e=0) : start(s), end(e) {}
  bool empty() const { return start >= end; }
  void clear() { start = end = 0; }
  bool contains(diffpos_t p) const { return start <= p && p < end; }
  void set_start(diffpos_t p)
  {
    start = p;
    if ( end < start )
      end = start;
  }
  void set_end(diffpos_t p)
  {
    end = p;
    if ( end < start )
      start = end;
  }
  void intersect(const diff_range_t &r)
  {
    if ( start < r.start )
      start = r.start;
    if ( end > r.end )
      end = r.end;
    if ( end < start )
      end = start;
  }

  int compare(const diff_range_t &r) const { return start > r.start ? 1 : start < r.start ? -1 : 0; }

  bool operator ==(const diff_range_t &r) const { return compare(r) == 0; }
  bool operator !=(const diff_range_t &r) const { return compare(r) != 0; }
};
DECLARE_TYPE_AS_MOVABLE(diff_range_t);

//------------------------------------------------------------------------
/// A difference degree.
/// Negative values are illegal.
/// 0 means no difference.
/// 1 means a difference.
/// Bigger values mean more important differences, of another nature.
/// INT_MAX is used for the situations where diffpos_t values are different.
/// Example: when comparing instructions and data, 1 is used to denote
/// differences at the operand type level, and 2 is used to denote differences
/// between instructions and data:
///    diff_degree("cmp eax, 20h", "db 83h, 0F8h, 20h") => 2
///    diff_degree("cmp eax, 20h", "cmp eax, 32") => 1
/// In the presence of the differences of higher degree the differences of
/// lower degrees should be ignored.
typedef ssize_t diff_degree_t;

//------------------------------------------------------------------------
enum diff_action_t
{
  DIFF_NONE, ///< unknown
  DIFF_USE1, ///< use information from src1
  DIFF_USE2, ///< use information from src2
  DIFF_BOTH, ///< use information from both (conflict)
};

//------------------------------------------------------------------------
/// A difference region.
/// These regions represent the mismatching ranges in the difference sources.
struct diff_region_t : public diff_range_t
{
  diff_degree_t diff_degree = 0;
  diff_action_t action = DIFF_BOTH;
  void clear() { diff_range_t::clear(); action = DIFF_NONE; }
  bool is_useless() const { return empty() || diff_degree == 0; }
  qstring dstr() const;
};
DECLARE_TYPE_AS_MOVABLE(diff_region_t);
typedef qvector<diff_region_t> diff_regions_t;

//------------------------------------------------------------------------
enum diffpos_check_t
{
  DIFFPOS_CHECK,        ///< verify if the position is valid;
                        ///< if not, return the next valid position
  DIFFPOS_FORWARD,      ///< advance to the next valid position
  DIFFPOS_BACKWARD,     ///< back off to the previous valid position
};

//------------------------------------------------------------------------
struct diff_text_t : public qstrvec_t
{
  diffpos_t pos;
};
DECLARE_TYPE_AS_MOVABLE(diff_text_t);
typedef qvector<diff_text_t> diff_texts_t;

//--------------------------------------------------------------------------
/// standard indexes into dbctx_ids[] and similar arrays
enum diff_source_idx_t
{
  NONE_IDX = -1,
  LOCAL_IDX = 0,
  REMOTE_IDX = 1,
  BASE_IDX = 2
};

//------------------------------------------------------------------------
#ifndef SWIG
#define DECLARE_DIFF_SOURCE_HELPERS(decl)\
decl void ida_export diff_source_merge_region(class diff_source_t *destination, class diff_source_t *source, const diff_range_t &dr);
#else
#define DECLARE_DIFF_SOURCE_HELPERS(decl)
#endif // SWIG

DECLARE_DIFF_SOURCE_HELPERS(idaman)

//------------------------------------------------------------------------
/// A difference source.
/// This abstract class provides information that is necessary for comparisons.
/// It can represent list of types, names, structs, enums.
/// It can also represent the program addresses, which can be used to
/// compare the attributes of the disassembly instructions, data, etc.
class diff_source_t
{
  friend class diff3_engine_t;
  diffpos_t get_lastpos(const diff_range_t &r)
  {
    diffpos_t last = check_position(r.end, DIFFPOS_BACKWARD);
    if ( last < r.start )
      last = r.end;
    if ( last == BADDIFF )
      last = r.start;
    return last;
  }

  void _merge_region(diff_source_t *source, const diff_range_t &dr);

  DECLARE_DIFF_SOURCE_HELPERS(friend)

public:
  int dbctx_id;
  diff_source_idx_t diffidx = NONE_IDX;
  diff_range_t range = diff_range_t(0, BADDIFF);
  diff_source_t(int id) : dbctx_id(id) {}

  virtual ~diff_source_t() {}

  /// initialize diff source.
  /// this function is called immediately before starting to use the diff source.
  /// this is the right place to read info from the idb for diffing.
  /// doing it earlier (for example, in the diff_source_t ctr) is wrong
  /// because a diff_source_t of one kind may depend on a diff_source_t of
  /// another kind. For example, crefs_diff_source_t depends on the flags_diff_source_t.
  /// It makes to start diffing only after completing work with flags.
  /// \note in short, do not perform initialization in the ctr, do it here!
  virtual void init_diff_source() {}

  /// set new range of positions
  virtual void set_range(const diff_range_t &r) { range = r; }

  /// get current range of positions
  virtual const diff_range_t &get_range() const { return range; }

  /// check the position, adjust and move it if requested
  /// if the requested position after DIFFPOS_FORWARD/DIFFPOS_BACKWARD does not
  /// exist, return a value outside of get_range()
  virtual diffpos_t check_position(diffpos_t dpos, diffpos_check_t adj=DIFFPOS_CHECK) const = 0;

  /// compare two difference source at the specified position.
  /// returns difference degree.
  /// 0 - no difference. non-zero return value mean that the chunks differ.
  /// the bigger the number, more important are differences.
  /// for simple cases please use 1 to indicate differences.
  virtual diff_degree_t compare_chunks(diff_source_t *src2, diffpos_t dpos) const = 0;

  /// find the next difference.
  /// this is an optional callback to speed up comparisons.
  /// \param dpos1 pointer to position in the current source.
  ///              out: position of the next difference.
  /// \param dpos2 pointer to position in the second source.
  ///              out: position of the next difference.
  /// \param src2  pointer to the second source.
  /// \return >= if implemented. the returned value is the difference degree,
  ///            the same thing as returned by compare_chunks
  virtual diff_degree_t find_next_diffpos(
        diffpos_t * /*dpos1*/,
        diffpos_t * /*dpos2*/,
        diff_source_t * /*src2*/) const
  {
    return -1; // not implemented
  }

  /// print the name at the specified position.
  /// usually it is the position name or a similar short string.
  virtual qstring print_diffpos_name(diffpos_t dpos) const = 0;

  /// print the details at the specified position.
  /// usually contains multiple lines, one for each attribute or detail.
  /// \note add details to OUT, do not clean the existing content
  virtual void print_diffpos_details(qstrvec_t * /*out*/, diffpos_t /*dpos*/) const {}

  /// merge from another diff source.
  /// this optional callback provides functionality to copy information
  /// from SRC at position DPOS.
  virtual void merge_add(diff_source_t * /*src*/, diffpos_t /*dpos*/) {}

  /// delete information at the specified position.
  virtual void merge_del(diffpos_t /*dpos*/) {}

  /// replace information at the position DPOS using SRC.
  /// the default implementation is provided below.
  virtual void merge_replace(diff_source_t *src, diffpos_t dpos)
  {
    merge_del(dpos);
    merge_add(src, dpos);
  }

  /// merge a region from another diff source.
  /// default implementation that uses one of merge_add/merge_del/merge_replace
  /// calls for each item in the region.
  /// A derived class may override this function to do that in a more optimal way
  virtual void merge_region(diff_source_t *src, const diff_range_t &region)
  {
    diff_source_merge_region(this, src, region);
  }

#ifdef TESTABLE_BUILD
  // dump the test results into the provided log file.
  // nb: there is no need to switch dbctx, it is already done.
  virtual void dump_merge_results(FILE * /*fp*/) const {}
#endif

  diff_texts_t print_range(const diff_range_t *r, bool with_details) const;
  void test_diffpos_behavior() const;
  bool is_valid_position(diffpos_t dpos) const
  {
    return get_range().contains(dpos) && check_position(dpos) == dpos;
  }
  diff_texts_t print_diff_source(bool with_details=true) const
  {
    return print_range(nullptr, with_details);
  }
};

//------------------------------------------------------------------------
enum merge_policy_t ENUM_SIZE(uint8)
{
  MERGE_POLICY_SKIP,       ///< do not merge
  MERGE_POLICY_USE_LOCAL,  ///< merge, resolve conflicts using local data
  MERGE_POLICY_USE_REMOTE, ///< merge, resolve conflicts using remote data
  MERGE_POLICY_POSTPONE,   ///< merge, do not resolve conflicts
  MERGE_POLICY_MDIFF,      ///< view mode: diff only, do not save the database
  MERGE_POLICY_VDIFF,      ///< view mode: visual diff only, do not save the database
  MERGE_POLICY_LAST,
};

//------------------------------------------------------------------------
/// A difference result.
/// This is the result of comparing 2 difference sources.
/// Essentially it is just a list of difference regions.
struct diff_result_t
{
  diff_source_t *src1;
  diff_source_t *src2;
  diff_regions_t regions;
  diff_result_t(diff_source_t *s1=nullptr, diff_source_t *s2=nullptr) : src1(s1), src2(s2) {}
  qstrvec_t print_region(const diff_region_t &b, bool with_details=true) const;
  qstrvec_t print_diff_result(bool with_details=true) const;
  size_t size() const { return regions.size(); }
  bool empty() const { return regions.empty(); }

  /// merge src1 and src2 into src1.
  /// removes the resolved regions from diff_result_t.
  /// \param merge_policy how to perform the merge
  /// \param i1 starting index in REGIONS
  /// \param i2 ending index in REGIONS (excluded)
  /// \return number of processed regions
  size_t merge_diff_sources(merge_policy_t merge_policy, size_t i1=0, size_t i2=SIZE_MAX);
private:
  bool merge_one_region(size_t n, merge_policy_t merge_policy) const;
};

//------------------------------------------------------------------------
/// A difference engine.
/// An abstract class that can perform a comparison.
class diff_engine_t
{
  friend class diff3_engine_t;
protected:
  diff_source_t *src1;
  diff_source_t *src2;

public:
  diff_engine_t(diff_source_t *_src1, diff_source_t *_src2)
    : src1(_src1), src2(_src2)
  {
  }
  virtual bool get_diff_regions(diff_regions_t *out) = 0;
  diff_result_t perform_diff();
};

//------------------------------------------------------------------------
/// A 2-way difference engine.
/// It compares 2 difference sources.
/// The result is symmetric wrt to src1 and src2.
/// diff_region_t::action is not provided by this engine.
class diff2_engine_t : public diff_engine_t
{
  // we maintain two positions to optimize calls to adjust_position
  // if you decide to remove one of them, please ensure that
  // std::lower_bound in testdiff3.cpp is not called too often
  diffpos_t pos1;
  diffpos_t pos2;
  diff_degree_t calc_diff_degree(diff_degree_t cur_degree);
public:
  diff2_engine_t(diff_source_t *_src1, diff_source_t *_src2)
    : diff_engine_t(_src1, _src2)
  {
    reset();
  }
  void reset();
  virtual bool get_diff_regions(diff_regions_t *out) override;
  bool get_diff_region(diff_region_t *out);
};

//------------------------------------------------------------------------
/// A 3-way difference engine.
/// It compares 2 difference sources: src1 and src2 but also uses their
/// common ancestor in order to resolve the situations when src1 and src2
/// do not match each other.
class diff3_engine_t : public diff2_engine_t
{
  diff2_engine_t de1; ///< between common base and src1
  diff2_engine_t de2; ///< between common base and src2
  diff2_engine_t de3; ///< between src1 and src2 (used to handle conflicts only)

public:
  diff3_engine_t(
        diff_source_t *base,
        diff_source_t *src1,
        diff_source_t *src2);
  virtual ~diff3_engine_t() {}
  virtual bool get_diff_regions(diff_regions_t *out) override;
};

/// Perform 3-way difference
/// \param base the base (common) source. if nullptr, then perform 2-way diff
/// \param src1 the first source (and destination)
/// \param src2 the second source
diff_result_t perform_diff3(
        diff_source_t *base,
        diff_source_t *src1,
        diff_source_t *src2);

qstrvec_t put_side_by_side(
        const char *const *headers,
        const diff_texts_t *const *linevecs,
        size_t n,
        int psbs_flags=0);
#define PSBS_DIFF_STARS 0x01    ///< show stars at diffing lines (***)
#define PSBS_ONLY_DIFFS 0x02    ///< skip lines without diffs

//-------------------------------------------------------------------------
/// diff result actions, \ref lcsdiff_t::diff \ref lcsdiff_t::diff_mod
enum lcsdiff_result_action_t
{
  TDLA_EQ = 0,  ///< items are equal
  TDLA_ADD,     ///< added items
  TDLA_SUB,     ///< removed items
  TDLA_MOD,     ///< updated items (new content)
};

//-------------------------------------------------------------------------
/// difference result,
/// stores vectors' items with action
/// to be applied to construct Y from X

/// result's portion
template<class T>
struct lcsdiff_res_part_t
{
  T part;                         ///< vector's items
  T x_part;                       ///< previous content, only for TDLA_MOD
  lcsdiff_result_action_t action; ///< action for items, \ref lcsdiff_result_action_t

  lcsdiff_res_part_t(lcsdiff_result_action_t _a) : action(_a) {}

  void append(const T &v, size_t idx) { part.push_back(v[idx]); }
  void reverse() { std::reverse(part.begin(), part.end()); }
};
// template specialisation for qstring vector
template<>
struct lcsdiff_res_part_t<qstring>
{
  qstring part;                   ///< vector's items
  qstring x_part;                 ///< previous content, only for TDLA_MOD
  lcsdiff_result_action_t action; ///< action for items, \ref lcsdiff_result_action_t

  lcsdiff_res_part_t(lcsdiff_result_action_t _a) : action(_a) {}

  void append(const qstring &v, size_t idx) { part.append(v[idx]); }
  void reverse() { if ( !part.empty() ) std::reverse(part.begin(), std::prev(part.end())); }
};
DECLARE_TYPE_AS_MOVABLE(lcsdiff_res_part_t<qstrvec_t>);
DECLARE_TYPE_AS_MOVABLE(lcsdiff_res_part_t<qstring>);

/// result
template<class T>
class lcsdiff_res_t : public qvector<lcsdiff_res_part_t<T>>
{
public:
  /// vector's items are equal
  void eq(const T &v, size_t idx)
  {
    lcsdiff_res_part_t<T> &part = set_action(TDLA_EQ);
    part.append(v, idx);
  }

  /// vector's item should be added
  void add(const T &v, size_t idx)
  {
    lcsdiff_res_part_t<T> &part = set_action(TDLA_ADD);
    part.append(v, idx);
  }

  /// vector's item should be deleted
  void sub(const T &v, size_t idx)
  {
    lcsdiff_res_part_t<T> &part = set_action(TDLA_SUB);
    part.append(v, idx);
  }

private:
  lcsdiff_res_part_t<T> &set_action(lcsdiff_result_action_t wanted_action)
  {
    if ( this->empty() || this->back().action != wanted_action )
      this->push_back(lcsdiff_res_part_t<T>(wanted_action));
    return this->back();
  }
};

//-------------------------------------------------------------------------
/// Calculate difference between two vectors.
/// Use Longest Common Subsequences (LCS) approach:
/// https://en.wikipedia.org/wiki/Longest_common_subsequence_problem
template<class T>
class lcsdiff_t
{
protected:
  const T &x;                     ///< left argument
  const T &y;                     ///< right argument
  const size_t n = 0;             ///< left argument size
  const size_t m = 0;             ///< right argument size
  sizevec_t lcs_table;            ///< table to store LCS for each step of the calculation

public:
  using result_t = lcsdiff_res_t<T>;
  result_t result;

  //------------------------------------------------------------------
  /// prepare LCS table
  lcsdiff_t(const T &_x, const T &_y, size_t _n, size_t _m)
    : x(_x),
      y(_y),
      n(_n),
      m(_m)
  {
    // allocate storage for TABLE
    // need an additional row/column at index 0
    const size_t rows = n + 1;
    const size_t cols = m + 1;
    lcs_table.resize(rows * cols);

    // compute the LCS for substring started from (i,j) indices
    for ( size_t i=0; i < rows; ++i )
    {
      for ( size_t j=0; j < cols; ++j )
      {
        if ( i == 0 || j == 0 )
        {
          table(i, j) = 0;
        }
        else if ( x[i - 1] == y[j - 1] )
        {
          table(i, j) = 1 + table(i - 1, j - 1);
        }
        else
        {
          size_t l = table(i - 1, j);
          size_t u = table(i, j - 1);
          table(i, j) = qmax(l, u);
        }
      }
    }
  }

  //------------------------------------------------------------------
  /// get a difference between two vectors
  /// RESULT will contain only TDLA_EQ, TDLA_ADD, TDLA_SUB actions
  void diff()
  {
    result.clear();
    size_t i = n;
    size_t j = m;
    while ( i != 0 || j != 0 )
    {
      // end of seq reached
      if ( i == 0 )
      {
        result.add(y, --j);
      }
      else if ( j == 0 )
      {
        result.sub(x, --i);
      }
      // Otherwise there's still parts of X and Y left. If the
      // currently considered parts are equal, then we found an unchanged
      // part which belongs to the longest common subsequence.
      else if ( x[i - 1] == y[j - 1] )
      {
        result.eq(x, --i);
        j--;
      }
      // In any other case, we go in the direction of the longest common subsequence.
      else if ( table(i - 1, j) <= table(i, j - 1) )
      {
        result.add(y, --j);
      }
      else
      {
        result.sub(x, --i);
      }
    }
    std::reverse(result.begin(), result.end());
    for ( auto &part : result )
      part.reverse();
  }

private:
  size_t &table(size_t i, size_t j)
  {
    const size_t idx = i * (m + 1) + j;
    QASSERT(2351, idx < lcs_table.size());
    return lcs_table[idx];
  }
};

//-------------------------------------------------------------------------
/// Base class for forming "colored" string (in HTML, for example)
struct txtdiff_printer_t
{
  enum event_t
  {
    init,          ///< start printing
    term,          ///< end printing

    // print lines
    next_line,     ///< start to print next line
                   ///< \param first (::bool) is the first line

    same_line,     ///< line is the same in X and Y, \ref TDLA_EQ
                   ///< \param (const char *)
    add_line,      ///< line is added to X, \ref TDLA_ADD
                   ///< \param line (const char *)
    del_line,      ///< line is removed from X, \ref TDLA_SUB
                   ///< \param line (const char *)
    mod_line,      ///< line is changed, \ref TDLA_MOD
                   ///< \param x_line (const char *) original X line
                   ///< \param y_line (const char *) new line
  };

  txtdiff_printer_t() {}
  virtual ~txtdiff_printer_t() {}

  virtual void on_event(event_t ev, ...) = 0;
};

//-------------------------------------------------------------------------
class txtdiff_t;

#ifndef SWIG
#define DECLARE_TXTDIFF_HELPERS(decl)\
decl void ida_export txtdiff_t_diff_mod(txtdiff_t *_this);\
decl void ida_export txtdiff_t_serialize(txtdiff_t *_this, txtdiff_printer_t &printer);
#else
#define DECLARE_TXTDIFF_HELPERS(decl)
#endif // SWIG

DECLARE_TXTDIFF_HELPERS(idaman)

//------------------------------------------------------------------------
/// Calculate difference between two string vectors.
class txtdiff_t : public lcsdiff_t<qstrvec_t>
{
public:
  txtdiff_t(const qstrvec_t &_x, const qstrvec_t &_y)
    : lcsdiff_t<qstrvec_t>(_x, _y, _x.size(), _y.size()) {}

  //--------------------------------------------------------
  /// calculate a difference and recognize lines modification
  /// If a TDLA_SUB will be followed by the TDLA_ADD,
  /// then collapse this sequence to TDLA_MOD and maybe TDLA_SUB/TDLA_ADD
  void diff_mod() { txtdiff_t_diff_mod(this); }

  //------------------------------------------------------------------------
  /// Create string with coloring
  /// In case of TDLA_MOD call diff() and serialize() for string
  void serialize(txtdiff_printer_t &printer) { txtdiff_t_serialize(this, printer); }

  //--------------------------------------------------------
  // Convenience methods

  /// Calculate the difference between two vectors in a visual way
  /// The RES lines will be prefixed with:
  /// "  " line as is
  /// "- " line was deleted
  /// "+ " line was added
  /// "* " line was changed
  static void visual_diff(qstrvec_t *res, const qstrvec_t &x, const qstrvec_t &y, bool use_mod=true)
  {
    txtdiff_t d(x, y);
    use_mod ? d.diff_mod() : d.diff();
    for ( const auto &dl : d.result )
    {
      char c = dl.action == TDLA_EQ  ? ' '
             : dl.action == TDLA_ADD ? '+'
             : dl.action == TDLA_SUB ? '-'
             :                         '*';   // TDLA_MOD
      for ( auto &p : dl.part )
        res->push_back().sprnt("%c %s", c, p.c_str());
    }
  }

private:
  DECLARE_TXTDIFF_HELPERS(friend)
  // do not call these functions directly, they are here only for exporting
  void _diff_mod();
  void _serialize(txtdiff_printer_t &printer);
};
#undef DECLARE_TXTDIFF_HELPERS

//-------------------------------------------------------------------------
/// Base class for forming "colored" string (in HTML, for example)
struct strdiff_printer_t
{
  enum event_t
  {
    init_chars,       ///< start printing
    term_chars,       ///< end printing

    same_chars,       ///< the same chars, \ref TDLA_EQ
                      ///< \param chars (const char *)
    add_chars,        ///< added chars to line from X, \ref TDLA_ADD
                      ///< \param chars (const char *)
    del_chars,        ///< deleted chars from line X, \ref TDLA_SUB
                      ///< \param chars (const char *)
  };

  strdiff_printer_t() {}
  virtual ~strdiff_printer_t() {}

  virtual void on_event(event_t ev, ...) = 0;
};

//-------------------------------------------------------------------------
class strdiff_t;

#ifndef SWIG
#define DECLARE_STRDIFF_HELPERS(decl)\
decl void ida_export strdiff_t_serialize(strdiff_t *_this, strdiff_printer_t &printer);
#else
#define DECLARE_STRDIFF_HELPERS(decl)
#endif // SWIG

DECLARE_STRDIFF_HELPERS(idaman)

//-------------------------------------------------------------------------
/// Calculate difference between two strings
class strdiff_t : public lcsdiff_t<qstring>
{
public:
  strdiff_t(const qstring &_x, const qstring &_y)
    : lcsdiff_t<qstring>(_x, _y, _x.length(), _y.length()) {}

  //------------------------------------------------------------------------
  /// Create string with coloring
  void serialize(strdiff_printer_t &printer) { strdiff_t_serialize(this, printer); }

private:
  DECLARE_STRDIFF_HELPERS(friend)
  // do not call these functions directly, they are here only for exporting
  void _serialize(strdiff_printer_t &printer);
};
#undef DECLARE_STRDIFF_HELPERS
#endif // _DIFF3_HPP
