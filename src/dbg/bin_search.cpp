#include <pro.h>
#include "debmod.h"

//#define TEST
#ifdef TEST
static uchar memory[256];
static const int PAGESZ = 4;
static ssize_t read_page(ea_t ea, void *buf, size_t size, qstring *)
{
  QASSERT(1517, (size % PAGESZ) == 0);
  if ( ea >= sizeof(memory) )
    return -1;
  memcpy(buf, &memory[ea], size);
  return size;
}
#else
static const int PAGESZ = 4096;
#define read_page(ea, buf, size, errbuf) mod->dbg_read_memory(ea, buf, size, errbuf)
#endif
static const int PAGE_HB = 1000;    // page heartbeat counter
static const int TIME_HB = (RECV_TIMEOUT_PERIOD/1000) / 2;
                                    // time period between heartbeats

//--------------------------------------------------------------------------
// memrchr is unavailable under Windows and MAC
#if defined(_WIN32) || defined(__MAC__)
// fixme: we need more optimized version
static void *local_memrchr(const void *s, int c, size_t n)
{
  const unsigned char *start = (const unsigned char *)s;
  const unsigned char *end = start + n - 1;
  while ( end >= start )
  {
    if ( *end == c )
      return (void *)end;
    end--;
  }
  return nullptr;
}
#else
#define local_memrchr memrchr
#endif

//--------------------------------------------------------------------------
class matcher_t
{
protected:
  struct partmatch_t
  {
    ea_t match_ea;  // starting address of the match
    size_t ptn_idx; // index of the pattern
    size_t ptn_off; // offset inside the pattern
  };
  typedef qlist<partmatch_t> partmatches_t;

  // constructor arguments
  ea_t *found_ea;
  debmod_t *mod;
  const compiled_binpat_vec_t &ptns;
  int srch_flags;
  qstring *errbuf;                                        //lint !e958

  uchar page[PAGESZ];
  ea_t page_ea;
  partmatches_t pmatches;
  ea_t failed_ea;

  // cache
  intvec_t simple_ptns;   // indexes of patterns w/o a mask and the search is case sensitive
  intvec_t complex_ptns;  // other patterns

  // heartbeat
  uint32 last_hb;         // time in secs of the last heartbeat

  matcher_t(
          ea_t *_found_ea,
          debmod_t *_mod,
          const compiled_binpat_vec_t &_ptns,
          int _srch_flags,
          qstring *_errbuf)
    : found_ea(_found_ea),
      mod(_mod),
      ptns(_ptns),
      srch_flags(_srch_flags),
      errbuf(_errbuf),
      page_ea(BADADDR),
      failed_ea(BADADDR)
  {
    for ( int i=0; i < ptns.size(); ++i )
    {
      const compiled_binpat_t &ptn = ptns[i];
      if ( ptn.bytes.empty() )
        continue;
      if ( sense_case() && ptn.all_bytes_defined() ) // TODO: && !inf_is_wide_high_byte_first() - for servers
        simple_ptns.push_back(i);
      else
        complex_ptns.push_back(i);
    }
    memset(page, 0, sizeof(page));
    last_hb = get_secs(qtime64());
  }

  bool sense_case(void)  const { return (srch_flags & BIN_SEARCH_CASE)    != 0; }
  bool check_break(void) const { return (srch_flags & BIN_SEARCH_NOBREAK) == 0; }

  bool test_cancelled(void) const
  {
    struct ida_local tester_t : public exec_request_t
    {
      virtual ~tester_t() {}
      virtual ssize_t idaapi execute(void) override
      {
        return user_cancelled();
      }
    };
    tester_t tester;
    return static_cast<bool>(execute_sync(tester, MFF_FAST));
  }

  void send_heartbeat(size_t *page_counter)
  {
    *page_counter += 1;
    if ( *page_counter >= PAGE_HB )
    {
      *page_counter = 0;
      uint32 now = get_secs(qtime64());
      if ( now - last_hb >= TIME_HB )
      {
        mod->dmsg("");    // heartbeat
        last_hb = now;
      }
    }
  }

public:
  virtual ~matcher_t()
  {
    found_ea = nullptr;
    mod = nullptr;
    errbuf = nullptr;
  }

  virtual drc_t walk_memory_ranges(const ea_t srch_start_ea, const ea_t srch_end_ea) = 0;

  drc_t search_memory_range(ea_t range_start_ea, ea_t range_end_ea)
  {
    if ( range_is_unreadable(range_start_ea) )
    {
      #ifndef TEST
      mod->debdeb("dbg_bin_search memory range %a..%a is unreadable, skip it\n", range_start_ea, range_end_ea);
      #endif
      return DRC_FAILED;
    }

    return find(range_start_ea, range_end_ea);
  }

  virtual drc_t find(ea_t start_ea, ea_t end_ea) = 0;

  bool match_pattern(
        const uchar *page_ptr,
        const compiled_binpat_t &ptn,
        size_t ptn_off,
        size_t nbytes) const
  {
    const uchar *ptn_ptr = ptn.bytes.begin() + ptn_off;
    const uchar *mask = ptn.all_bytes_defined() ? nullptr : ptn.mask.begin() + ptn_off;
    for ( int i=0; i < nbytes; ++i, ++page_ptr, ++ptn_ptr )
      if ( !bytes_match_for_bin_search(*page_ptr, *ptn_ptr, mask, i, srch_flags) )
        return false;
    return true;
  }

  ea_t get_failed_address(void) const { return failed_ea; }

private:
  bool range_is_unreadable(ea_t range_start_ea)
  {
    uchar dummy;
    return mod->dbg_read_memory(range_start_ea, &dummy, sizeof(dummy), nullptr) != sizeof(dummy);
  }
};

typedef janitor_t<matcher_t *> matcher_janitor_t;
template <> inline matcher_janitor_t::~janitor_t()
{
  delete resource;
  resource = nullptr;
}

//--------------------------------------------------------------------------
class forward_matcher_t : public matcher_t
{
  size_t last_off;

public:
  forward_matcher_t(
          ea_t *_found_ea,
          debmod_t *_mod,
          const compiled_binpat_vec_t &_ptns,
          int _srch_flags,
          qstring *_errbuf)
    : matcher_t(_found_ea, _mod, _ptns, _srch_flags, _errbuf),
      last_off(PAGESZ)
  {}

  //--------------------------------------------------------------------------
  virtual drc_t walk_memory_ranges(const ea_t srch_start_ea, const ea_t srch_end_ea) override
  {
    meminfo_vec_t::const_iterator p=mod->old_ranges.begin();
    ea_t range_start_ea = BADADDR;
    for ( ; p < mod->old_ranges.end(); ++p )
    {
      if ( p->contains(srch_start_ea) )
      {
        range_start_ea = srch_start_ea;
        break;
      }
      if ( p->start_ea > srch_start_ea )
        break;
    }
    if ( range_start_ea == BADADDR )
    {
      if ( p == mod->old_ranges.end() || p->start_ea >= srch_end_ea )
        return DRC_FAILED;    // not found
      range_start_ea = p->start_ea;
    }
    ea_t range_end_ea = srch_end_ea < p->end_ea ? srch_end_ea : p->end_ea;
    drc_t drc = search_memory_range(range_start_ea, range_end_ea);
    if ( drc != DRC_FAILED )  // not found
      return drc;

    for ( ++p; p < mod->old_ranges.end() && srch_end_ea >= p->end_ea; ++p )
    {
      range_start_ea = p->start_ea;
      range_end_ea = p->end_ea;
      drc = search_memory_range(range_start_ea, range_end_ea);
      if ( drc != DRC_FAILED )  // not found
        return drc;
    }

    return DRC_FAILED;    // not found
  }

  //--------------------------------------------------------------------------
  // find patterns in [start_ea, end_ea)
  virtual drc_t find(ea_t start_ea, ea_t end_ea) override
  {
    page_ea = align_down(start_ea, PAGESZ);
    ea_t page_off = start_ea - page_ea;
    size_t page_counter = 0;
    while ( page_ea < end_ea )
    {
      if ( check_break() && test_cancelled() )
        return DRC_ERROR;
      if ( read_page(page_ea, page, sizeof(page), errbuf) != sizeof(page) )
      {
        failed_ea = page_ea;
        return DRC_ERROR;
      }
      last_off = end_ea - page_ea;
      if ( last_off > PAGESZ )
        last_off = PAGESZ;
      // handle partial matches first
      for ( partmatches_t::iterator p=pmatches.begin(); p != pmatches.end(); )
      {
        switch ( finalize_partial_match(*p) )
        {
          case DRC_OK:          // found a match
            return DRC_OK;
          default:
          case DRC_FAILED:      // definitely failed
            p = pmatches.erase(p);
            break;
          case DRC_NONE:        // need to continue matching
            ++p;
            break;
        }
      }
      // try to find new matches
      if ( match_simple_patterns(page_off) )
        return DRC_OK;
      if ( !complex_ptns.empty() )
      {
        while ( page_off < last_off )
        {
          if ( match_at(page_off) )
            return DRC_OK;
          page_off++;
        }
      }
      page_ea += PAGESZ; // advance to the next page
      page_off = 0;
      send_heartbeat(&page_counter);
    }
    return DRC_FAILED;
  }

private:
  //--------------------------------------------------------------------------
  // try to match complex patterns at PAGE_OFF
  // too long patterns that do not fit the page will be matched partially
  // if the partial match is ok, we will remember them
  bool match_at(ea_t page_off)
  {
    const uchar *page_ptr = page + page_off;
    size_t rest = last_off - page_off;
    for ( intvec_t::const_iterator p=complex_ptns.begin();
          p != complex_ptns.end();
          ++p )
    {
      const int &i = *p;
      const compiled_binpat_t &ptn = ptns[i];
      size_t vecsize = ptn.bytes.size();
      size_t nbytes = qmin(rest, vecsize);
      if ( !match_pattern(page_ptr, ptn, 0, nbytes) )
        continue;
      if ( vecsize <= rest )
      {
        *found_ea = page_ea + page_off;
        return true; // fits the page, a simple comparison is enough
      }
      // remember partial match
      partmatch_t pm;
      pm.match_ea = page_ea + page_off;
      pm.ptn_idx = i;
      pm.ptn_off = nbytes;
      pmatches.push_back(pm);
    }
    return false;
  }

  //--------------------------------------------------------------------------
  // try to match simple patterns inside the page
  // the partial match is processed as described above
  bool match_simple_patterns(ea_t page_off)
  {
    for ( intvec_t::const_iterator p=simple_ptns.begin();
          p != simple_ptns.end();
          ++p )
    {
      const int &i = *p;
      const uchar *page_ptr = page + page_off;
      size_t rest = last_off - page_off;
      const bytevec_t &ptn_bytes = ptns[i].bytes;
      size_t ptn_sz = ptn_bytes.size();
      uchar ptn_ch = ptn_bytes[0];

      const uchar *pold = page_ptr;
      while ( rest > 0 )
      {
        const uchar *pnew = (uchar *)memchr(pold, ptn_ch, rest);
        if ( pnew == nullptr )
          break;
        rest -= (pnew - pold);
        size_t nbytes = qmin(rest, ptn_sz);
        if ( memcmp(pnew, ptn_bytes.begin(), nbytes) == 0 )
        {
          ea_t matched_ea = page_ea + (pnew - page);
          if ( ptn_sz <= rest )
          {
            *found_ea = matched_ea;
            return true;
          }
          // remember partial match
          partmatch_t pm;
          pm.match_ea = matched_ea;
          pm.ptn_idx = i;
          pm.ptn_off = nbytes;
          pmatches.push_back(pm);
        }
        pold = pnew + 1;
        rest -= 1;
      }
    }
    return false;
  }

  //--------------------------------------------------------------------------
  // try to finalize a partial match by matching the next part of the
  // long pattern against the start of the PAGE. patterns that are still
  // too long for matching may produce new partial matches.
  drc_t finalize_partial_match(partmatch_t &pm)
  {
    const compiled_binpat_t &ptn = ptns[pm.ptn_idx];
    size_t vecsize = ptn.bytes.size();
    size_t ptn_rest = vecsize - pm.ptn_off;
    size_t nbytes = qmin(ptn_rest, last_off);
    if ( !match_pattern(page, ptn, pm.ptn_off, nbytes) )
      return DRC_FAILED;
    if ( ptn_rest <= last_off )
    {
      *found_ea = pm.match_ea;
      return DRC_OK; // finalized the match
    }
    if ( last_off != PAGESZ )
      return DRC_FAILED;
    // remember a new partial match
    pm.ptn_off += PAGESZ;
    return DRC_NONE;
  }
};

//--------------------------------------------------------------------------
class backward_matcher_t : public matcher_t
{
  ea_t page_off;

public:
  backward_matcher_t(
          ea_t *_found_ea,
          debmod_t *_mod,
          const compiled_binpat_vec_t &_ptns,
          int _srch_flags,
          qstring *_errbuf)
    : matcher_t(_found_ea, _mod, _ptns, _srch_flags, _errbuf),
      page_off(0)
  {}

  //--------------------------------------------------------------------------
  virtual drc_t walk_memory_ranges(const ea_t srch_start_ea, const ea_t srch_end_ea) override
  {
    meminfo_vec_t::const_iterator p=mod->old_ranges.end() - 1;
    ea_t range_end_ea = BADADDR;
    for ( ; p >= mod->old_ranges.begin(); --p )
    {
      if ( p->start_ea < srch_end_ea )
      {
        range_end_ea = srch_end_ea < p->end_ea ? srch_end_ea : p->end_ea;
        break;
      }
    }
    if ( range_end_ea == BADADDR )
      return DRC_FAILED;    // not found
    ea_t range_start_ea = p->contains(srch_start_ea) ? srch_start_ea : p->start_ea;
    drc_t drc = search_memory_range(range_start_ea, range_end_ea);
    if ( drc != DRC_FAILED )  // not found
      return drc;

    for ( --p; p >= mod->old_ranges.begin() && srch_start_ea < p->end_ea; --p )
    {
      range_end_ea = p->end_ea;
      range_start_ea = p->contains(srch_start_ea) ? srch_start_ea : p->start_ea;
      drc = search_memory_range(range_start_ea, range_end_ea);
      if ( drc != DRC_FAILED )  // not found
        return drc;
    }

    return DRC_FAILED;    // not found
  }

  //--------------------------------------------------------------------------
  // find patterns in [start_ea, end_ea)
  virtual drc_t find(ea_t start_ea, ea_t end_ea) override
  {
    page_ea = align_down(end_ea - 1, PAGESZ);
    ea_t last_off = end_ea - page_ea;
    size_t page_counter = 0;
    while ( start_ea < page_ea + PAGESZ )
    {
      if ( check_break() && test_cancelled() )
        return DRC_ERROR;
      if ( read_page(page_ea, page, sizeof(page), errbuf) != sizeof(page) )
      {
        failed_ea = page_ea;
        return DRC_ERROR;
      }
      page_off = page_ea < start_ea ? start_ea - page_ea : 0;
      // handle partial matches first
      for ( partmatches_t::iterator p=pmatches.begin(); p != pmatches.end(); )
      {
        switch ( finalize_partial_match(*p) )
        {
          case DRC_OK:          // found a match
            return DRC_OK;
          default:
          case DRC_FAILED:      // definitely failed
            p = pmatches.erase(p);
            break;
          case DRC_NONE:        // need to continue matching
            ++p;
            break;
        }
      }
      // try to find new matches
      if ( match_simple_patterns(last_off) )
        return DRC_OK;
      if ( !complex_ptns.empty() )
      {
        while ( page_off < last_off )
        {
          if ( match_before(last_off) )
            return DRC_OK;
          last_off--;
        }
      }
      page_ea -= PAGESZ; // advance to the next page
      last_off = PAGESZ;
      send_heartbeat(&page_counter);
    }
    return DRC_FAILED;
  }

private:
  //--------------------------------------------------------------------------
  // try to match all patterns before LAST_OFF
  // too long patterns that do not fit the page will be matched partially
  // if the partial match is ok, we will remember them
  bool match_before(ea_t last_off)
  {
    size_t rest = last_off - page_off;
    for ( intvec_t::const_iterator p=complex_ptns.begin();
          p != complex_ptns.end();
          ++p )
    {
      const int &i = *p;
      const compiled_binpat_t &ptn = ptns[i];
      size_t vecsize = ptn.bytes.size();
      size_t nbytes = qmin(rest, vecsize);
      if ( !match_pattern(page+last_off-nbytes, ptn, vecsize-nbytes, nbytes) )
        continue;
      if ( vecsize <= rest )
      {
        *found_ea = page_ea + last_off - nbytes;
        return true; // fits the page, a simple comparison is enough
      }
      // remember partial match
      partmatch_t pm;
      pm.match_ea = page_ea + last_off - vecsize;
      pm.ptn_idx = i;
      pm.ptn_off = nbytes;
      pmatches.push_back(pm);
    }
    return false;
  }

  //--------------------------------------------------------------------------
  // try to match simple patterns inside the page
  // the partial match is processed as described above
  bool match_simple_patterns(ea_t last_off)
  {
    const uchar *page_ptr = page + page_off;

    for ( intvec_t::const_iterator q=simple_ptns.begin();
          q != simple_ptns.end();
          ++q )
    {
      const int &i = *q;
      size_t rest = last_off - page_off;
      const bytevec_t &ptn_bytes = ptns[i].bytes;
      size_t ptn_sz = ptn_bytes.size();
      uchar ptn_ch = ptn_bytes[ptn_sz-1];

      while ( rest > 0 )
      {
        const uchar *p = (uchar *)local_memrchr(page_ptr, ptn_ch, rest);
        if ( p == nullptr )
          break;
        rest = p + 1 - page_ptr;
        size_t nbytes = qmin(rest, ptn_sz);
        if ( memcmp(p + 1 - nbytes, &ptn_bytes[ptn_sz - nbytes], nbytes) == 0 )
        {
          ea_t matched_ea = page_ea + (p + 1 - page) - ptn_sz;
          if ( ptn_sz <= rest )
          {
            *found_ea = matched_ea;
            return true;
          }
          // remember partial match
          partmatch_t pm;
          pm.match_ea = matched_ea;
          pm.ptn_idx = i;
          pm.ptn_off = nbytes;
          pmatches.push_back(pm);
        }
        rest -= 1;
      }
    }
    return false;
  }

  //--------------------------------------------------------------------------
  // try to finalize a partial match by matching the previous part of the
  // long pattern against the end of the PAGE. patterns that are still
  // too long for matching may produce new partial matches.
  drc_t finalize_partial_match(partmatch_t &pm)
  {
    const compiled_binpat_t &ptn = ptns[pm.ptn_idx];
    size_t vecsize = ptn.bytes.size();
    size_t ptn_rest = vecsize - pm.ptn_off;
    size_t nbytes = qmin(ptn_rest, PAGESZ - page_off);
    if ( !match_pattern(page + PAGESZ - nbytes, ptn, ptn_rest - nbytes, nbytes) )
      return DRC_FAILED;
    if ( ptn_rest <= PAGESZ - page_off )
    {
      *found_ea = pm.match_ea;
      return DRC_OK; // finalized the match
    }
    if ( page_off != 0 )
      return DRC_FAILED;
    // remember a new partial match
    pm.ptn_off += PAGESZ;
    return DRC_NONE;
  }

};

#ifndef TEST
//--------------------------------------------------------------------------
// Note:
// The input search range can include the unreadable memory regions.
// For example, "[vvar]" on Linux.
// read_memory() returns 0 when trying to read from such region.
// These regions must be skipped.
drc_t idaapi debmod_t::dbg_bin_search(
        ea_t *found_ea,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &ptns,
        int srch_flags,
        qstring *errbuf)
{
  static int forbidden = -1;
  if ( forbidden == -1 )
    forbidden = qgetenv("IDA_IDB_BIN_SEARCH", nullptr);
  if ( forbidden )
    return DRC_NONE;

  debdeb("dbg_bin_search %a..%a\n", start_ea, end_ea);

  if ( start_ea >= end_ea || ptns.empty() || old_ranges.empty() )
    return DRC_NONE;

  //lint -esym(429,matcher) has not been freed
  matcher_t *matcher = nullptr;
  matcher_janitor_t matcher_janitor(matcher);

  bool search_backward = (srch_flags & BIN_SEARCH_BACKWARD) != 0;
  if ( search_backward )
    matcher = new backward_matcher_t(found_ea, this, ptns, srch_flags, errbuf);
  else
    matcher = new forward_matcher_t(found_ea, this, ptns, srch_flags, errbuf);

  drc_t drc = matcher->walk_memory_ranges(start_ea, end_ea);
  if ( drc != DRC_ERROR )
    return drc;   //-V773 without releasing the 'matcher' pointer

  ea_t failed_ea = matcher->get_failed_address();
  if ( failed_ea != BADADDR )
  {
    debdeb("dbg_bin_search failed to read memory at %a\n", failed_ea);
    if ( errbuf != nullptr && errbuf->empty() )
      errbuf->sprnt("Failed to read memory at %a\n", failed_ea);
  }

  return DRC_ERROR;
}

#else   // TEST
//--------------------------------------------------------------------------
drc_t binary_search(
        ea_t *found_ea,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &ptns,
        int srch_flags,
        qstring *errbuf)
{
  matcher_t *matcher;
  if ( (srch_flags & BIN_SEARCH_BACKWARD) != 0 )
    matcher = new backward_matcher_t(found_ea, nullptr, ptns, srch_flags, errbuf);
  else
    matcher = new forward_matcher_t(found_ea, nullptr, ptns, srch_flags, errbuf);
  drc_t drc = matcher->find(start_ea, end_ea);
  delete matcher;
  return drc;
}

//---------------------------------------------------------------------------
inline bool cmpbytes(
        const uchar *ptr,
        uchar b,
        const uchar *pptr,
        size_t ptnsize,
        bool sense_case)
{
  if ( sense_case )
    return *ptr == b && memcmp(ptr+1, pptr, ptnsize) == 0;  //lint !e670
  if ( qtoupper(b) != qtoupper(*ptr) )
    return false;
  ++ptr;
  for ( int i=0; i < ptnsize; ++i, ++ptr, ++pptr )
  {
    if ( qtoupper(*ptr) != qtoupper(*pptr) )
      return false;
  }
  return true;
}

//---------------------------------------------------------------------------
void *memmem(
        const void *buf,
        size_t bufsize,
        const void *ptn,
        size_t ptnsize,
        bool sense_case)
{
  if ( int(ptnsize) <= 0 || int(bufsize) < 0 || ptnsize > bufsize )
    return nullptr;
  const uchar *ptr = (const uchar *)buf;
  const uchar *const end = ptr + bufsize - ptnsize + 1;
  const uchar *pptr = (const uchar *)ptn;
  uchar b = *pptr++;
  ptnsize--;
  while ( ptr < end )
  {
    if ( cmpbytes(ptr, b, pptr, ptnsize, sense_case) )
      return (void *)ptr;
    ++ptr;
  }
  return nullptr;
}

//---------------------------------------------------------------------------
void *memmemr(
        const void *buf,
        size_t bufsize,
        const void *ptn,
        size_t ptnsize,
        bool sense_case)
{
  if ( int(ptnsize) <= 0 || int(bufsize) < 0 || ptnsize > bufsize )
    return nullptr;
  const uchar *ptr = (const uchar *)buf + bufsize - ptnsize;
  const uchar *const start = (const uchar *)buf;
  const uchar *pptr = (const uchar *)ptn;
  uchar b = *pptr++;
  ptnsize--;
  while ( start <= ptr )
  {
    if ( cmpbytes(ptr, b, pptr, ptnsize, sense_case) )
      return (void *)ptr;
    --ptr;
  }
  return nullptr;
}

//--------------------------------------------------------------------------
drc_t simple_binary_search(
        eavec_t *found_eas,
        ea_t start_ea,
        ea_t end_ea,
        const compiled_binpat_vec_t &ptns,
        int srch_flags,
        qstring * /*errbuf*/)
{
  if ( start_ea >= end_ea || start_ea > sizeof(memory) )
    return DRC_FAILED;
  bool sense_case = (srch_flags & BIN_SEARCH_CASE) != 0;
  found_eas->clear();
  bool backward = (srch_flags & BIN_SEARCH_BACKWARD) != 0;
  for ( compiled_binpat_vec_t::const_iterator p=ptns.begin();
        p != ptns.end();
        ++p )
  {
    const bytevec_t &vec = p->bytes;
    uchar *start = memory + start_ea;
    asize_t nbytes = qmin(sizeof(memory)-start_ea, end_ea-start_ea);
    uchar *f = (uchar *)(backward
                       ? memmemr(start, nbytes, vec.begin(), vec.size(), sense_case)
                       : memmem(start, nbytes, vec.begin(), vec.size(), sense_case));
    if ( f == nullptr )
      continue;
    ea_t idx = f - memory;
    if ( idx >= end_ea )
      continue;
    found_eas->push_back(idx);
  }
  return found_eas->empty() ? DRC_FAILED : DRC_OK;
}

//--------------------------------------------------------------------------
static bool check(qstring *found1_s, const eavec_t &found1, ea_t found2)
{
  bool ok = found1.empty() && found2 == BADADDR;
  for ( int k=0; k < found1.size(); ++k )
  {
    if ( found1[k] == found2 )
      ok = true;
    if ( k > 0 )
      found1_s->append(',');
    found1_s->cat_sprnt("%a", found1[k]);
  }
  if ( found1_s->empty() )
    found1_s->sprnt("%a", BADADDR);
  return ok;
}

//--------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  bool sense_case = false;
  int max_ptns = 3;
  for ( int i=1; i < argc; ++i )
  {
    char argch = argv[i][0];
    if ( argch == 'C' )
    {
      sense_case = true;
    }
    else if ( '0' < argch && argch <= '9' )
    {
      max_ptns = argch - '0';
    }
  }
  msg("Test bin_search with %d pattern[s] and %s\n",
      max_ptns,
      sense_case ? "case sensitive" : "case ignored");

  for ( int i=0; i < sizeof(memory); i++ )
    memory[i] = i;//rand();

  for ( int i=0; i < 1000000; i++ )
  {
    // prepare a pattern for searching
    compiled_binpat_vec_t ptns;
    int ptns_cnt = max_ptns == 1 ? 1 : (rand() % max_ptns) + 1;
    ptns.resize(ptns_cnt);
    qstring out;
    for ( int c=0; c < ptns.size(); c++ )
    {
      size_t off = rand() % sizeof(memory);
      size_t len = (rand() % sizeof(memory)/20) + 1;
      if ( (rand() % 50) == 0 )
        len += 8;
      compiled_binpat_t &pat = ptns[c];
      pat.bytes.resize(len, 0xFF);
      size_t copyable = qmin(sizeof(memory)-off, len);
      memcpy(pat.bytes.begin(), &memory[off], copyable);
      if ( c > 0 )
        out.append(",");
      out.cat_sprnt("%X:%X", int(off), int(len));
      // if some rare cases make the pattern possibly insearchable
      if ( (rand() % 50) == 0 )
      {
        pat.bytes[0] = 0xAA;
        out.append("-");
      }
    }
    ea_t start_ea = rand() % sizeof(memory);
    ea_t end_ea   = start_ea + (rand() % sizeof(memory));
    if ( end_ea > sizeof(memory) )
      end_ea = sizeof(memory);    // no need to test out of memory
    int flags = sense_case ? BIN_SEARCH_CASE : BIN_SEARCH_NOCASE;

    eavec_t found1;
    simple_binary_search(&found1, start_ea, end_ea, ptns, flags|BIN_SEARCH_FORWARD, nullptr);

    ea_t found2 = BADADDR;
    binary_search(&found2, start_ea, end_ea, ptns, flags|BIN_SEARCH_FORWARD, nullptr);

    qstring found1_s;
    bool ok = check(&found1_s, found1, found2);
    msg("%3d find (%s) in (%a..%a) => %s %a\n", i, out.c_str(), start_ea, end_ea, found1_s.c_str(), found2);
    if ( !ok )
    {
      msg("FAILED!\n");
      return 1;
    }

    found1.clear();
    simple_binary_search(&found1, start_ea, end_ea, ptns, flags|BIN_SEARCH_BACKWARD, nullptr);

    found2 = BADADDR;
    binary_search(&found2, start_ea, end_ea, ptns, flags|BIN_SEARCH_BACKWARD, nullptr);

    found1_s.qclear();
    ok = check(&found1_s, found1, found2);
    msg("%3d findr(%s) in (%a..%a) => %s %a\n", i, out.c_str(), start_ea, end_ea, found1_s.c_str(), found2);
    if ( !ok )
    {
      msg("FAILED!\n");
      return 1;
    }
  }
  msg("OK\n");
  return 0;
}
#endif    // TEST
