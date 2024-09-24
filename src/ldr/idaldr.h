#ifndef __IDALDR_H__
#define __IDALDR_H__

#include <ida.hpp>
#include <fpro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <fixup.hpp>
#include <entry.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>

//----------------------------------

#define CLASS_CODE    "CODE"
#define NAME_CODE     ".text"
#define CLASS_DATA    "DATA"
#define CLASS_CONST   "CONST"
#define NAME_DATA     ".data"
#define CLASS_BSS     "BSS"
#define NAME_BSS      ".bss"
#define NAME_EXTERN   "extern"
#define NAME_COMMON   "common"
#define NAME_ABS      "abs"
#define NAME_UNDEF    "UNDEF"
#define CLASS_STACK   "STACK"
#define CLASS_RES16   "RESOURCE"
#define LDR_NODE      "$ IDALDR node for ids loading $"
#define LDR_INFO_NODE "$ IDALDR node for unload $"

//--------------------------------------------------------------------------
template <class T> bool _validate_array_count(
        linput_t *li,
        T *p_cnt,
        size_t elsize,
        int64 current_offset=-1,
        int64 max_offset=-1)
{
  if ( current_offset == -1 )
    current_offset = qltell(li);
  if ( max_offset == -1 )
    max_offset = qlsize(li);
  int64 rest = max_offset - current_offset;
  T cnt = *p_cnt;
  if ( current_offset >= 0 && rest >= 0 )
  {
#ifndef __X86__
    typedef size_t biggest_t;
#else
    typedef ea_t biggest_t;
#endif
    if ( is_mul_ok<biggest_t>(elsize, cnt) )
    {
      biggest_t needed = elsize * cnt;
#ifdef __X86__
      if ( needed == size_t(needed) )
#endif
        if ( rest >= needed )
          return true; // all ok
    }
    cnt = rest / elsize;
  }
  else
  {
    cnt = 0;
  }
  *p_cnt = cnt;
  return false;
}

//--------------------------------------------------------------------------
// Validate a counter taken from the input file. If there are not enough bytes
// in the input file, ask the user if we may continue and fix the counter.
template <class T> void validate_array_count(
        linput_t *li,
        T *p_cnt,
        size_t elsize,
        const char *counter_name,
        int64 curoff=-1,
        int64 maxoff=-1)
{
  T old = *p_cnt;
  if ( !_validate_array_count(li, p_cnt, elsize, curoff, maxoff) )
  {
    static const char *const format =
      "AUTOHIDE SESSION\n"
      "HIDECANCEL\n"
      "%s %" FMT_64 "u is incorrect, maximum possible value is %" FMT_64 "u%s";
#ifndef __KERNEL__
    if ( ask_yn(ASKBTN_YES,
                format,
                counter_name,
                uint64(old),
                uint64(*p_cnt),
                ". Do you want to continue with the new value?") != ASKBTN_YES )
    {
      loader_failure(nullptr);
    }
#else
    warning(format, counter_name, uint64(old), uint64(*p_cnt), "");
#endif
  }
}

//--------------------------------------------------------------------------
// Validate a counter taken from the input file. If there are not enough bytes
// in the input file, die.
template <class T> void validate_array_count_or_die(
        linput_t *li,
        T cnt,
        size_t elsize,
        const char *counter_name,
        int64 curoff=-1,
        int64 maxoff=-1)
{
  if ( !_validate_array_count(li, &cnt, elsize, curoff, maxoff) )
  {
    static const char *const format =
      "%s is incorrect, maximum possible value is %u%s";
#ifndef __KERNEL__
    loader_failure(format, counter_name, uint(cnt), "");
#else
    error(format, counter_name, uint(cnt), "");
#endif
  }
}

//-------------------------------------------------------------------------
// Read a string table in COFF format.
inline bool read_string_table(qstring *out, linput_t *li, qoff64_t filepos=0, bool mf=false)
{
  if ( filepos != 0 && qlseek(li, filepos, SEEK_SET) != filepos )
    return false;
  // read the string table length
  uint32 strtsize;
  if ( qlread(li, &strtsize, 4) != 4 )
    return false;
  if ( mf )
    strtsize = swap32(strtsize);

  // it includes the length field itself, so should be greater than 4
  if ( strtsize <= 4 )
    return false; // too small table

  qlseek(li, -4, SEEK_CUR);
#ifdef LOADER_COMPILE
  // Loaders display a message about the problematic size, to inform the user
  // and give him a choice.
  validate_array_count(li, &strtsize, 1, "String table size");
#else
  // Other modules silently fail.
  if ( !_validate_array_count(li, &strtsize, 1) )
    return false;
#endif

  char *stable = (char *)qalloc(strtsize + 1);
  if ( stable == nullptr )
    return false; // out of memory?!

  bool ok;
  if ( qlread(li, stable, strtsize) == strtsize )
  {
    stable[strtsize] = '\0';
    out->clear();
    out->inject(stable, strtsize + 1);
    ok = true;
  }
  else
  {
    qfree(stable);
    ok = false;
  }
  return ok;
}

//-------------------------------------------------------------------------
inline uchar readchar(linput_t *li)
{
  uchar x;
  lread(li, &x, sizeof(x));
  return x;
}

//-------------------------------------------------------------------------
inline uint16 readshort(linput_t *li)
{
  uint16 x;
  lread(li, &x, sizeof(x));
  return x;
}

//-------------------------------------------------------------------------
inline uint32 readlong(linput_t *li)
{
  uint32 x;
  lread(li, &x, sizeof(x));
  return x;
}

inline uint32 mf_readlong(linput_t *li)  { return swap32(readlong(li)); }
inline uint16 mf_readshort(linput_t *li) { return swap16(readshort(li)); }

// each loader must declare and export this symbol:
idaman loader_t ida_module_data LDSC;

#endif // __IDALDR_H__
