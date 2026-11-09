// FindCrypt - find constants used in crypto algorithms
// Copyright 2006 Ilfak Guilfanov <ig@hexblog.com>
// This is a freeware program.
// This copyright message must be kept intact.

// This plugin looks for constant arrays used in popular crypto algorithms.
// If a crypto algorithm is found, it will rename the appropriate locations
// of the program and put bookmarks on them.

// Version 2.0

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <moves.hpp>
#include <auto.hpp>

#include "findcrypt.hpp"

// #define VERIFY_CONSTANTS 1

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  plugin_ctx_t()
  {
    // agree to work with any database
#ifndef TESTABLE_BUILD
    hook_event_listener(HT_IDP, this);
#endif
  }
  ~plugin_ctx_t()
  {
    // listeners are uninstalled automatically
    // when the owner module is unloaded
  }

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//--------------------------------------------------------------------------
// retrieve the first byte of the specified array
// take into account the byte sex
inline uchar get_first_byte(const array_info_t *a)
{
  const uchar *ptr = (const uchar *)a->array;
  if ( !inf_is_be() )
    return ptr[0];
  return ptr[a->elsize-1];
}

//--------------------------------------------------------------------------
// check that all constant arrays are distinct (no duplicates)
//lint -e528 not used
#ifdef VERIFY_CONSTANTS
static void verify_constants(const array_info_t *consts)
{
  typedef std::set<qstring> strset_t;
  strset_t myset;
  for ( const array_info_t *ptr=consts; ptr->size != 0; ptr++ )
  {
    qstring s((char*)ptr->array, ptr->size);
    if ( !myset.insert(s).second )
      error("duplicate array %s!", ptr->name);
  }
}
#endif

//--------------------------------------------------------------------------
// match a constant array against the database at the specified address
static bool match_array_pattern(ea_t ea, const array_info_t *ai)
{
  uchar *ptr = (uchar *)ai->array;
  for ( size_t i=0; i < ai->size; i++ )
  {
    switch ( ai->elsize )
    {
      case 1:
        if ( get_byte(ea) != *(uchar*)ptr )
          return false;
        break;
      case 2:
        if ( get_word(ea) != *(ushort*)ptr )
          return false;
        break;
      case 4:
        if ( get_dword(ea) != *(uint32*)ptr )
          return false;
        break;
      case 8:
        if ( get_qword(ea) != *(uint64*)ptr )
          return false;
        break;
      default:
        error("interr: unexpected array '%s' element size %" FMT_Z,
              ai->name, ai->elsize);
    }
    ptr += ai->elsize;
    ea  += ai->elsize;
  }
  return true;
}

//--------------------------------------------------------------------------
// match a sparse array against the database at the specified address
// NB: all sparse arrays must be word32!
static bool match_sparse_pattern(ea_t ea, const array_info_t *ai)
{
  const word32 *ptr = (const word32*)ai->array;
  if ( get_dword(ea) != *ptr++ )
    return false;
  ea += 4;
  for ( size_t i=1; i < ai->size; i++ )
  {
    word32 c = *ptr++;
    if ( inf_is_be() )
      c = swap32(c);
    // look for the constant in the next N bytes
    const size_t N = 64;
    uchar mem[N+4];
    memset(mem, 0xFF, sizeof(mem));
    get_bytes(mem, sizeof(mem), ea);
    int j;
    for ( j=0; j < N; j++ )
      if ( *(uint32*)(mem+j) == c )
        break;
    if ( j == N )
      return false;
    ea += j + 4;
  }
  return true;
}

//--------------------------------------------------------------------------
// mark a location with the name of the algorithm
// use the first free slot for the marker
static void mark_location(ea_t ea, const char *name)
{
  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  uint32 i, n = bookmarks_t::size(e, nullptr);
  for ( i = 0; i < n; ++i )
  {
    qstring desc;
    lochist_entry_t loc(e);
    if ( !bookmarks_t::get(&loc, &desc, &i, nullptr) )
      break;
    // reuse old "Crypto: " slots
    if ( desc.starts_with("Crypto: ") && loc.place()->toea() == ea )
      break;
  }
  qstring buf;
  buf.sprnt("Crypto: %s", name);
  bookmarks_t::mark(e, i, nullptr, buf.c_str(), nullptr);
}

//--------------------------------------------------------------------------
// try to find constants at the given address range
static void recognize_constants(ea_t ea1, ea_t ea2)
{
  int count = 0;
  show_wait_box("Searching for crypto constants...");
  for ( ea_t ea=ea1; ea < ea2; ea=next_addr(ea) )
  {
    if ( (ea % 0x1000) == 0 )
    {
      show_addr(ea);
      if ( user_cancelled() )
        break;
    }
    uchar b = get_byte(ea);
    // check against normal constants
    for ( const array_info_t *ptr=non_sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != get_first_byte(ptr) )
        continue;
      if ( match_array_pattern(ea, ptr) )
      {
        msg("%a: found const array %s (used in %s)\n", ea, ptr->name, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        force_name(ea, ptr->name);
        count++;
        break;
      }
    }
    // check against sparse constants
    for ( const array_info_t *ptr=sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != get_first_byte(ptr) )
        continue;
      if ( match_sparse_pattern(ea, ptr) )
      {
        msg("%a: found sparse constants for %s\n", ea, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        count++;
        break;
      }
    }
  }
  hide_wait_box();
  if ( count != 0 )
    msg("Found %d known constant arrays in total.\n", count);
}

//--------------------------------------------------------------------------
// This callback is called for IDP notification events
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list /*va*/)
{
  if ( code == processor_t::ev_newfile ) // a new file has been loaded
    recognize_constants(inf_get_min_ea(), inf_get_max_ea());
  return 0;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  ea_t ea1;
  ea_t ea2;
  read_range_selection(nullptr, &ea1, &ea2); // if fails, inf.min_ea and inf.max_ea will be used
  recognize_constants(ea1, ea2);
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
#ifdef VERIFY_CONSTANTS
  verify_constants(non_sparse_consts);
  verify_constants(sparse_consts);
#endif
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char help[] = "Find crypt v2";
static const char comment[] = "Find crypt v2";
static const char wanted_name[] = "Find crypt v2";
static const char wanted_hotkey[] = "";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC           // Load plugin when a processor module is loaded
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
