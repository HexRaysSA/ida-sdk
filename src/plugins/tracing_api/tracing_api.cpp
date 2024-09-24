/* Tracing API sample plugin.
 *
 * Copyright (c) 2012-2024 Hex-Rays, support@hex-rays.com
 *
 * This sample plugin demonstrates how to use the tracing events API
 * in IDA v6.3
 *
 * The tracing events API allow you to record, save and load traces,
 * find register values as well as memory pointed by registers.
 *
 * This sample plugin looks for an ASCII string in the recorded
 * trace's memory
 *
 */

//---------------------------------------------------------------------------
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  bytevec_t last_found; // last found buffer

  virtual bool idaapi run(size_t) override;
  bool find_memory_tev(int i, const char *mem);
};

//--------------------------------------------------------------------------
inline bool __memmem(
        const unsigned char *where,
        size_t size1,
        const char *what,
        size_t size2)
{
  if ( size2 > size1 )
    return false;
  else if ( size2 == size1 )
    return memcmp(where, what, size1) == 0;

  int i = size1 - size2;
  do
  {
    if ( where[i] == what[0] )
    {
      if ( memcmp(where+i, what, size2) == 0 )
        return true;
    }
  }
  while ( --i >= 0 );

  return false;
}

//--------------------------------------------------------------------------
static void dump_memreg(const unsigned char *buf, size_t size)
{
  msg("Memory found: ");
  for ( int i = 0; i < size; i++ )
  {
    if ( isprint(buf[i]) )
      msg("%c", buf[i]);
    else
      msg(".");
  }
  msg("\n");
}

//--------------------------------------------------------------------------
bool plugin_ctx_t::find_memory_tev(int i, const char *mem)
{
  // retrieve the memory map
  memreg_infos_t memmap;
  if ( get_insn_tev_reg_mem(i, &memmap) )
  {
    // iterate over all elements in the map
    memreg_infos_t::iterator p;
    for ( p = memmap.begin(); p != memmap.end(); ++p )
    {
      memreg_info_t reg = *p;
      // compare the memory of this memreg_info_t object with the given
      // string mem
      if ( last_found != reg.bytes && __memmem(reg.bytes.begin(), reg.bytes.size(), mem, strlen(mem)) )
      {
        last_found = reg.bytes;
        // if found, print it to the output window
        dump_memreg(reg.bytes.begin(), reg.bytes.size());
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
  // clear the last found buffer
  last_found.clear();

  // get the number of recorded events
  size_t total = get_tev_qty();
  if ( total == 0 )
  {
    msg("No recorded events.");
    return true;
  }

  qstring mem_search;
  if ( !ask_str(&mem_search,
                HIST_SRCH,
                "Enter the string to search in the recorded trace:")
    || mem_search.empty() )
  {
    return true;
  }

  // iterate over all the recorded events
  for ( int i = total; i != 0; i-- )
  {
    // if the recorded event is an instruction trace event
    // search the string mem_search in the recorded memory
    tev_info_t tev;
    if ( get_tev_info(i, &tev) && tev.type == tev_insn )
    {
      // if the string is found in this instruction trace event's memory
      // print the tev object address, thread and number if the output
      // window
      const char *str = mem_search.begin();
      if ( find_memory_tev(i, str) )
        msg("%a: tid %d: string '%s' found in tev %d.\n", tev.ea, tev.tid, str, i);
    }
  }
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  "Search for a string in the recorded trace memory", // long comment about the plugin
  "", // multiline help about the plugin
  "Trace search",       // the preferred short name of the plugin
  "" // the preferred hotkey to run the plugin
};
