#include "../ldr/pe/pe.h"
#include "win32/win32_rpc.h"

//--------------------------------------------------------------------------
inline void idaapi rebase_if_required_to(ea_t new_base)
{
  netnode penode(PE_NODE);
  ea_t currentbase = new_base;
  ea_t imagebase = ea_t(penode.altval(PE_ALT_IMAGEBASE)); // loading address (usually pe.imagebase)

  if ( imagebase == 0 )
  {
    if ( !is_miniidb() )
      warning("AUTOHIDE DATABASE\n"
              "IDA could not automatically determine if the program should be\n"
              "rebased in the database because the database format is too old and\n"
              "doesn't contain enough information.\n"
              "Create a new database if you want automated rebasing to work properly.\n"
              "Note you can always manually rebase the program by using the\n"
              "Edit, Segments, Rebase program command.");
  }
  else if ( imagebase != currentbase )
  {
    rebase_or_warn(imagebase, currentbase);
  }
}

//--------------------------------------------------------------------------
inline bool read_pe_header(peheader_t *pe)
{
  netnode penode(PE_NODE);
  return penode.valobj(pe, sizeof(peheader_t)) > 0;
}

//--------------------------------------------------------------------------
inline bool is_windows_binary(processor_t &ph)
{
  if ( inf_get_filetype() != f_PE )
    return false; // only PE files

  if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
    return false;

  // find out the pe header
  peheader_t pe;
  if ( !read_pe_header(&pe) )
    return false;

  // debug only gui, console, or unknown applications
  if ( pe.subsys != PES_WINGUI    // Windows GUI
    && pe.subsys != PES_WINCHAR   // Windows Character
    && pe.subsys != PES_UNKNOWN ) // Unknown
  {
    return false;
  }

  return true;
}

