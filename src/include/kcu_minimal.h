#pragma once

#include <pro.h>

/*! \file kcu_minimal.h

  \brief Apple kernelcache (KernelCollection) vocabulary

  Which collection a kernelcache file, a KEXT or a cross-collection reference
  belongs to. This names a property of the file format, so it is kept apart
  from the kernelcache API (see kcu.h): file parsers determine a collection's
  kind and must not depend on the service that later exposes it.

*/

//-------------------------------------------------------------------------
/// Type of a KernelCollection. The values match the cacheLevel encoding of
/// the DYLD_CHAINED_PTR_*_KERNEL_CACHE chained fixups, and serve as the
/// "which collection" coordinate everywhere a KEXT or a cross-collection
/// reference is located (kext_coords_t, kcu_extref_t, kcu_linked_kc_info_t).
enum kc_type_t
{
  kc_none = -1,  ///< no collection
  kc_boot    = 0,  ///< base kernel collection (the kernel and its KEXTs)
  kc_system  = 1,  ///< system/pageable kext collection
  kc_aux     = 2,  ///< auxiliary kext collection (third-party KEXTs)
};

//-------------------------------------------------------------------------
/// Name of a collection type (e.g. "boot").
inline const char *kc_type_name(kc_type_t kc)
{
  switch ( kc )
  {
    case kc_none:   return "none";
    case kc_boot:   return "boot";
    case kc_system: return "system";
    case kc_aux:    return "aux";
  }
  return "?";
}
