#include <pro.h>
#include "stack_unwind.hpp"

static const libunwind_pair_name_t libunwind_pair_name[] =
{
  { "libunwind-x86_64.so.8", "libunwind-ptrace.so.0" },
  { "libunwind-x86_64.so", "libunwind-ptrace.so" },
};

//----------------------------------------------------------
const char *stkunw_library_name()
{
  return libunwind_pair_name[0].libx86_64_name;
}

//----------------------------------------------------------
const libunwind_pair_name_t *stkunw_get_libraries(const char *path)
{
  for ( const auto &p : libunwind_pair_name )
  {
    if ( streq(p.libx86_64_name, path)
      || qisabspath(path) && streq(p.libx86_64_name, qbasename(path)) )
    {
      return &p;
    }
  }
  return nullptr;
}
