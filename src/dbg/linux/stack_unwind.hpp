#pragma once

#if defined(__EA64__) \
 && defined(USE_LIBUNWIND) \
 && !defined(__ANDROID__) \
 && !defined(__ARM__)
  #define HAVE_UPDATE_CALL_STACK
#endif

struct libunwind_pair_name_t
{
  const char *const libx86_64_name;
  const char *const libptrace_name;
};

const char *stkunw_library_name();
const libunwind_pair_name_t *stkunw_get_libraries(const char *path);
