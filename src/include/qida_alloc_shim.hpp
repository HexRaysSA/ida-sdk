#pragma once

#include <pro.h>

struct ida_alloc_policy
{
  static void *allocate(size_t n) noexcept { return qalloc(n); }
  static void  deallocate(void *p) noexcept { qfree(p); }
};
