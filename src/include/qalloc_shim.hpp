// qalloc_shim.hpp
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <type_traits>

// This is for linters that do not understand __cpp_aligned_new
#if defined(__cpp_aligned_new) && (__cpp_aligned_new >= 201606)
  #define Q_HAS_ALIGNED_NEW 1
#else
  #define Q_HAS_ALIGNED_NEW 0
#endif

// ---------------------------------------------
// Policy *concept*
// ---------------------------------------------
// Policy must provide:
//   static void *allocate(std::size_t bytes) noexcept;
//   static void  deallocate(void *p) noexcept;
//
// The aligned path is implemented *here* via a portable bumping shim
// layered on top of the unaligned functions.
// See `qida_alloc_shim.hpp` for an example policy (used everywhere but tests).
// ---------------------------------------------

namespace qalloc_detail
{
  // If you call IDA's allocators, they will return pointers aligned to this
  static constexpr std::size_t k_min_platform_align = alignof(void *);

  // Since IDA does not provide alligned allocators, and C++17 often uses the
  // concept of aligned allocation, we provide a portable shim here.
  template<class Policy>
  struct unaligned_alloc_aligner
  {
    static inline bool is_pow2(std::size_t x) { return x && ((x & (x - 1)) == 0); }

    // This is the main entry point for aligned allocation. Since IDA's
    // allocators guarantee k_min_platform_align alignment, we only bump for
    // larger alignments.
    static void *aligned_allocate(std::size_t n, std::size_t al) noexcept
    {
      if ( al <= k_min_platform_align )
        return Policy::allocate(n);
      return portable_aligned_alloc(n, al);
    }

    // Call the above, and throw on failure.
    static void *aligned_allocate_or_throw(std::size_t n, std::size_t al)
    {
      if ( void *p = unaligned_alloc_aligner<Policy>::aligned_allocate(n, al) )
        return p;
      throw std::bad_alloc();
    }

    // Aligned deallocation: only unbump if a > alignof(void*).
    static void aligned_deallocate(void *p, std::size_t al) noexcept
    {
      if ( !p )
        return;
      if ( al <= k_min_platform_align )
        Policy::deallocate(p);
      else
        portable_aligned_free(p);
    }

  private:
    // Portable aligned allocation via overallocation + bumping (if needed).
    static inline void *portable_aligned_alloc(std::size_t size, std::size_t align) noexcept
    {
      if ( align < alignof(void *) )
        align = alignof(void *);
      if ( !is_pow2(align) )
        return nullptr;
      const std::size_t extra = align - 1 + sizeof(void *);
      if ( size > SIZE_MAX - extra )
        return nullptr;
      void *base = Policy::allocate(size + extra);
      if ( !base )
        return nullptr;
      std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(base) + sizeof(void *);
      std::uintptr_t aligned = (raw + (align - 1)) & ~(static_cast<std::uintptr_t>(align) - 1);
      reinterpret_cast<void **>(aligned)[-1] = base; // store base just before aligned
      return reinterpret_cast<void *>(aligned);
    }

    // Freeing the portable aligned allocation above.
    static inline void portable_aligned_free(void *p) noexcept
    {
      if ( !p )
        return;
      void *base = reinterpret_cast<void **>(p)[-1];
      Policy::deallocate(base);
    }
  };
}

// ---------------------------------------------
// Class-local new/delete for a *container type*,
// wired to a *Policy* that only has unaligned hooks.
// The aligned overloads use the portable shim above.
// ---------------------------------------------
// Always-available: scalar/array/placement using unaligned hooks
#define CXX17_MEMORY_ALLOCATION_FUNCS_USING_UNALIGNED_POLICY(Policy)                             \
  /* scalar new/delete via unaligned hooks */                                                    \
  static void *operator new(std::size_t n)                                                       \
  {                                                                                              \
    if ( void *p = Policy::allocate(n) )                                                         \
      return p;                                                                                  \
    throw std::bad_alloc();                                                                      \
  }                                                                                              \
  static void  operator delete(void *p) noexcept { Policy::deallocate(p); }                      \
  static void  operator delete(void *p, std::size_t) noexcept { Policy::deallocate(p); }         \
  /* array delegates to scalar (keeps one code path) */                                          \
  static void *operator new[](std::size_t n) { return operator new(n); }                         \
  static void  operator delete[](void *p) noexcept { operator delete(p); }                       \
  static void  operator delete[](void *p, std::size_t n) noexcept { operator delete(p, n); }     \
  /* placement */                                                                                \
  static void *operator new(std::size_t, void *p) noexcept { return p; }                         \
  static void  operator delete(void*, void*) noexcept {}

#if Q_HAS_ALIGNED_NEW
  // Only compiled when aligned new/delete are supported by the toolchain
#define CXX17_ALIGNED_NEWDELETE_USING_UNALIGNED_POLICY(Policy)                                     \
    /* aligned scalar new/delete: only bump if a > alignof(void*) */                               \
    static void *operator new(std::size_t n, std::align_val_t a)                                   \
    {                                                                                              \
      const std::size_t al = static_cast<std::size_t>(a);                                          \
      return qalloc_detail::unaligned_alloc_aligner<Policy>::aligned_allocate_or_throw(n, al);     \
    }                                                                                              \
    static void operator delete(void *p, std::align_val_t a) noexcept                              \
    {                                                                                              \
      const std::size_t al = static_cast<std::size_t>(a);                                          \
      qalloc_detail::unaligned_alloc_aligner<Policy>::aligned_deallocate(p, al);                   \
    }                                                                                              \
    static void operator delete(void *p, std::size_t, std::align_val_t a) noexcept                 \
    {                                                                                              \
      operator delete(p, a);                                                                       \
    }                                                                                              \
    /* aligned array delegates to aligned scalar */                                                \
    static void *operator new[](std::size_t n, std::align_val_t a) { return operator new(n, a); }  \
    static void  operator delete[](void *p, std::align_val_t a) noexcept { operator delete(p, a); }\
    static void  operator delete[](void *p, std::size_t n, std::align_val_t a) noexcept            \
    {                                                                                              \
      operator delete(p, n, a);                                                                    \
    }
#else
  // No aligned new/delete available: expand to nothing
#define CXX17_ALIGNED_NEWDELETE_USING_UNALIGNED_POLICY(Policy)
#endif

// Final convenience macro: unaligned + (conditionally) aligned
#define CXX17_MEMORY_ALLOCATION_FUNCS_USING_POLICY(Policy)                                       \
  CXX17_MEMORY_ALLOCATION_FUNCS_USING_UNALIGNED_POLICY(Policy)                                   \
  CXX17_ALIGNED_NEWDELETE_USING_UNALIGNED_POLICY(Policy)
