#pragma once

#include "qalloc_shim.hpp"

// Adapts an AllocPolicy to the C++ Allocator requirements (C++17).
template <class T, class AllocPolicy>
struct qallocator
{
  using value_type = T;
  using pointer = T *;
  using const_pointer = const T *;
  using void_pointer = void *;
  using const_void_pointer = const void *;
  using size_type = std::size_t;
  using difference_type = std::ptrdiff_t;

  // C++20 deprecates rebind, but allocator_traits still recognizes it in C++17.
  template <class U> struct rebind
  {
    using other = qallocator<U, AllocPolicy>;
  };

  // Enforce emptiness/statelessness for ABI reasons:
  static_assert(std::is_empty<AllocPolicy>::value,
    "Allocator policy must be empty/stateless for ABI stability");

  // Propagation and equality: all instances are interchangeable (stateless).
  using propagate_on_container_copy_assignment = std::true_type;
  using propagate_on_container_move_assignment = std::true_type;
  using propagate_on_container_swap = std::true_type;
  using is_always_equal = std::true_type;

  qallocator() noexcept = default;

  template <class U>
  qallocator(const qallocator<U, AllocPolicy> &) noexcept {}

  // Allocate n objects of T with proper alignment. Throw on failure.
  [[nodiscard]] pointer allocate(size_type n)
  {
    if ( n > max_size() )
      throw std::bad_alloc();
    const std::size_t bytes = n * sizeof(T);
    void *p = AlignedAllocPolicy::aligned_allocate(bytes, alignof(T));
    if ( !p )
      throw std::bad_alloc();
    return static_cast<pointer>(p);
  }

  void deallocate(pointer p, size_type /*n*/) noexcept
  {
    AlignedAllocPolicy::aligned_deallocate(p, alignof(T));
  }

  size_type max_size() const noexcept
  {
    return size_type(-1) / sizeof(T);
  }

  // All stateless allocators compare equal.
  bool operator==(const qallocator &) const noexcept { return true; }
  bool operator!=(const qallocator &) const noexcept { return false; }

private:
  // AllocPolicy is assumed to provide unaligned allocate/deallocate functions
  // that are noexcept. We use this to build an aligned allocator.
  using AlignedAllocPolicy = qalloc_detail::unaligned_alloc_aligner<AllocPolicy>;
};
