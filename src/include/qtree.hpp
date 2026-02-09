#pragma once

// A C++17 red-black tree providing building blocks for qset and qmap. Intended
// for C++17. This header must not be included under non-default packing.
//
// Hex-Rays uses std::map and std::set in many places, but we cannot expose
// these types in the Hex-Rays SDK, because the ABI of the STL containers is not
// stable across compiler versions and standard library implementations. As a
// result, past SDKs have treated std::map and std::set as opaque types, which
// clients could only manipulate through helper functions provided by the SDK
// to handle all of the ordinary operations. This is cumbersome for both
// Hex-Rays internally as well as for SDK clients.
//
// This implementation provides similar functionality without exposing any
// non-empty type defined in the STL, to allow our SDK to expose map and set
// types directly, without helper functions.
//
// There are a few noteworthy aspects to this implementation:
//
// 1. Header-only implementation: SDK clients have access to our entire
//    implementation, without needing to link against SDK exports. When an SDK
//    client wants to perform a lookup, or an insertion, or a removal, their
//    compiler generates that code directly based on the code below. Thus,
//    their compiler needs to produce identical structure layouts to ours.
//
// 2. ABI: continuing the previous point, we must be careful to avoid any
//    implementation tricks that could lead to different structure layouts.
//    STL implementations commonly use empty base optimization to avoid storing
//    comparator and allocator instances in each container object, but as of
//    C++17, empty base optimization is not guaranteed to be applied in all
//    cases. Taking it further, we even eschew inheritance entirely due to
//    possible variations in structure layout: `qmap` composes a `qtree` rather
//    than inheriting from it, and forwards the public API to the composed
//    `qtree` instance. We also provide `qpair` as a replacement for
//    `std::pair`, so we own every non-empty type used herein.
//
//    The concrete node layout is intentionally standard-layout and relies only
//    on platform ABI rules; there are no compiler-specific extensions or
//    inheritance/EBO tricks. This makes the layout stable across MS/Itanium
//    ABIs and compilers that implement them.
//
//    The most important goal in this interface is that the data layout be
//    stable. Even if we were to identify bugs in the red-black algorithms,
//    we could fix them later without breaking ABI, as long as the data layout
//    is designed to be stable from the start. This goal seems very achievable,
//    given that MSVC has had a more-or-less identical layout for std::map and
//    std::set ever since the very first implementation. Changes to these
//    classes over the years have mostly been about adding new member
//    functions and improving performance, rather than changing the underlying
//    data layout.
//
// 3. Comparator and allocator: we require that both the comparator and
//    allocator types be empty and stateless. This way, Hex-Rays cannot rely on
//    hidden state that would not be visible to SDK clients (or would require
//    them to link against SDK exports to access comparator state).
//
// 4. Memory allocation: without overriding the allocator template parameter,
//    an ordinary implementation of set and map would ultimately route all
//    allocations and deallocations through operator new and delete. It would
//    be very bad if client code were using different underlying heaps from
//    Hex-Rays. Our template AllocPolicy parameter routes all allocations
//    through qalloc_shim.hpp, which in turn routes them through the IDA memory
//    management APIs. Thus, when client code wants to insert new elements, or
//    remove elements, all memory operations go through the IDA memory
//    management APIs, ensuring that everything is allocated and freed from the
//    same heap. Additionally, we define `operator new` and `operator delete`
//    for the base tree structure, to ensure that, if client code were to use
//    `operator new` to create a new map or set, or use `operator delete` to
//    destroy a map or set, that the allocations for the map and set itself
//    would go through the allocator specified as a template parameter. In
//    other words, both sides should be able to freely allocate and deallocate
//    qmap and qset objects via `operator new` and `operator delete`, and the
//    other side should be able to delete such objects regardless of which side
//    they were allocated on, without worrying about heap mismatches.
//
// 5. Exceptions: the trickiest part. Exceptions are another corner of C++ that
//    lacks a standardized ABI, meaning that exceptions thrown from inside of
//    Hex-Rays code may not be catchable from client code, and vice versa.
//
//    This code offers five possible sources of exceptions:
//    1. `qmap::at` throws `std::out_of_range`.
//    2. Memory allocation failures propagating through `node_new`. These can
//       happen any time we insert a new element and need to allocate memory,
//       or when copying the tree.
//    3. Constructors of the key / value types when inserting new elements.
//    4. Copy constructors of the key / value types when copying the tree.
//    5. Client code mutating map values in ways that throw exceptions.
//
//    Since this is a header-only implementation, exceptions thrown from this
//    code will be thrown by whoever invokes the exceptional functionality. So,
//    for example, if Hex-Rays calls `qmap::at`, it's responsible for the
//    exception. Identically, if a client calls `qmap::at` and it throws, that
//    exception will be thrown from their code, not from inside of Hex-Rays, so
//    they will be able to catch it normally. If they don't, it will propagate
//    up to Hex-Rays code, which might not be able to catch it. Clients must
//    catch exceptions, if they want their code to be exception-safe!
//
//    On the remaining points 2-5, note that IDA's existing discipline here is
//    not great. For example, qvector -- which has a header-only implementation
//    in pro.h -- calls `qalloc_or_throw` for its memory operations, which is
//    an SDK export. In other words, when a qvector reallocation operation
//    fails, the `throw` originates from inside of IDA rather than from client
//    code. This is bad for ABI compatability, because, as discussed above,
//    exceptions aren't guaranteed to cross module boundaries cleanly.
//
//    In this implementation of qmap and qset, memory operations are delegated
//    to template policy classes via the `AllocPolicy` parameters, which are
//    discussed more in `qalloc_shim.hpp`. In particular, we require that the
//    provided AllocPolicy's `allocate` function is `noexcept` -- i.e., it
//    returns `nullptr` instead of throwing on failure. `AllocPolicy` gets
//    wrapped up into a `qallocator`, which detects `nullptr` returns and
//    throws `std::bad_alloc`. The upshot of this is that allocation failures
//    will happen in client code, not inside of IDA. This addresses point 2
//    from above. As with point 1, if clients want their code to be
//    exception-safe, they need to catch such exceptions themselves.
//
//    Finally, points 3-5 are the worst, because they may originate from inside
//    of IDA rather than from client code. Let's imagine that:
//
//    A. Hex-Rays shared a `qmap<ea_t, eavec_t>` with the client.
//    B. The client made a copy of the `qmap`, which triggered a call to
//       the `eavec_t` copy constructor, and thus, `qalloc_or_throw`.
//    C. IDA threw an exception inside of `qalloc_or_thow`.
//
//    Because the exception from `qalloc_or_throw` originates inside of IDA,
//    the exception would have to traverse the client stack frames on the way
//    back up to IDA. This might lead to the exception not being caught. (This
//    situation comes from `qvector` using `qalloc_or_throw`, and doesn't
//    strictly have anything to do with `qmap` or `qset`.)
//
//    (Fortunately, the reverse should not happen: Hex-Rays should never end up
//    in a situation where it catches an exception thrown by a custom client
//    type, since Hex-Rays uses qmap and qset to share data with client code,
//    not the other way around. I.e., Hex-Rays code will never have to
//    construct or copy custom client key or value types. Clients are free to
//    use qmap and qset as replacements for std::map and std::set, but Hex-Rays
//    will never have to construct, copy, or mutate client-defined key/value
//    types; it only has to deal with types defined by Hex-Rays in the SDK.)
//
//    So, to summarize, the worst case for exceptions here stems from existing
//    deficiencies with regards to shared data types that may throw exceptions
//    across module boundaries, with `qalloc_or_throw` (and hence `qvector` and
//    `qstring`, and `qlist`) being the culprits.
//
//    The only thing I can think to do about this is to redefine
//    `qalloc_or_throw` and `qrealloc_or_throw` away from being exports, and
//    instead define them as inline functions that throw their exceptions on
//    the SDK client side, like this:
//
//    // First, add throw_nomem to pro.h
//    // Next, change the definition of qalloc_or_throw and qrealloc_or_throw:
//    INLINE void *qalloc_or_throw(size_t size)
//    {
//      if ( void *p = qalloc(size) )
//       return p;
//     throw_nomem();
//    }
//
//    INLINE void *qrealloc_or_throw(void *alloc, size_t size)
//    {
//      if ( void *p = qrealloc(alloc, size) )
//       return p;
//     throw_nomem();
//    }
//
//    Then whoever triggered an allocation would always be responsible for any
//    resulting exceptions. But I'm not sure if this would break anything about
//    the existing SDK <=> IDA regimen, and I don't have any other ideas if it
//    turns out to be unsuitable.

#include <algorithm> // for std::lexicographical_compare
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include "qallocator.hpp"
#include "qpair.hpp"
#include "qiterator.hpp"

namespace qtree_detail
{

// Forward declaration of the tester class.
class qtree_tester;

// --------------------------------------------------------------------------
// "Key selector" is the thing that makes sets different from maps. Maps store
// entries as qpair<key, value>, and the key selector extracts the key from
// the pair. Sets store entries as just the key, so the key selector is just
// the identity function.
// --------------------------------------------------------------------------
// The value selector used for sets: identity function.
template <class T>
struct identity_key
{
  using key_type = T;
  constexpr key_type const &operator()(T const &value) const noexcept
  {
    return value;
  }
};

// The value selector used for maps: select the 'first' member of a qpair.
// This is the forward declaration; there is intentionally only one
// specialization for qpair.
template <class Pair>
struct select_first;

template <class First, class Second>
struct select_first<qpair<First, Second>>
{
  using key_type = std::remove_const_t<First>;
  constexpr First const &operator()(qpair<First, Second> const &value) const noexcept
  {
    return value.first;
  }
};

// This is here so we can assert the key selector has `key_type` later on
template <class, class = void>
struct has_key_type : std::false_type {};

template <class T>
struct has_key_type<T, std::void_t<typename T::key_type>> : std::true_type {};

// --------------------------------------------------------------------------
// is_transparent trait: detects if Compare has a nested type is_transparent.
// This is used to enable heterogeneous lookup when the comparator supports it.
// --------------------------------------------------------------------------
template <class Compare, class = void>
struct is_transparent : std::false_type
{
};

template <class Compare>
struct is_transparent<Compare, std::void_t<typename Compare::is_transparent>> : std::true_type
{
};

template <class Compare>
static constexpr bool is_transparent_v = is_transparent<Compare>::value;

// --------------------------------------------------------------------------
// Comparator helper traits used for heterogeneous lookup.
//
// We want to enable find/lower_bound/etc. with key types K that are different
// from key_type (e.g., std::string_view vs std::string), but only when the
// comparator actually supports comparing those types. The following traits
// detect exactly that.

// is_cmp_invocable<C, A, B> is true if an expression of the form
//   std::declval<const C&>()(std::declval<A>(), std::declval<B>())
// is well-formed. In other words: can we call comparator C with argument
// types (A, B)?
template<class C, class A, class B, class = void>
struct is_cmp_invocable : std::false_type {};

template<class C, class A, class B>
struct is_cmp_invocable<C, A, B,
  std::void_t<decltype(std::declval<const C &>()(std::declval<A>(), std::declval<B>()))>> : std::true_type
{
};

// cmp(const Key&, const K&)
template<class Compare, class Key, class K>
static constexpr bool cmp_key_to_k_v =
   is_transparent_v<Compare>
&& is_cmp_invocable<Compare, const Key&, const K&>::value;

// cmp(const K&, const Key&)
template<class Compare, class K, class Key>
static constexpr bool cmp_k_to_key_v =
   is_transparent_v<Compare>
&& is_cmp_invocable<Compare, const K&, const Key&>::value;

// Need equality-style comparability: both directions work
template<class Compare, class Key, class K>
static constexpr bool cmp_bidir_v =
   cmp_key_to_k_v<Compare, Key, K>
&& cmp_k_to_key_v<Compare, K, Key>;

// --------------------------------------------------------------------------
// This is for linters that complain about std::launder usage. All of the
// compilers that we use support C++17, so std::launder is available.
#ifdef __CODE_CHECKER__
  template <class T> constexpr T *q_launder(T *p) noexcept { return p; }
#else
  template <class T> constexpr T *q_launder(T *p) noexcept { return std::launder(p); }
#endif

// --------------------------------------------------------------------------
// Used to implement the `value_compare` type for sets and maps. This is part
// of the standard interface for associative containers, so we provide it for
// compatibility. Compares Value by applying KeySelector then KeyCompare.
// --------------------------------------------------------------------------
template <class Value, class KeySelector, class KeyCompare>
struct value_compare_impl
{
  constexpr explicit value_compare_impl() {}
  constexpr bool operator()(Value const &a, Value const &b) const
    noexcept(noexcept(KeyCompare {} (KeySelector {} (a), KeySelector {} (b))))
  {
    return KeyCompare {} (KeySelector {} (a), KeySelector {} (b));
  }
};

// --------------------------------------------------------------------------
// Red-black color
enum class Color : uint8_t { Red, Black };

// We currently do not implement the C++17 API surface involving node handles
// (merge, extract). Also, `AllocPolicy` is not an allocator, but it used to
// construct an allocator. (Perhaps we should change this?)
template <class Value, class Compare, class AllocPolicy, bool PackNode, class KeySelector>
class qtree
{
  static_assert(!std::is_reference<Value>::value, "Value must not be a reference type");

  // Because we don't want SDK clients to have to link against data items for these things
  static_assert(std::is_empty<Compare>::value, "Compare must be empty and stateless");
  static_assert(std::is_empty<AllocPolicy>::value, "AllocPolicy must be empty");
  static_assert(std::is_empty<KeySelector>::value, "KeySelector must be empty and stateless");

  // Because we default-construct all of these things
  static_assert(std::is_default_constructible_v<Compare>, "Compare must be default-constructible");
  static_assert(std::is_default_constructible_v<AllocPolicy>, "AllocPolicy must be default-constructible");
  static_assert(std::is_default_constructible_v<KeySelector>, "KeySelector must be default-constructible");

  static_assert(has_key_type<KeySelector>::value, "KeySelector must define a nested 'key_type' typedef.");

  using key_selector = KeySelector;

  friend class qtree_detail::qtree_tester;

  template <class, class, class, class, bool>
  friend class qmap;

  // Definition of the main red-black tree node structure that holds the Value.
  // The Value is stored in a std::byte array with proper alignment, and
  // constructed/destructed in place. This allows us to have a single sentinel
  // nil node (header_) that does not hold a Value, saving memory (among other
  // design gains).
  //
  // Most of the red-black tree algorithms are implemented in the parent class
  // qtree, because they often require access to the header and/or root
  // node, i.e., they don't simply treat single nodes in isolation from one
  // another. As a consequence, qtree_node_packed doesn't need to know about
  // comparators and key selectors.

  // This version of `qtree_node` stores `is_nil` and `color` as fields, in
  // contrast to the one below that packs them into the `parent` pointer. We
  // need two separate structs for this, despite some duplication, for ABI
  // reasons.
  struct qtree_node_unpacked
  {
    friend class qtree;
    qtree_node_unpacked *_parent() noexcept             { return parent_; }
    qtree_node_unpacked const *_parent() const noexcept { return parent_; }
    void _set_parent(qtree_node_unpacked *p) noexcept { parent_ = p; }

    Color _color() const noexcept { return color_; }
    void _set_color(Color c) noexcept { color_ = c; }

    uint8_t _is_nil() const noexcept { return is_nil_; }
    void _set_is_nil(uint8_t is_nil) noexcept { is_nil_ = is_nil; }

  private:
    alignas(alignof(void *)) qtree_node_unpacked *parent_ = nullptr;
    alignas(alignof(void *)) qtree_node_unpacked *left_ = nullptr;
    alignas(alignof(void *)) qtree_node_unpacked *right_ = nullptr;
    Color color_ = Color::Black;
    uint8_t is_nil_ = true;
    alignas(Value) std::byte storage_[sizeof(Value)] = {};
  };

  // Static assertions that only apply to qtree_node_unpacked
  static_assert(offsetof(qtree_node_unpacked, parent_) == 0, "qtree_node_unpacked::parent_ must be at offset 0");
  static_assert(offsetof(qtree_node_unpacked, color_) == 3 * sizeof(void *), "qtree_node_unpacked::color_ must follow the three pointer-sized fields");
  static_assert(offsetof(qtree_node_unpacked, is_nil_) == 3 * sizeof(void *) + 1, "qtree_node_unpacked::is_nil_ must follow color_");
  static_assert(offsetof(qtree_node_unpacked, storage_) >= 3 * sizeof(void *) + 2, "qtree_node_unpacked::storage_ must follow is_nil_");

  // This version packs `color` and `is_nil` into the bottom 2 bits of `parent`.
  // It relies on a guarantee that the allocator returns addresses whose
  // alignment is at least 4 (so there will indeed be 2 unused bottom bits).
  struct qtree_node_packed
  {
    friend class qtree;
    qtree_node_packed *_parent() noexcept             { return untag(parent_and_tags_); }
    qtree_node_packed const *_parent() const noexcept { return untag(parent_and_tags_); }
    // preserve existing tags when changing the parent pointer
    void _set_parent(qtree_node_packed *p) noexcept { parent_and_tags_ = tagptr(p, parent_and_tags_); }

    Color _color() const noexcept { return ternary(color_mask_, Color::Red, Color::Black); }
    void _set_color(Color c) noexcept { set_or_clear(c == Color::Red, color_mask_); }

    uint8_t _is_nil() const noexcept { return ternary(nil_mask_, (uint8_t)1, (uint8_t)0); }
    void _set_is_nil(uint8_t is_nil) noexcept { set_or_clear(is_nil != 0, nil_mask_); }

  private:
    // parent pointer + {color,is_nil} packed in the low bits
    alignas(alignof(void *)) std::uintptr_t parent_and_tags_ = 0;
    alignas(alignof(void *)) qtree_node_packed *left_ = nullptr;
    alignas(alignof(void *)) qtree_node_packed *right_ = nullptr;
    alignas(Value) std::byte storage_[sizeof(Value)] = {};

    static_assert(alignof(void *) >= 4, "pointer tagging requires >= 2 tag bits");
    // Revisit this if we ever support any weird platforms
    static_assert(sizeof(void *) == sizeof(std::uintptr_t), "uintptr_t must match pointer size");

    // Support definitions/methods for bit packing.
    static constexpr std::uintptr_t color_mask_ = 0x1;      // bit 0
    static constexpr std::uintptr_t nil_mask_   = 0x2;      // bit 1
    static constexpr std::uintptr_t tag_mask_   = color_mask_ | nil_mask_;
    static constexpr std::uintptr_t ptr_mask_   = ~tag_mask_;

    // Remove the tag bits, obtain a pointer
    static qtree_node_packed *untag(std::uintptr_t v) noexcept
    {
      return reinterpret_cast<qtree_node_packed*>(v & ptr_mask_);
    }

    // Add tag bits to a pointer
    static std::uintptr_t tagptr(qtree_node_packed *p, std::uintptr_t tags) noexcept
    {
      return (reinterpret_cast<std::uintptr_t>(p) & ptr_mask_) | (tags & tag_mask_);
    }

    // Return a value based on mask
    template <class T> T ternary(std::uintptr_t mask, T t, T f) const noexcept
    {
      return (parent_and_tags_ & mask) ? t : f;
    }

    // Set or clear a bitmask based on bool
    void set_or_clear(bool b, std::uintptr_t mask)
    {
      if ( b )
        parent_and_tags_ |= mask;
      else
        parent_and_tags_ &= ~mask;
    }
  };

  // Static assertions that only apply to qtree_node_packed
  static_assert(offsetof(qtree_node_packed, parent_and_tags_) == 0, "qtree_node_packed::parent_and_tags_ must be at offset 0");
  static_assert(alignof(Value) > alignof(void *) || offsetof(qtree_node_packed, storage_) == 3 * sizeof(void *), "qtree_node_packed::storage_ must immediately follow right_");
  static_assert(alignof(Value) <= alignof(void *) || offsetof(qtree_node_packed, storage_) > 3 * sizeof(void *), "qtree_node_packed::storage_ must follow right_");

  // Choose the node type (packed or unpacked) based on PackNode template param
  using node_type = std::conditional_t<PackNode, qtree_node_packed, qtree_node_unpacked>;
  using node_alloc = qallocator<node_type, AllocPolicy>;
  using node_traits = std::allocator_traits<node_alloc>;
  static node_alloc make_node_alloc() noexcept { return node_alloc {}; }

  // Static assertions that apply to both node varieties
  static_assert(alignof(node_type) >= alignof(void *), "node alignment");
  static_assert(std::is_standard_layout<node_type>::value, "node_type must be standard layout");
  static_assert(offsetof(node_type, left_) % alignof(void *) == 0, "packed layout not allowed");
  static_assert(offsetof(node_type, left_) == sizeof(void *), "left_ must immediately follow parent field");
  static_assert(offsetof(node_type, right_) % alignof(void *) == 0, "packed layout not allowed");
  static_assert(offsetof(node_type, right_) == 2 * sizeof(void *), "right_ must immediately follow left_");
  static_assert(offsetof(node_type, storage_) % alignof(Value) == 0, "storage_ must be Value-aligned (don't compile under packing)");
  static_assert(alignof(node_type) >= (alignof(void *) > alignof(Value) ? alignof(void *) : alignof(Value)),"node alignment must meet pointer/value alignment");

public:
  using value_type = Value;
  using key_type = typename key_selector::key_type;
  using key_compare = Compare;
  using size_type = std::size_t;
  using difference_type = ptrdiff_t;
  using reference = value_type &;
  using const_reference = value_type const &;
  using pointer = value_type *;
  using const_pointer = value_type const *;
  using value_compare = qtree_detail::value_compare_impl<value_type, key_selector, key_compare>;
  using allocator_type = qallocator<value_type, AllocPolicy>;

  // This thing defines operator new/delete for the qtree type, such that if
  // you were to allocate a qtree via operator new, or delete a qtree via
  // operator delete, the allocation would go through the AllocPolicy.
  CXX17_MEMORY_ALLOCATION_FUNCS_USING_POLICY(AllocPolicy)

  // ----------------------- Public interface -------------------------------
  // One thing to note about qtree is that it always represents the empty
  // state without any material nodes. Initially, header_ is null and the
  // tree is completely header-less. On first insertion (or when copying /
  // moving from a non-empty tree) we allocate the sentinel header node.
  //
  // The header node serves double duty: it is the shared nil sentinel and
  // it caches the root/min/max pointers. The header node is black, its
  // parent points to the root, its left points to the minimum, and its
  // right points to the maximum. When the tree is empty but a header has
  // been allocated, the header's parent, left, and right all point to
  // itself.
  qtree() noexcept
    : header_(nullptr), node_count_(0)
  {
  }

  qtree(std::initializer_list<value_type> init) : qtree()
  {
    insert(init.begin(), init.end());
  }

  qtree(qtree const &other)
    : header_(nullptr), node_count_(0)
  {
    if ( other.empty() )
      return;

    header_ = allocate_header();
    node_count_ = 0;
    try
    {
      init_header();
      clone_from(other);           // may throw
    }
    catch ( ... )
    {
      node_delete(header_);        // prevent leak of header_ on failure
      throw;
    }
  }

  qtree(qtree &&other) noexcept
    : header_(other.header_), node_count_(other.node_count_)
  {
    other.header_ = nullptr;
    other.node_count_ = 0;
  }

  ~qtree()
  {
    if ( header_ != nullptr )
    {
      clear();
      node_delete(header_);
    }
  }

  qtree &operator=(qtree const &other)
  {
    if ( this == &other )
      return *this;
    qtree tmp(other);
    using std::swap;
    swap(*this, tmp);
    return *this;
  }

  qtree &operator=(qtree &&other) noexcept
  {
    if ( this == &other )
      return *this;

    // Destroy current contents
    if ( header_ != nullptr )
    {
      clear();
      node_delete(header_);
    }

    header_ = other.header_;
    node_count_ = other.node_count_;

    other.header_ = nullptr;
    other.node_count_ = 0;
    return *this;
  }

  void swap(qtree &other) noexcept
  {
    if ( this == &other )
      return;
    using std::swap;
    swap(header_, other.header_);
    swap(node_count_, other.node_count_);
  }
  friend void swap(qtree &a, qtree &b) noexcept(noexcept(a.swap(b))) { a.swap(b); }

  // ---------------------------------------------------------------------------
  // The familiar parts of the std::map/set interface: iteration.
  // ---------------------------------------------------------------------------

  // Bidirectional iterator for in-order traversal of the tree. Nothing fancy.
  class mutable_iterator
  {
  public:
    using iterator_category = std::bidirectional_iterator_tag;
    using difference_type = ptrdiff_t;
    using value_type = qtree::value_type;
    using pointer = value_type *;
    using reference = value_type &;

    mutable_iterator() noexcept = default;

    reference operator*() const noexcept { return *value_ptr(node_); }
    pointer operator->() const noexcept { return value_ptr(node_); }

    mutable_iterator &operator++()
    {
      increment();
      return *this;
    }

    mutable_iterator operator++(int)
    {
      mutable_iterator tmp(*this);
      increment();
      return tmp;
    }

    mutable_iterator &operator--()
    {
      decrement();
      return *this;
    }

    mutable_iterator operator--(int)
    {
      mutable_iterator tmp(*this);
      decrement();
      return tmp;
    }

    friend bool operator==(mutable_iterator lhs, mutable_iterator rhs) noexcept
    {
      return lhs.node_ == rhs.node_;
    }

    friend bool operator!=(mutable_iterator lhs, mutable_iterator rhs) noexcept
    {
      return !(lhs == rhs);
    }

  private:
    node_type *node_ = nullptr;

    explicit mutable_iterator(node_type *node) noexcept : node_(node)
    {
    }

    void increment() { node_ = successor(node_); }
    // --end(): when node_ is the sentinel, max is header_->right.
    // ++end(): undefined.
    void decrement() { node_ = prev_including_header(node_); }

    friend class qtree;
    friend class const_iterator;
    template <class, class, class, class, bool>
    friend class qmap;
  };

  static_assert(std::is_trivially_copyable<mutable_iterator>::value, "iter must be trivial");
  static_assert(sizeof(mutable_iterator) == sizeof(void *), "iter size must be 1 ptr");

  // Although const_iterator and iterator are nearly identical, if you were to
  // try to refactor them together (like I did), you'd find that you suddenly
  // experience many compiler errors that ultimately stem from const vs.
  // non-const contexts. So it's simpler to just duplicate the code, and due to
  // the factoring of most relevant functionality into qtree_node, the code is
  // simple enough, anyway.
  class const_iterator
  {
  public:
    using iterator_category = std::bidirectional_iterator_tag;
    using difference_type = ptrdiff_t;
    using value_type = qtree::value_type;
    using pointer = value_type const *;
    using reference = value_type const &;

    const_iterator() noexcept = default;
    const_iterator(mutable_iterator it) noexcept : node_(it.node_) {}

    reference operator*() const noexcept { return *value_ptr(node_); }
    pointer operator->() const noexcept { return value_ptr(node_); }

    const_iterator &operator++()
    {
      increment();
      return *this;
    }

    const_iterator operator++(int)
    {
      const_iterator tmp(*this);
      increment();
      return tmp;
    }

    const_iterator &operator--()
    {
      decrement();
      return *this;
    }

    const_iterator operator--(int)
    {
      const_iterator tmp(*this);
      decrement();
      return tmp;
    }

    friend bool operator==(const_iterator lhs, const_iterator rhs) noexcept
    {
      return lhs.node_ == rhs.node_;
    }

    friend bool operator!=(const_iterator lhs, const_iterator rhs) noexcept
    {
      return !(lhs == rhs);
    }

  private:
    node_type *node_ = nullptr;

    explicit const_iterator(node_type *node) noexcept : node_(node)
    {
    }

    void increment() { node_ = successor(node_); }
    // --end(): when node_ is the sentinel, max is header_->right.
    // ++end(): undefined.
    void decrement() { node_ = prev_including_header(node_); }

    friend class qtree;
  };

  static_assert(std::is_trivially_copyable<const_iterator>::value, "citer must be trivial");
  static_assert(sizeof(const_iterator) == sizeof(void *), "citer size must be 1 ptr");

  // qset uses const_iterator for both iterator and const_iterator; qmap uses
  // mutable_iterator for iterator and const_iterator for const_iterator.
  // long line because of checkstyle
  using iterator = typename std::conditional_t<std::is_same_v<KeySelector, qtree_detail::identity_key<Value>>,const_iterator,mutable_iterator>;
  using reverse_iterator = qiterator_detail::qreverse_iterator<iterator>;
  using const_reverse_iterator = qiterator_detail::qreverse_iterator<const_iterator>;

  iterator begin() noexcept
  {
    if ( header_ == nullptr || node_count_ == 0 )
      return end();
    return iterator(left(header_));
  }
  const_iterator begin() const noexcept
  {
    if ( header_ == nullptr || node_count_ == 0 )
      return end();
    return const_iterator(left(header_));
  }
  const_iterator cbegin() const noexcept { return begin(); }

  iterator end() noexcept { return iterator(header_); }
  const_iterator end() const noexcept { return const_iterator(header_); }
  const_iterator cend() const noexcept { return end(); }

  reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
  const_reverse_iterator rbegin() const noexcept { return const_reverse_iterator(end()); }
  const_reverse_iterator crbegin() const noexcept { return rbegin(); }

  reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
  const_reverse_iterator rend() const noexcept { return const_reverse_iterator(begin()); }
  const_reverse_iterator crend() const noexcept { return rend(); }

  // Mixed comparisons between iterator and const_iterator.
  friend bool operator==(mutable_iterator l, const_iterator r) noexcept { return const_iterator(l) == r; }
  friend bool operator==(const_iterator l, mutable_iterator r) noexcept { return l == const_iterator(r); }
  friend bool operator!=(mutable_iterator l, const_iterator r) noexcept { return !(l == r); }
  friend bool operator!=(const_iterator l, mutable_iterator r) noexcept { return !(l == r); }

  // ---------------------------------------------------------------------------
  // Below, determines whether heterogeneous lookup is enabled for the given
  // Compare, key type, and lookup key type K.
  // ---------------------------------------------------------------------------

  // For find/contains/count: we need both directions.
  template <class K>
  using enable_hetero_eq = std::enable_if_t<cmp_bidir_v<Compare, key_type, K>, int>;

  // For lower_bound: we only call cmp(node_key, key).
  template <class K>
  using enable_hetero_lb = std::enable_if_t<cmp_key_to_k_v<Compare, key_type, K>, int>;

  // For upper_bound: we only call cmp(key, node_key).
  template <class K>
  using enable_hetero_ub = std::enable_if_t<cmp_k_to_key_v<Compare, K, key_type>, int>;

  // For equal_range(K): we call both lower_bound_node(K) and upper_bound_node(K).
  template <class K>
  using enable_hetero_eqrange = std::enable_if_t<cmp_key_to_k_v<Compare, key_type, K> && cmp_k_to_key_v<Compare, K, key_type>, int>;

  // Unused, but, outside code can use this to test whether `K` can be used as
  // a heterogenous key.
  template<class K>
  static constexpr bool supports_heterogeneous_key_v = cmp_bidir_v<Compare, key_type, K>;

  // ---------------------------------------------------------------------------
  // The familiar parts of the std::map/set interface: query/lookup/comparisons.
  // As in the standard, functions that look keys up are deliberately not
  // noexcept, because the comparator might throw an exception.
  // ---------------------------------------------------------------------------

  bool empty() const noexcept { return node_count_ == 0; }
  size_type size() const noexcept { return node_count_; }

  friend bool operator==(qtree const &a, qtree const &b)
  {
    if ( a.size() != b.size() )
      return false;
    return std::equal(a.begin(), a.end(), b.begin());
  }

  friend bool operator!=(qtree const &a, qtree const &b)
  {
    return !(a == b);
  }

  // Relational operators mirror std::set/map semantics: lexicographical compare
  // of value_type using its natural operator<. For sets, this compares keys.
  // For maps, this compares std::pair which compares both key AND mapped value.
  friend bool operator<(qtree const &a, qtree const &b)
  {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
  }

  friend bool operator>(qtree const &a, qtree const &b)
  {
    return b < a;
  }

  friend bool operator<=(qtree const &a, qtree const &b)
  {
    return !(b < a);
  }

  friend bool operator>=(qtree const &a, qtree const &b)
  {
    return !(a < b);
  }

  [[nodiscard]] iterator find(key_type const &key)
  {
    return iterator(find_node(key));
  }

  [[nodiscard]] const_iterator find(key_type const &key) const
  {
    return const_iterator(find_node(key));
  }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] iterator find(K const &key)
  {
    return iterator(find_node(key));
  }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] const_iterator find(K const &key) const
  {
    return const_iterator(find_node(key));
  }

  [[nodiscard]] bool contains(key_type const &key) const
  {
    return find_node(key) != header_;
  }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] bool contains(K const &key) const
  {
    return find_node(key) != header_;
  }

  [[nodiscard]] size_type count(key_type const &key) const
  {
    return contains(key) ? 1u : 0u;
  }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] size_type count(K const &key) const
  {
    return contains(key) ? 1u : 0u;
  }

  [[nodiscard]] iterator lower_bound(key_type const &key)
  {
    return iterator(lower_bound_node(key));
  }

  [[nodiscard]] const_iterator lower_bound(key_type const &key) const
  {
    return const_iterator(lower_bound_node(key));
  }

  template <class K, class = enable_hetero_lb<K>>
  [[nodiscard]] iterator lower_bound(K const &key)
  {
    return iterator(lower_bound_node(key));
  }

  template <class K, class = enable_hetero_lb<K>>
  [[nodiscard]] const_iterator lower_bound(K const &key) const
  {
    return const_iterator(lower_bound_node(key));
  }

  [[nodiscard]] iterator upper_bound(key_type const &key)
  {
    return iterator(upper_bound_node(key));
  }

  [[nodiscard]] const_iterator upper_bound(key_type const &key) const
  {
    return const_iterator(upper_bound_node(key));
  }

  template <class K, class = enable_hetero_ub<K>>
  [[nodiscard]] iterator upper_bound(K const &key)
  {
    return iterator(upper_bound_node(key));
  }

  template <class K, class = enable_hetero_ub<K>>
  [[nodiscard]] const_iterator upper_bound(K const &key) const
  {
    return const_iterator(upper_bound_node(key));
  }

  [[nodiscard]] qpair<iterator, iterator> equal_range(key_type const &key)
  {
    return { lower_bound(key), upper_bound(key) };
  }

  [[nodiscard]] qpair<const_iterator, const_iterator> equal_range(key_type const &key) const
  {
    return { lower_bound(key), upper_bound(key) };
  }

  template <class K, class = enable_hetero_eqrange<K>>
  [[nodiscard]] qpair<iterator, iterator> equal_range(K const &key)
  {
    return { iterator(lower_bound_node(key)), iterator(upper_bound_node(key)) };
  }

  template <class K, class = enable_hetero_eqrange<K>>
  [[nodiscard]] qpair<const_iterator, const_iterator> equal_range(K const &key) const
  {
    return { const_iterator(lower_bound_node(key)), const_iterator(upper_bound_node(key)) };
  }

  // ---------------------------------------------------------------------------
  // The familiar parts of the std::map/set interface: insertion.
  // ---------------------------------------------------------------------------

  template <class InputIt>
  void insert(InputIt first, InputIt last)
  {
    for ( ; first != last; ++first )
      insert(*first);
  }

  void insert(std::initializer_list<value_type> init)
  {
    insert(init.begin(), init.end());
  }

  qpair<iterator, bool> insert(value_type const &value)
  {
    return lazy_emplace_impl(
      KeySelector {} (value),
      [&](value_type *slot) { ::new ((void*)slot) value_type(value); } );
  }

  qpair<iterator, bool> insert(value_type &&value)
  {
    return lazy_emplace_impl(
      KeySelector {} (value),
      [&](value_type *slot) { ::new ((void*)slot) value_type(std::move(value)); } );
  }

  iterator insert(const_iterator hint, value_type const &value)
  {
    auto result = lazy_emplace_with_hint(
      KeySelector {} (value),
      hint,
      [&](value_type *slot) { ::new ((void*)slot) value_type(value); } );
    return result.first;
  }

  iterator insert(const_iterator hint, value_type &&value)
  {
    auto result = lazy_emplace_with_hint(
      KeySelector {} (value),
      hint,
      [&](value_type *slot) { ::new ((void*)slot) value_type(std::move(value)); } );
    return result.first;
  }

  template <class... Args>
  qpair<iterator, bool> emplace(Args &&...args)
  {
    value_type tmp(std::forward<Args>(args)...);
    return lazy_emplace_impl(
      KeySelector {} (tmp),
      [&](value_type *slot) { ::new ((void*)slot) value_type(std::move(tmp)); } );
  }

  template <class... Args>
  iterator emplace_hint(const_iterator hint, Args &&...args)
  {
    value_type tmp(std::forward<Args>(args)...);
    auto result = lazy_emplace_with_hint(
      KeySelector {} (tmp),
      hint,
      [&](value_type *slot) { ::new ((void*)slot) value_type(std::move(tmp)); } );
    return result.first;
  }

  // ---------------------------------------------------------------------------
  // The familiar parts of the std::map/set interface: removal.
  // ---------------------------------------------------------------------------

  iterator erase(const_iterator pos)
  {
    iterator mutable_it(pos.node_);
    ++mutable_it;
    // Advance iterator before erase_node() so we never touch the freed node.
    erase_node(pos.node_);
    return mutable_it;
  }

  iterator erase(const_iterator first, const_iterator last)
  {
    iterator it(first.node_);
    iterator last_it(last.node_);
    while ( it != last_it )
      it = erase(it);
    return it;
  }

  size_type erase(key_type const &key)
  {
    node_type *node = find_node(key);
    if ( node == header_ )
      return 0;
    erase_node(node);
    return 1;
  }

  template <class K, class = enable_hetero_eq<K>>
  size_type erase(K const &key)
  {
    node_type *node = find_node(key);
    if ( node == header_ )
      return 0;
    erase_node(node);
    return 1;
  }

  template<class Pred>
  size_type erase_if(Pred pred)
  {
    size_type n = 0;
    for ( auto it = begin(); it != end(); )
    {
      if ( pred(*it) )
      {
        it = erase(it);
        ++n;
      }
      else
        ++it;
    }
    return n;
  }

  void clear() noexcept
  {
    if ( header_ == nullptr || node_count_ == 0 )
    {
      // header-less empty, or already empty with a header
      node_count_ = 0;
      if ( header_ != nullptr )
        init_header(); // keep sentinel, just normalize its links
      return;
    }

    clear_subtree(root());  // frees all non-header nodes
    init_header();          // make header_ the self-linked nil node again
    node_count_ = 0;
  }

  // ---------------------------------------------------------------------------
  // Less-familiar parts of the std::map/set interface.
  // ---------------------------------------------------------------------------

  // These two are part of std::set/map interface, so we replicate them.
  key_compare key_comp() const noexcept { return key_compare {}; }
  value_compare value_comp() const noexcept { return value_compare {}; }
  allocator_type get_allocator() const noexcept { return allocator_type {}; }
  size_type max_size() const noexcept { return get_allocator().max_size(); }

private:
  // ---------------------------------------------------------------------------
  // General red-black tree stuff. Factored out of the qtree_node variants above
  // to prevent duplication and allow easier refactoring in the future.
  // ---------------------------------------------------------------------------
  static node_type *left(node_type *node) noexcept { return node->left_; }
  static node_type const *left(const node_type *node) noexcept { return node->left_; }
  static void set_left(node_type *node, node_type *left) noexcept { node->left_ = left; }

  static node_type *right(node_type *node) noexcept { return node->right_; }
  static node_type const *right(const node_type *node) noexcept { return node->right_; }
  static void set_right(node_type *node, node_type *right) noexcept { node->right_ = right; }

  static node_type *parent(node_type *node) noexcept { return node->_parent(); }
  static node_type const *parent(const node_type *node) noexcept { return node->_parent(); }
  static void set_parent(node_type *node, node_type *parent) noexcept { node->_set_parent(parent); }

  static Color color(const node_type *node) noexcept { return node->_color(); }
  static void set_color(node_type *node, Color color_val) noexcept { node->_set_color(color_val); }

  static std::uint8_t is_nil(const node_type *node) noexcept { return node->_is_nil(); }
  static void set_is_nil(node_type *node, std::uint8_t is_nil_val) noexcept { node->_set_is_nil(is_nil_val); }

  // Descend to the left-most non-nil descendant of `node`. In a binary search
  // tree this is the smallest key in the subtree, so this helper is used when
  // we need to find the in-order beginning of a subtree (e.g., during erase
  // and when updating the header extrema). The precondition is that `node`
  // represents a material element and therefore is not the sentinel header.
  // Can throw due to `QASSERT`.
  static node_type *minimum(node_type *node)
  {
    return minimum_impl(node);
  }
  static const node_type *minimum(const node_type *node)
  {
    return minimum_impl(const_cast<node_type *>(node));
  }
  static node_type *minimum_impl(node_type *node)
  {
    QASSERT(3437, !is_nil(node));
    while ( !is_nil(left(node)) )
    {
      // Keep walking left until we hit the sentinel; that node owns the
      // smallest key in this subtree.
      node = left(node);
    }
    return node;
  }

  // Mirror of minimum(): walk right until we hit the greatest element in the
  // subtree rooted at `node`. Returning the right-most node lets us refresh
  // the header extrema quickly after mutations.
  // Can throw due to `QASSERT`.
  static node_type *maximum(node_type *node)
  {
    return maximum_impl(node);
  }
  static const node_type *maximum(const node_type *node)
  {
    return maximum_impl(const_cast<node_type *>(node));
  }
  static node_type *maximum_impl(node_type *node)
  {
    QASSERT(3438, !is_nil(node));
    while ( !is_nil(right(node)) )
    {
      // Mirror minimum(): keep walking right to find the largest key.
      node = right(node);
    }
    return node;
  }

  // Symmetric to predecessor(): either descend into the left-most child of
  // the right subtree, or climb parents until we traverse a left edge. When
  // visiting the sentinel (successor of end()), callers will receive header_.
  // Can throw due to `QASSERT`.
  static node_type *successor(node_type *node)
  {
    return successor_impl(node);
  }
  static const node_type *successor(const node_type *node)
  {
    return successor_impl(const_cast<node_type *>(node));
  }
  static node_type *successor_impl(node_type *node)
  {
    if ( is_nil(node) )
    {
      // end() stays end() if incremented; still outside supported contract.
      return node;
    }
    if ( !is_nil(right(node)) )
    {
      // Successor is the minimum of the right subtree when it exists.
      return minimum(right(node));
    }
    node_type *parent_node = parent(node);
    while ( !is_nil(parent_node) && node == right(parent_node) )
    {
      // Bubble up until we exit through a right edge; the first left turn
      // gives us the next greater node (or the header sentinel).
      node = parent_node;
      parent_node = parent(parent_node);
    }
    return parent_node;
  }

  // Compute the in-order predecessor of `node`. If a left child exists we go
  // to its right-most descendant; otherwise we bubble up towards the root
  // until we take the first right turn. The header sentinel acts as the
  // predecessor of begin() which keeps iterator code simple.
  // Can throw due to `QASSERT`.
  static node_type *predecessor(node_type *node)
  {
    return predecessor_impl(node);
  }
  static node_type *predecessor(const node_type *node)
  {
    return predecessor_impl(const_cast<node_type *>(node));
  }
  static node_type *predecessor_impl(node_type *node)
  {
    if ( is_nil(node) )
    {
      return node;
    }
    if ( !is_nil(left(node)) )
    {
      // Any left child means the predecessor lives at the max of that subtree.
      return maximum(left(node));
    }
    node_type *parent_node = parent(node);
    while ( !is_nil(parent_node) && node == left(parent_node) )
    {
      // Walk up the tree until we step out of a left edge; the first right
      // turn yields the predecessor.
      node = parent_node;
      parent_node = parent(parent_node);
    }
    return parent_node;
  }

  static Color node_color(const node_type *node) noexcept
  {
    return is_nil(node) ? Color::Black : color(node);
  }
  static Color left_color(const node_type *node) noexcept
  {
    return is_nil(node) ? Color::Black : node_color(left(node));
  }
  static Color right_color(const node_type *node) noexcept
  {
    return is_nil(node) ? Color::Black : node_color(right(node));
  }
  static node_type *prev_including_header(node_type *node)
  {
    return is_nil(node) ? right(node) : predecessor(node);
  }
  static const node_type *prev_including_header(const node_type *node)
  {
    return is_nil(node) ? right(node) : predecessor(node);
  }

  // ---------------------------------------------------------------------------
  // Utilities for construction, destruction, copying, and swapping.
  // ---------------------------------------------------------------------------
  static void destroy_value(node_type *node) noexcept
  {
    if ( !is_nil(node) )
    {
      value_addr(node)->~Value();
      set_is_nil(node, true);
    }
  }

  static Value *value_addr(node_type *node) noexcept { return reinterpret_cast<Value *>(node->storage_); }
  static Value const *value_addr(const node_type *node) noexcept { return reinterpret_cast<Value const *>(node->storage_); }

  static Value *value_ptr(node_type *node) noexcept { return q_launder(value_addr(node)); }
  static Value const *value_ptr(const node_type *node) noexcept { return q_launder(value_addr(node)); }

  // Allocate the sentinel header node. The header doubles as the nil
  // sentinel and stores cached links to the root/min/max nodes. We only
  // allocate it on demand (e.g., on the first insertion or when cloning
  // from a non-empty tree) and wire every pointer to itself until the tree
  // contains data.
  node_type *allocate_header()
  {
    node_type *h = node_new();   // Obtain storage for the sentinel node.
    set_parent(h, h);            // Header pretends to be its own parent.
    set_left(h, h);              // ...and its own min/max until populated.
    set_right(h, h);
    set_color(h, Color::Black);  // Sentinels are always black in RB trees.
    set_is_nil(h, true);         // Mark as nil so algorithms treat it as such.
    return h;
  }

  // Reset the header to represent an empty tree after we have already
  // created it. This keeps the sentinel black and self-referential so
  // algorithms can treat `header_` as a nil child without sprinkling
  // special cases. When header_ is null, the tree is also empty, but
  // without a material sentinel node yet.
  void init_header() noexcept
  {
    set_parent(header_, header_);     // Root pointer collapses back to header.
    set_left(header_, header_);       // Min/max cache also points at the sentinel.
    set_right(header_, header_);
    set_color(header_, Color::Black);
    set_is_nil(header_, true);
  }

  void ensure_header()
  {
    if ( header_ == nullptr )
    {
      header_ = allocate_header();
      init_header();
    }
  }

  // Recursively destroy a subtree rooted at `node`. We descend depth-first,
  // release both children, destroy the stored Value, and finally return the
  // node back to the allocator. Nil children short-circuit the recursion.
  void clear_subtree(node_type *node) noexcept
  {
    if ( is_nil(node) )
      return;
    if ( !is_nil(left(node)) )
    {
      // Clear out the entire left branch before destroying this node.
      clear_subtree(left(node));
    }
    if ( !is_nil(right(node)) )
    {
      // Likewise release the right subtree.
      clear_subtree(right(node));
    }
    destroy_value(node);
    node_delete(node);
  }

  // Clone a subtree from `other_node` into this tree, reparenting the new nodes
  // under `parent`. We copy construct each payload, mirror the color and then
  // recursively duplicate the left/right descendants. Any exception during
  // cloning unwinds via clear_subtree(), so we never leak partially built nodes.
  node_type *clone_subtree(node_type const *other_node, node_type *parent_node)
  {
    if ( is_nil(other_node) )
      return header_;

    node_type *new_node = node_new();  // Create storage for the cloned node.
    try
    {
      ::new (value_addr(new_node)) Value(*value_ptr(other_node));
      set_is_nil(new_node, false);
    }
    catch ( ... )
    {
      node_delete(new_node);
      throw;
    }

    set_color(new_node, color(other_node));
    set_parent(new_node, parent_node);
    set_left(new_node, header_);    // Initialize children to sentinels until filled.
    set_right(new_node, header_);

    try
    {
      // Recursively clone left and right subtrees under the new node.
      set_left(new_node, clone_subtree(left(other_node), new_node));
      set_right(new_node, clone_subtree(right(other_node), new_node));
    }
    catch ( ... )
    {
      clear_subtree(new_node);
      throw;
    }

    return new_node;
  }

  // Rebuild this tree from `other`. We clone the other root and then refresh
  // the cached extrema and node count. On failure we roll back to an empty
  // state, leaving the current tree consistent.
  void clone_from(qtree const &other)
  {
    // Make sure nobody changes the code to do this in the future
    QASSERT(3439, !other.empty());

    try
    {
      node_type *new_root = clone_subtree(other.root(), header_); // Deep copy.
      set_parent(header_, new_root);                              // Fix root cache.
      set_left(header_, minimum(new_root));                       // Refresh minimum.
      set_right(header_, maximum(new_root));                      // Refresh maximum.
      node_count_ = other.node_count_;                            // Mirror size.
    }
    catch ( ... )
    {
      clear();
      throw;
    }
  }

  // ---------------------------------------------------------------------------
  // Red-black tree algorithms and utilities.
  // ---------------------------------------------------------------------------

  // Because the comparator is required to be empty and stateless, we can just
  // default-construct it on demand.
  static constexpr key_compare comp() noexcept { return key_compare {}; }

  // Provide mutable access to the root pointer stored off of the header
  // sentinel. When header_ is non-null, the header pretends to be the
  // parent of the actual root, so returning header_->parent keeps tree
  // rotations uniform. When header_ is null the tree is empty and root()
  // returns nullptr.
  node_type *root() noexcept
  {
    if ( header_ == nullptr )
      return nullptr;
    return parent(header_);
  }

  // Const-qualified facade returning the same cached root pointer.
  node_type const *root() const noexcept
  {
    if ( header_ == nullptr )
      return nullptr;
    return parent(header_);
  }

  // Extract the key from a node's stored Value using the key selector policy.
  // This indirection lets qtree power both qmap (pair key/value) and qset
  // (key-only) without duplicating tree logic.
  key_type const &node_key(node_type const *node) const
  {
    return KeySelector {} (*value_ptr(node));
  }

  // -----------------------------------------------------------------------------
  // rotate_left()
  // -----------------------------------------------------------------------------
  // Perform the standard left rotation used by red-black trees.
  //
  // Before rotation (pivoting on 'node'):
  //
  //        parent
  //          |
  //        (node)
  //        .    .
  //      A       (right)
  //             .    .
  //           B        C
  //
  // After rotation:
  //
  //        parent
  //          |
  //       (right)
  //       .     .
  //   (node)     C
  //   .    .
  //  A      B
  //
  // The "right" child moves up to become the subtree root,
  // "node" slides left under it, and the B subtree migrates from
  // right->left to node->right.
  // -----------------------------------------------------------------------------
  void rotate_left(node_type *node) noexcept
  {
    node_type *right_node = right(node);
    QASSERT(3440, !is_nil(right_node));

    // B subtree moves across
    set_right(node, left(right_node));
    if ( !is_nil(left(right_node)) )
      set_parent(left(right_node), node);

    // promote 'right' into node's former parent slot
    set_parent(right_node, parent(node));
    if ( parent(node) == header_ )
      set_parent(header_, right_node);           // update cached root
    else if ( node == left(parent(node)) )
      set_left(parent(node), right_node);
    else
      set_right(parent(node), right_node);

    // complete the rotation
    set_left(right_node, node);
    set_parent(node, right_node);
  }

  // -----------------------------------------------------------------------------
  // rotate_right()
  // -----------------------------------------------------------------------------
  // Mirror of rotate_left(): the left child is promoted and 'node' becomes its
  // right child.
  //
  // Before rotation (pivoting on 'node'):
  //
  //          parent
  //            |
  //          (node)
  //          .    .
  //     (left)     C
  //     .    .
  //    A      B
  //
  // After rotation:
  //
  //          parent
  //            |
  //         (left)
  //         .     .
  //       A       (node)
  //               .    .
  //              B      C
  //
  // The "left" child moves up, "node" slides right under it,
  // and the B subtree migrates from left->right to node->left.
  // -----------------------------------------------------------------------------
  void rotate_right(node_type *node) noexcept
  {
    node_type *left_node = left(node);
    QASSERT(3441, !is_nil(left_node));

    // B subtree moves across
    set_left(node, right(left_node));
    if ( !is_nil(right(left_node)) )
      set_parent(right(left_node), node);

    // promote 'left' into node's former parent slot
    set_parent(left_node, parent(node));
    if ( parent(node) == header_ )
      set_parent(header_, left_node);            // update cached root
    else if ( node == right(parent(node)) )
      set_right(parent(node), left_node);
    else
      set_left(parent(node), left_node);

    // complete the rotation
    set_right(left_node, node);
    set_parent(node, left_node);
  }

  // ---------------------------------------------------------------------------
  // Red-black tree algorithms and utilities: lookup.
  // ---------------------------------------------------------------------------

  template <class K>
  // Search for an exact key, following the BST invariant relative to the
  // stateless comparator. When the key is not present we return the header
  // sentinel so callers can interpret "not found" uniformly.
  node_type *find_node(K const &key) const
  {
    node_type *node = const_cast<node_type *>(root());
    // Handle headerless case: return the sentinel (which is nullptr here)
    if ( node == nullptr )
      return node;
    const auto cmp = comp();
    while ( !is_nil(node) )
    {
      key_type const &node_k = node_key(node); // Extract current key for comparisons.
      if ( cmp(key, node_k) )
      {
        node = left(node);           // Search value is smaller: follow left branch.
      }
      else if ( cmp(node_k, key) )
      {
        node = right(node);          // Search value is larger: follow right branch.
      }
      else
      {
        return node;                 // Neither less-than holds => keys are equal.
      }
    }
    return const_cast<node_type *>(header_); // Header sentinel denotes "not found".
  }

  template <class K>
  // Locate the first node whose key is not less than `key`. We walk down the
  // tree, tracking the last node that satisfied the lower-bound predicate so
  // we can return it even when the search terminates via a nil sentinel.
  node_type *lower_bound_node(K const &key) const
  {
    node_type *node = const_cast<node_type *>(root());
    // Handle headerless case: return the sentinel (which is nullptr here)
    if ( node == nullptr )
      return node;
    node_type *result = const_cast<node_type *>(header_);
    const auto cmp = comp();
    while ( !is_nil(node) )
    {
      if ( !cmp(node_key(node), key) )
      {
        result = node;               // Candidate is >= key; remember it...
        node = left(node);           // ...and look for an even smaller one.
      }
      else
      {
        node = right(node);          // Candidate is < key; discard and go right.
      }
    }
    return result;
  }

  template <class K>
  // Locate the first node whose key compares strictly greater than `key`.
  // The algorithm mirrors lower_bound_node(), changing only the branch that
  // determines when we capture a candidate result.
  node_type *upper_bound_node(K const &key) const
  {
    node_type *node = const_cast<node_type *>(root());
    // Handle headerless case: return the sentinel (which is nullptr here)
    if ( node == nullptr )
      return node;
    node_type *result = const_cast<node_type *>(header_);
    const auto cmp = comp();
    while ( !is_nil(node) )
    {
      if ( cmp(key, node_key(node)) )
      {
        result = node;               // Found a key strictly greater than target.
        node = left(node);           // Check if there's an even smaller qualifying key.
      }
      else
      {
        node = right(node);          // Current key <= target; continue searching right.
      }
    }
    return result;
  }

  // ---------------------------------------------------------------------------
  // Red-black tree algorithms and utilities: insertion.
  // ---------------------------------------------------------------------------

  // Determine comparator equality by confirming neither side is strictly less
  // than the other. This is the STL idiom that works with transparent
  // comparators and avoids requiring operator== on the key type.
  bool keys_equal(key_type const &lhs, key_type const &rhs) const
  {
    const auto cmp = comp();
    return !cmp(lhs, rhs) && !cmp(rhs, lhs);
  }

  // Heterogeneous version: compare key_type vs K when comparator supports it.
  template <class K, class = enable_hetero_eq<K>>
  bool keys_equal(key_type const &lhs, K const &rhs) const
  {
    const auto cmp = comp();
    return !cmp(lhs, rhs) && !cmp(rhs, lhs);
  }

  // Walk the tree looking for where a new key should be inserted. We bubble
  // down while remembering the would-be parent and which side we should attach
  // to. If we encounter an equivalent key we return that node so the caller can
  // signal "already present". Otherwise we fall through with nullptr so the
  // caller inserts under `parent` on the indicated side.
  // Works for both key_type and heterogeneous K.
  template <class K>
  node_type *find_insert_position(K const &key, node_type *&parent_node, bool &go_left)
  {
    node_type *node = root();
    parent_node = header_;
    go_left = true;
    const auto cmp = comp();
    while ( !is_nil(node) )
    {
      parent_node = node;              // Track the node we just visited.
      key_type const &node_k = node_key(node);
      if ( cmp(key, node_k) )
      {
        node = left(node);             // Descend left for smaller target key...
        go_left = true;                // ...and remember we want to attach left.
      }
      else if ( cmp(node_k, key) )
      {
        node = right(node);            // Larger target key => go right instead.
        go_left = false;               // New node would be the right child.
      }
      else
      {
        return node;                   // Equivalent key found; caller treats as duplicate.
      }
    }
    return nullptr;                    // Fell off the tree: caller should insert at parent.
  }

  // Overload used by the hint-aware insertion path. We reuse the core search
  // logic above but surface the found node through an out parameter to keep
  // the call sites uniform.
  template <class K>
  node_type *find_insert_position(
    K const &key,
    node_type *&parent_node,
    bool &go_left,
    node_type *&existing)
  {
    existing = find_insert_position(key, parent_node, go_left);
    return existing;
  }

  // Validate whether an iterator hint gives us immediate placement. The
  // standard allows us to insert in O(1) when the hint is correct, so we check
  // the neighboring nodes relative to the hint and either produce the parent
  // slot, identify an existing key, or fall back to the general insertion
  // search. Any mismatch returns false so the caller can retry the slow path.
  template <class K>
  bool try_hint_insert(
        K const &key,
        const_iterator hint,
        node_type *&parent_node,
        bool &go_left,
        node_type *&existing)
  {
    node_type *hint_node = hint.node_;
    if ( hint_node == nullptr )
      return false;

    parent_node = header_;
    go_left = true;
    existing = nullptr;

    if ( empty() )
    {
      parent_node = header_;             // Empty tree: new node becomes root.
      return true;
    }

    const auto cmp = comp();
    if ( hint_node == header_ )
    {
      node_type *max_node = right(header_);
      if ( is_nil(max_node) )
      {
        parent_node = header_;           // No max yet, so new node becomes root.
        return true;
      }
      key_type const &max_key = node_key(max_node);
      if ( cmp(max_key, key) )
      {
        parent_node = max_node;          // Hint is end(), key is greater than max...
        go_left = false;                 // ...so attach to the right of current max.
        return true;
      }
      if ( keys_equal(max_key, key) )
      {
        existing = max_node;             // Exact match found at the cached max.
        return true;
      }
      return false;
    }

    key_type const &hint_key = node_key(hint_node);
    if ( keys_equal(hint_key, key) )
    {
      existing = hint_node;              // Hint points exactly at the element we need.
      return true;
    }

    if ( cmp(key, hint_key) )
    {
      node_type *prev = predecessor(hint_node);
      if ( prev == header_ || cmp(node_key(prev), key) )
      {
        if ( is_nil(left(hint_node)) )
        {
          parent_node = hint_node;       // Hint is the first element greater than key...
          go_left = true;                // ...and left slot is empty, so insert there.
          return true;
        }
        if ( prev != header_ && is_nil(right(prev)) )
        {
          parent_node = prev;            // Otherwise hook on the right of the predecessor.
          go_left = false;
          return true;
        }
      }
      return false;
    }

    node_type *next = successor(hint_node);
    if ( next == header_ || cmp(key, node_key(next)) )
    {
      if ( is_nil(right(hint_node)) )
      {
        parent_node = hint_node;         // Key sits between hint and successor, attach right.
        go_left = false;
        return true;
      }
      if ( next != header_ && is_nil(left(next)) )
      {
        parent_node = next;              // Or attach as successor's left child.
        go_left = true;
        return true;
      }
    }
    return false;
  }

  template <class Builder>
  // Materialize a brand-new node under `parent` on the requested side and then
  // rebalance the tree. The Builder functor constructs the Value directly in
  // the node storage so we can support piecewise construction just like
  // std::map::emplace().
  qpair<iterator, bool> emplace_at(node_type *parent_node, bool go_left, Builder &&builder)
  {
    node_type *new_node = node_new(); // Allocate a blank node before construction.
    try
    {
      builder(value_addr(new_node));     // Placement-new the Value via the builder.
      set_is_nil(new_node, false);       // Mark as material now that the Value exists.
    }
    catch ( ... )
    {
      node_delete(new_node);             // Construction failed: release the raw node.
      throw;
    }
    set_parent(new_node, parent_node);        // Hook into the tree structure.
    set_left(new_node, header_);         // Nil children until rotations wire real ones.
    set_right(new_node, header_);
    set_color(new_node, Color::Red);     // New nodes start red; fixup may recolor.

    if ( parent_node == header_ )
    {
      set_parent(header_, new_node);     // Tree was empty: new node becomes root...
      set_left(header_, new_node);       // ...and both extrema point at it.
      set_right(header_, new_node);
      set_color(new_node, Color::Black); // Root must be black.
      set_parent(new_node, header_);     // Root's parent is always the header sentinel.
    }
    else
    {
      if ( go_left )
      {
        set_left(parent_node, new_node);
        // If we attached as the left child of the current leftmost, we have a new leftmost.
        if ( parent_node == left(header_) )
          set_left(header_, new_node);
      }
      else
      {
        set_right(parent_node, new_node);
        // Symmetrically for rightmost.
        if ( parent_node == right(header_) )
          set_right(header_, new_node);
      }
      insert_fixup(new_node);             // Restore red-black invariants.
    }

    ++node_count_;                        // Container now owns one more element.
    return { iterator(new_node), true };
  }

  // -----------------------------------------------------------------------------
  // insert_fixup()
  // -----------------------------------------------------------------------------
  // Summary (outer-line target shape after fixup, conceptually):
  //
  //          P (black)
  //         .         .
  //      ...           ...
  //
  // We iteratively repair a "double red" at (node, parent).
  // If uncle is red: recolor and bubble up.
  // If uncle is black: convert inner triangle to outer line (small rotate),
  // then rotate grand to make parent the local root and recolor.
  // -----------------------------------------------------------------------------
  void insert_fixup(node_type *node) noexcept
  {
    while ( !is_nil(parent(node)) && color(parent(node)) == Color::Red )
    {
      node_type *parent_node = parent(node);
      node_type *grand = parent(parent_node);  // parent is red => grand exists

      // -------------------------------------------------------------------------
      // CASE GROUP A: parent is left child of grand
      // -------------------------------------------------------------------------
      if ( parent_node == left(grand) )
      {
        node_type *uncle = right(grand);   // opposite side

        // A1) RED UNCLE: recolor and bubble up
        //
        // Before:
        //        G(black)
        //        .     .
        //     P(red)  U(red)
        //      .
        //    N(red)
        //
        // After recolor (no rotations):
        //        G(red)
        //        .    .
        //     P(black) U(black)
        //      .
        //    N(red)
        if ( node_color(uncle) == Color::Red )
        {
          set_color(parent_node, Color::Black);
          set_color(uncle, Color::Black);
          set_color(grand, Color::Red);
          node = grand;
          continue;
        }

        // A2) BLACK UNCLE: two subcases
        //
        // A2a) INNER TRIANGLE (node is right child): rotate_left at parent
        //
        // Before:
        //        G(black)
        //        .     .
        //     P(red)  U(black)
        //        .
        //        N(red)
        //
        // After rotate_left(parent_node):
        //        G(black)
        //        .     .
        //     N(red)  U(black)
        //     .
        //   P(red)
        if ( node == right(parent_node) )
        {
          node = parent_node;
          rotate_left(node);
          parent_node = parent(node);      // refresh
          grand = parent(parent_node);
        }

        // A2b) OUTER LINE (node is left child, or after A2a):
        // rotate_right at grand, recolor parent black, grand red
        //
        // Before:
        //        G(black)
        //        .     .
        //     P(red)  U(black)
        //     .
        //   N(red)
        //
        // After rotate_right(grand):
        //        P(black)
        //        .     .
        //     N(red)  G(red)
        //                 .
        //                 U(black)
        set_color(parent_node, Color::Black);
        set_color(grand, Color::Red);
        rotate_right(grand);
      }
      // -------------------------------------------------------------------------
      // CASE GROUP B: parent is right child of grand (mirror of A)
      // -------------------------------------------------------------------------
      else
      {
        node_type *uncle = left(grand);    // opposite side

        // B1) RED UNCLE: recolor and bubble up
        //
        // Before:
        //        G(black)
        //        .     .
        //   U(red)    P(red)
        //               .
        //               N(red)
        //
        // After recolor (no rotations):
        //        G(red)
        //        .    .
        //   U(black) P(black)
        //               .
        //               N(red)
        if ( node_color(uncle) == Color::Red )
        {
          set_color(parent_node, Color::Black);
          set_color(uncle, Color::Black);
          set_color(grand, Color::Red);
          node = grand;
          continue;
        }

        // B2) BLACK UNCLE: two subcases
        //
        // B2a) INNER TRIANGLE (node is left child): rotate_right at parent
        //
        // Before:
        //        G(black)
        //        .     .
        //   U(black)  P(red)
        //             .
        //           N(red)
        //
        // After rotate_right(parent_node):
        //        G(black)
        //        .     .
        //   U(black)  N(red)
        //                .
        //                P(red)
        if ( node == left(parent_node) )
        {
          node = parent_node;
          rotate_right(node);
          parent_node = parent(node);        // refresh
          grand = parent(parent_node);
        }

        // B2b) OUTER LINE (node is right child, or after B2a):
        // rotate_left at grand, recolor parent black, grand red
        //
        // Before:
        //        G(black)
        //        .     .
        //   U(black)  P(red)
        //                .
        //                N(red)
        //
        // After rotate_left(grand):
        //        P(black)
        //        .     .
        //    G(red)   N(red)
        //     .
        //  U(black)
        set_color(parent_node, Color::Black);
        set_color(grand, Color::Red);
        rotate_left(grand);
      }
    }

    // Root must be black
    if ( !is_nil(parent(header_)) )
      set_color(parent(header_), Color::Black);
  }

  template <class Builder>
  // Entry point for emplacement without a hint. We either return an existing
  // node when the key already lives in the tree or delegate to emplace_at() to
  // create and balance a new node.
  qpair<iterator, bool> lazy_emplace_impl(key_type const &key, Builder &&builder)
  {
    if ( header_ == nullptr || node_count_ == 0 )
      return emplace_into_empty_tree(std::forward<Builder>(builder));

    node_type *parent_node = header_;
    bool go_left = true;
    node_type *existing = this->find_insert_position(key, parent_node, go_left);
    if ( existing != nullptr )
      return { iterator(existing), false }; // Key already present; no insertion.
    return emplace_at(parent_node, go_left, std::forward<Builder>(builder));
  }

  // Heterogeneous key overload: enabled only when comparator supports it.
  template <class K, class Builder, class = std::enable_if_t<cmp_bidir_v<Compare, key_type, K>>>
  qpair<iterator, bool> lazy_emplace_impl(K const &key, Builder &&builder)
  {
    if ( header_ == nullptr || node_count_ == 0 )
      return emplace_into_empty_tree(std::forward<Builder>(builder));

    node_type *parent_node = header_;
    bool go_left = true;
    node_type *existing = this->find_insert_position(key, parent_node, go_left);
    if ( existing != nullptr )
      return { iterator(existing), false };
    return emplace_at(parent_node, go_left, std::forward<Builder>(builder));
  }

  template <class Builder>
  // Hint-aware emplacement. We first attempt the constant-time placement by
  // validating that the hint is adjacent to the target location; failing that
  // we fall back to the general lazy_emplace_impl() search.
  qpair<iterator, bool> lazy_emplace_with_hint(
    key_type const &key, const_iterator hint, Builder &&builder)
  {
    if ( header_ == nullptr || node_count_ == 0 )
      return emplace_into_empty_tree(std::forward<Builder>(builder));

    node_type *parent_node = header_;
    bool go_left = true;
    node_type *existing = nullptr;
    if ( hint.node_ != nullptr
      && try_hint_insert(key, hint, parent_node, go_left, existing) )
    {
      if ( existing != nullptr )
        return { iterator(existing), false }; // Hint pointed to duplicate key.
      return emplace_at(parent_node, go_left, std::forward<Builder>(builder)); // Insert using O(1) slot.
    }
    return lazy_emplace_impl(key, std::forward<Builder>(builder)); // Fallback to regular search.
  }

  template <class K, class Builder, class = std::enable_if_t<cmp_bidir_v<Compare, key_type, K>>>
  qpair<iterator, bool> lazy_emplace_with_hint(
    K const &key, const_iterator hint, Builder &&builder)
  {
    if ( header_ == nullptr || node_count_ == 0 )
      return emplace_into_empty_tree(std::forward<Builder>(builder));

    node_type *parent_node = header_;
    bool go_left = true;
    node_type *existing = nullptr;
    if ( hint.node_ != nullptr
      && try_hint_insert(key, hint, parent_node, go_left, existing) )
    {
      if ( existing != nullptr )
        return { iterator(existing), false };
      return emplace_at(parent_node, go_left, std::forward<Builder>(builder));
    }
    return lazy_emplace_impl(key, std::forward<Builder>(builder));
  }

  template <class Builder>
  qpair<iterator, bool> emplace_into_empty_tree(Builder &&builder)
  {
    ensure_header();
    node_type *parent_node = header_;
    bool go_left = true;
    return emplace_at(parent_node, go_left, std::forward<Builder>(builder));
  }

  // ---------------------------------------------------------------------------
  // Red-black tree algorithms and utilities: removal.
  // ---------------------------------------------------------------------------

  // -----------------------------------------------------------------------------
  // transplant(u, v)
  // -----------------------------------------------------------------------------
  // Replace subtree rooted at 'u' with subtree rooted at 'v'.
  // Fixes parent pointers; treats 'header_' as pseudo-parent of the root.
  //
  // Cases:
  //   - u was root: header_->parent becomes v (or header_ if v is nil)
  //   - u was left child:  u->parent_node->left = v
  //   - u was right child: u->parent_node-> right = v
  //   - if v is not nil:   v->parent = u->parent
  // -----------------------------------------------------------------------------
  void transplant(node_type *u, node_type *v) noexcept
  {
    if ( parent(u) == header_ )
      set_parent(header_, is_nil(v) ? header_ : v);
    else if ( u == left(parent(u)) )
      set_left(parent(u), v);
    else
      set_right(parent(u), v);

    if ( !is_nil(v) )
      set_parent(v, parent(u));
  }

  // -----------------------------------------------------------------------------
  // erase_node()
  // -----------------------------------------------------------------------------
  // Delete 'node' while preserving BST ordering and RB invariants.
  // We consider the standard 3 structural cases. We remember the color of the
  // physical node that gets removed ('original'). If that color was black,
  // we run erase_fixup() starting at 'x' with its current parent 'x_parent'.
  // -----------------------------------------------------------------------------
  void erase_node(node_type *node)
  {
    // Handle headerless case. This should only arise if somebody did
    // `t.erase(t.begin())` or something, which is an error on an empty tree.
    // But, might as well not segfault, right?
    if ( node == nullptr )
      return;
    node_type *y = node;               // physical node that will be removed
    node_type *x = header_;            // child that replaces y (may be header_)
    node_type *x_parent = header_;     // parent to continue fixup from if x is header_
    Color original = color(y);

    // Case 1: no left child -> splice in right child
    //
    // Before:
    //        node
    //        .  .
    //      nil   R
    //
    // After:
    //        R         (R may be header_)
    //
    if ( is_nil(left(node)) )
    {
      x = right(node);
      x_parent = parent(node);
      transplant(node, right(node));
    }
    // Case 2: no right child -> splice in left child
    //
    // Before:
    //        node
    //        .  .
    //       L   nil
    //
    // After:
    //        L
    //
    else if ( is_nil(right(node)) )
    {
      x = left(node);
      x_parent = parent(node);
      transplant(node, left(node));
    }
    // Case 3: two children -> use in-order successor 'y'
    //
    // Find y = minimum(node->right). y has no left child.
    // We remove y from its spot, and put y where 'node' was.
    //
    // Before (y is leftmost in node->right):
    //        node
    //        .  .
    //       L    R
    //           .
    //          y
    //           .
    //            x      (x is y->right, possibly nil)
    //
    // After splicing y out and moving it up to node's position:
    //        y
    //       . .
    //      L   R
    //
    else
    {
      y = minimum(right(node));
      original = color(y);
      x = right(y);                     // y has at most one right child

      if ( parent(y) == node )
        x_parent = y;                     // x's parent will be y after transplant
      else
      {
        // Splice y out of its current position:
        //
        //    parent(y)
        //       .
        //      y
        //       .
        //        x
        //
        // becomes:
        //
        //    parent(y)
        //       .
        //      x
        //
        transplant(y, right(y));

        // Move node->right under y:
        set_right(y, right(node));
        if ( !is_nil(right(y)) )
          set_parent(right(y), y);

        x_parent = parent(y);           // track parent for fixup when x is nil
      }

      // Replace 'node' by 'y' at node's position
      //
      // Before:
      //   ... -> node
      //
      // After:
      //   ... -> y
      //
      transplant(node, y);

      // Attach node->left under y
      set_left(y, left(node));
      if ( !is_nil(left(y)) )
        set_parent(left(y), y);

      // y takes node's original color
      set_color(y, color(node));
    }

    // Destroy and free the removed node
    destroy_value(node);
    node_delete(node);
    --node_count_;

    // If we physically removed a black node, we may have broken black-height
    if ( original == Color::Black )
      erase_fixup(x, x_parent);

    // Refresh header extrema or reset header if empty
    if ( node_count_ == 0 )
      init_header();
    else
    {
      set_left(header_, minimum(parent(header_)));
      set_right(header_, maximum(parent(header_)));
    }
  }

  // -----------------------------------------------------------------------------
  // erase_fixup(x, parent)
  // -----------------------------------------------------------------------------
  // Repair red-black properties after removing a black node.
  // Loop while x is black and not the root. Consider sibling w and apply the
  // 4 textbook cases (and their mirror).
  // Important: `x` may be `header_`, because we represent nil children by the
  // shared header sentinel. node_color()/left_color()/right_color() treat any
  // nil (header_) as black and never dereference its children, so erase_fixup()
  // doesn't need separate header-specific branches.
  // -----------------------------------------------------------------------------
  void erase_fixup(node_type *x, node_type *parent_node) noexcept
  {
    while ( x != parent(header_) && node_color(x) == Color::Black )
    {
      // ----------------------------- LEFT SIDE ---------------------------------
      // x is the left child; sibling w = parent()->right
      if ( x == left(parent_node) )
      {
        node_type *w = right(parent_node);

        // Case 1 (left): w is red  -> rotate_left(parent_node)
        //
        // Before:
        //       parent(B)
        //       .      .
        //     x(B)     w(R)
        //
        // After rotate_left(parent_node):
        //          w(B)
        //         .    .
        //   parent(R)  ...
        //    .
        //  x(B)
        if ( node_color(w) == Color::Red )
        {
          set_color(w, Color::Black);
          set_color(parent_node, Color::Red);
          rotate_left(parent_node);
          w = right(parent_node);              // new sibling
        }

        Color w_left  = left_color(w);         // black if nil
        Color w_right = right_color(w);        // black if nil

        // Case 2 (left): w's children are both black -> paint w red, move up
        //
        //       parent(?)
        //       .      .
        //     x(B)     w(B)
        //             .   .
        //           B       B
        if ( w_left == Color::Black && w_right == Color::Black )
        {
          if ( !is_nil(w) )
            set_color(w, Color::Red);

          x = parent_node;
          parent_node = parent(parent_node);
        }
        else
        {
          // Case 3 (left): w_right is black, w_left is red
          // Convert to case 4 shape by rotate_right(w)
          //
          // Before:
          //       parent
          //       .     .
          //     x       w(B)
          //            .
          //          R
          //
          // After rotate_right(w):
          //       parent
          //       .     .
          //     x       R
          //              .
          //               w(B)
          if ( w_right == Color::Black )
          {
            if ( !is_nil(w) )
            {
              if ( !is_nil(left(w)) )
                set_color(left(w), Color::Black);

              set_color(w, Color::Red);
              rotate_right(w);
            }
            w = right(parent_node);
          }

          // Case 4 (left): w_right is red -> rotate_left(parent_node), recolor
          //
          // Before:
          //       parent(Pcol)
          //       .      .
          //     x        w(R or B)
          //               .
          //                R
          //
          // After rotate_left(parent_node):
          //          w(Pcol)
          //         .      .
          //   parent(B)     ...
          //     .
          //   x(B)
          if ( !is_nil(w) )
            set_color(w, color(parent_node));

          set_color(parent_node, Color::Black);
          if ( !is_nil(right(w)) )
            set_color(right(w), Color::Black);

          rotate_left(parent_node);

          // Done: force exit
          x = parent(header_);
          parent_node = header_;
        }
      }
      // ---------------------------- RIGHT SIDE ---------------------------------
      // x is the right child; sibling w = parent()->left  (mirror of left side)
      else
      {
        node_type *w = left(parent_node);

        // Case 1 (right): w is red -> rotate_right(parent_node)
        //
        // Before:
        //       parent(B)
        //       .      .
        //     w(R)     x(B)
        //
        // After rotate_right(parent_node):
        //          w(B)
        //         .    .
        //       ...   parent(R)
        //                .
        //                x(B)
        if ( node_color(w) == Color::Red )
        {
          set_color(w, Color::Black);
          set_color(parent_node, Color::Red);
          rotate_right(parent_node);
          w = left(parent_node);                  // new sibling
        }

        Color w_left  = left_color(w);         // black if nil
        Color w_right = right_color(w);        // black if nil

        // Case 2 (right): w's children both black -> paint w red, move up
        //
        //       parent(?)
        //       .      .
        //     w(B)     x(B)
        //     .  .
        //    B    B
        if ( w_left == Color::Black && w_right == Color::Black )
        {
          if ( !is_nil(w) )
            set_color(w, Color::Red);

          x = parent_node;
          parent_node = parent(parent_node);
        }
        else
        {
          // Case 3 (right): w_left is black, w_right is red
          // Convert to case 4 shape by rotate_left(w)
          //
          // Before:
          //        parent
          //        .     .
          //      w(B)     x
          //        .
          //         R
          //
          // After rotate_left(w):
          //        parent
          //        .     .
          //       R       x
          //      .
          //    w(B)
          if ( w_left == Color::Black )
          {
            if ( !is_nil(w) )
            {
              if ( !is_nil(right(w)) )
                set_color(right(w), Color::Black);

              set_color(w, Color::Red);
              rotate_left(w);
            }
            w = left(parent_node);
          }

          // Case 4 (right): w_left is red -> rotate_right(parent_node), recolor
          //
          // Before:
          //       parent(Pcol)
          //       .       .
          //     w(R or B)  x
          //     .
          //    R
          //
          // After rotate_right(parent_node):
          //          w(Pcol)
          //         .      .
          //       ...    parent(B)
          //                  .
          //                  x(B)
          if ( !is_nil(w) )
            set_color(w, color(parent_node));

          set_color(parent_node, Color::Black);
          if ( !is_nil(left(w)) )
            set_color(left(w), Color::Black);

          rotate_right(parent_node);

          // Done: force exit
          x = parent(header_);
          parent_node = header_;
        }
      }
    }

    // Ensure x and root are black on exit
    if ( !is_nil(x) )
      set_color(x, Color::Black);

    if ( !is_nil(parent(header_)) )
      set_color(parent(header_), Color::Black);
  }

  // ---------------------------------------------------------------------------
  // Allocation and deallocation of nodes.
  // ---------------------------------------------------------------------------

  // Acquire storage for a fresh node via the allocator policy and construct the
  // bookkeeping fields in place. The Value payload is filled later by callers.
  node_type *node_new()
  {
    node_alloc a = make_node_alloc();
    // The allocator (not `AllocPolicy::allocate`) throws on allocation failure.
    node_type *mem = node_traits::allocate(a, 1);
    try
    {
      return ::new (mem) node_type();     // Value-initialize bookkeeping fields.
    }
    catch ( ... )
    {
      node_traits::deallocate(a, mem, 1);
      throw;
    }
  }

  // Complement to node_new(): destroy the node object (which calls the Value
  // destructor when present) and return its memory to the allocator policy.
  void node_delete(node_type *p) noexcept
  {
    if ( p == nullptr )
      return;
    p->~node_type();                       // Run destructor to release Value, if any.
    node_alloc a = make_node_alloc();
    node_traits::deallocate(a, p, 1);      // Return memory to allocator.
  }

  // Invariants for header_ / "nil":
  //
  //  - When header_ == nullptr, the tree is empty and no sentinel node has
  //    been allocated yet. All operations must treat this as an empty tree
  //    and must not dereference header_.
  //
  //  - When header_ != nullptr, it is the unique sentinel node with
  //    _is_nil() == 1. (Transiently, nodes being destroyed may also be
  //    marked nil before deallocation.)
  //
  //  - Every "nil" child pointer in the tree is represented by `header_`
  //    (we do not allocate per-node nils). In the header-less empty state,
  //    we never store or follow any child pointers.
  //
  //  - When the tree is empty and header_ != nullptr:
  //      parent(header_) == header_
  //      left(header_)   == header_
  //      right(header_)  == header_
  //
  //  - When the tree is non-empty:
  //      parent(header_) == root
  //      left(header_)   == minimum(root)
  //      right(header_)  == maximum(root)
  //
  //    Even in the non-empty case, algorithms treat `header_` as the
  //    unique nil sentinel: is_nil(header_) is true and helpers like
  //    node_color(), left_color(), right_color() special-case nil nodes
  //    as black. This lets us reuse header_ as both the nil leaf and the
  //    (root, min, max) cache without extra nodes.
  node_type *header_ = nullptr;
  size_type node_count_ = 0;
};

// Declaration of qset, a set based on qtree.
template <class Key, class Compare, class AllocPolicy, bool PackNode = true>
using qset = qtree<Key, Compare, AllocPolicy, PackNode, qtree_detail::identity_key<Key>>;

// qmap uses composition rather than inheritance, for ABI reasons. This
// requires us to reimplement the whole public API of qtree that we wish to
// expose as small wrappers that forward to the internal qtree instance.
template <class Key, class T, class Compare, class AllocPolicy, bool PackNode = true>
class qmap
{
  using Tree = qtree < qpair<const Key, T>, Compare, AllocPolicy, PackNode,
    select_first<qpair<const Key, T>>>;

  friend class qtree_tester;

public:
  // ------------------------ public types ------------------------
  using key_type = Key;
  using mapped_type = T;
  using value_type = qpair<const Key, T>;
  using size_type = typename Tree::size_type;
  using difference_type = typename Tree::difference_type;
  using key_compare = Compare;
  using value_compare = typename Tree::value_compare;
  using allocator_policy_type = AllocPolicy;

  using reference = value_type &;
  using const_reference = value_type const &;
  using pointer = value_type *;
  using const_pointer = value_type const *;

  using iterator = typename Tree::iterator;
  using const_iterator = typename Tree::const_iterator;
  using reverse_iterator = qiterator_detail::qreverse_iterator<iterator>;
  using const_reverse_iterator = qiterator_detail::qreverse_iterator<const_iterator>;
  using allocator_type = typename Tree::allocator_type;

  // This thing defines operator new/delete for the qmap type, such that if
  // you were to allocate a qmap via operator new, or delete a qmap via
  // operator delete, the allocation would go through the AllocPolicy.
  CXX17_MEMORY_ALLOCATION_FUNCS_USING_POLICY(AllocPolicy)

  // ------------------------ constructors / assignment ------------------------
  qmap() noexcept : tree_() {}

  qmap(std::initializer_list<value_type> init) : tree_()
  {
    tree_.insert(init.begin(), init.end());
  }

  qmap(qmap const &other) : tree_(other.tree_) {}

  qmap(qmap &&other) noexcept
    : tree_(std::move(other.tree_))
  {
  }

  ~qmap() = default;

  qmap &operator=(qmap const &other)
  {
    tree_ = other.tree_;
    return *this;
  }

  qmap &operator=(qmap &&other) noexcept
  {
    tree_ = std::move(other.tree_);
    return *this;
  }

  void swap(qmap &other) noexcept(noexcept(tree_.swap(other.tree_)))
  {
    tree_.swap(other.tree_);
  }
  friend void swap(qmap &a, qmap &b) noexcept(noexcept(a.swap(b))) { a.swap(b); }

  // Here we duplicate the public API of qtree, in order to avoid ABI issues
  // that could arise from inheritance.

  // ------------------------ iterators ------------------------
  iterator begin() noexcept { return tree_.begin(); }
  const_iterator begin() const noexcept { return tree_.begin(); }
  const_iterator cbegin() const noexcept { return tree_.cbegin(); }

  iterator end() noexcept { return tree_.end(); }
  const_iterator end() const noexcept { return tree_.end(); }
  const_iterator cend() const noexcept { return tree_.cend(); }

  reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
  const_reverse_iterator rbegin() const noexcept { return const_reverse_iterator(end()); }
  const_reverse_iterator crbegin() const noexcept { return rbegin(); }

  reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
  const_reverse_iterator rend() const noexcept { return const_reverse_iterator(begin()); }
  const_reverse_iterator crend() const noexcept { return rend(); }

  // ------------------------ capacity ------------------------
  bool empty() const noexcept { return tree_.empty(); }
  size_type size() const noexcept { return tree_.size(); }

  // --------- heterogenous comparator helpers  ---------------
  template <class K>
  using enable_hetero_eq = typename Tree::template enable_hetero_eq<K>;

  template <class K>
  using enable_hetero_lb = typename Tree::template enable_hetero_lb<K>;

  template <class K>
  using enable_hetero_ub = typename Tree::template enable_hetero_ub<K>;

  template <class K>
  using enable_hetero_eqrange = typename Tree::template enable_hetero_eqrange<K>;

  // ------------------------ lookup (exact key type) ------------------------
  // find
  [[nodiscard]] iterator find(key_type const &key) { return tree_.find(key); }
  [[nodiscard]] const_iterator find(key_type const &key) const { return tree_.find(key); }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] iterator find(K const &k) { return tree_.find(k); }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] const_iterator find(K const &k) const { return tree_.find(k); }

  // contains
  [[nodiscard]] bool contains(key_type const &key) const { return tree_.contains(key); }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] bool contains(K const &k) const { return tree_.contains(k); }

  // count
  [[nodiscard]] size_type count(key_type const &key) const { return tree_.count(key); }

  template <class K, class = enable_hetero_eq<K>>
  [[nodiscard]] size_type count(K const &k) const { return tree_.count(k); }

  // lower_bound
  [[nodiscard]] iterator lower_bound(key_type const &key) { return tree_.lower_bound(key); }
  [[nodiscard]] const_iterator lower_bound(key_type const &key) const { return tree_.lower_bound(key); }

  template <class K, class = enable_hetero_lb<K>>
  [[nodiscard]] iterator lower_bound(K const &k) { return tree_.lower_bound(k); }

  template <class K, class = enable_hetero_lb<K>>
  [[nodiscard]] const_iterator lower_bound(K const &k) const { return tree_.lower_bound(k); }

  // upper_bound
  [[nodiscard]] iterator upper_bound(key_type const &key) { return tree_.upper_bound(key); }
  [[nodiscard]] const_iterator upper_bound(key_type const &key) const { return tree_.upper_bound(key); }

  template <class K, class = enable_hetero_ub<K>>
  [[nodiscard]] iterator upper_bound(K const &k) { return tree_.upper_bound(k); }

  template <class K, class = enable_hetero_ub<K>>
  [[nodiscard]] const_iterator upper_bound(K const &k) const { return tree_.upper_bound(k); }

  // equal_range
  [[nodiscard]] qpair<iterator, iterator> equal_range(key_type const &key)
  {
    return tree_.equal_range(key);
  }
  [[nodiscard]] qpair<const_iterator, const_iterator> equal_range(key_type const &key) const
  {
    return tree_.equal_range(key);
  }

  template <class K, class = enable_hetero_eqrange<K>>
  [[nodiscard]] qpair<iterator, iterator> equal_range(K const &k) { return tree_.equal_range(k); }

  template <class K, class = enable_hetero_eqrange<K>>
  [[nodiscard]] qpair<const_iterator, const_iterator> equal_range(K const &k) const { return tree_.equal_range(k); }

  // ------------------------ modifiers ------------------------
  void clear() noexcept { tree_.clear(); }

  // insert
  template <class InputIt>
  void insert(InputIt first, InputIt last) { tree_.insert(first, last); }

  void insert(std::initializer_list<value_type> init)
  {
    tree_.insert(init.begin(), init.end());
  }

  qpair<iterator, bool> insert(value_type const &v) { return tree_.insert(v); }
  qpair<iterator, bool> insert(value_type &&v) { return tree_.insert(std::move(v)); }

  iterator insert(const_iterator hint, value_type const &v)
  {
    return tree_.insert(hint, v);
  }
  iterator insert(const_iterator hint, value_type &&v)
  {
    return tree_.insert(hint, std::move(v));
  }

  // erase
  iterator erase(const_iterator pos) { return tree_.erase(pos); }
  iterator erase(iterator pos)
  {
    return tree_.erase(const_iterator(pos));
  }
  iterator erase(const_iterator first, const_iterator last)
  {
    return tree_.erase(first, last);
  }

  size_type erase(key_type const &key) { return tree_.erase(key); }

  template <class K, class = enable_hetero_eq<K>>
  size_type erase(K const &k) { return tree_.erase(k); }

  template <class Pred>
  size_type erase_if(Pred pred) { return tree_.erase_if(pred); }

  // ------------------------ observers ------------------------
  key_compare key_comp() const noexcept { return tree_.key_comp(); }
  value_compare value_comp() const noexcept { return tree_.value_comp(); }
  allocator_type get_allocator() const noexcept { return tree_.get_allocator(); }
  size_type max_size() const noexcept { return tree_.max_size(); }

  // ------------------------ element access ------------------------
  mapped_type &at(key_type const &key)
  {
    auto it = find(key);
    if ( it == end() )
      throw std::out_of_range("qmap::at");
    return it->second;
  }
  mapped_type const &at(key_type const &key) const
  {
    auto it = find(key);
    if ( it == end() )
      throw std::out_of_range("qmap::at");
    return it->second;
  }

  mapped_type &operator[](key_type const &key)
  {
    // Insert default-constructed mapped_type if missing.
    return try_emplace(key).first->second;
  }

  mapped_type &operator[](key_type &&key)
  {
    // Same as above, but move the key when we actually insert.
    return try_emplace(std::move(key)).first->second;
  }

  // ------------------------ emplacement ------------------------
  // Perfectly forwards to the underlying tree; duplicates are checked
  // via the KeySelector inside qtree, so mapped_type is only constructed on insert.
  template <class... Args>
  qpair<iterator, bool> emplace(Args &&...args)
  {
    return tree_.emplace(std::forward<Args>(args)...);
  }

  template <class... Args>
  iterator emplace_hint(const_iterator hint, Args &&...args)
  {
    return tree_.emplace_hint(hint, std::forward<Args>(args)...);
  }

  // ------------------------ map-specific insertion ------------------------
  template <class... Args>
  // Exact-type lvalue key: probe with const&, construct mapped only on insert.
  // Overload #1: exact key_type lvalue
  qpair<iterator, bool> try_emplace(key_type const &key, Args &&...args)
  {
    // long line because checkstyle
    return tree_.lazy_emplace_impl(key, [&](value_type *slot) { mapped_type m(std::forward<Args>(args)...); ::new ((void *)slot) value_type(key, std::move(m)); } );
  }

  template <class... Args>
  // Exact-type rvalue key: probe by const& to same object, then move key once.
  // Overload #2: exact key_type rvalue (move key once)
  qpair<iterator, bool> try_emplace(key_type &&key, Args &&...args)
  {
    // long line because checkstyle
    key_type const &key_ref = key; // probe without moving
    return tree_.lazy_emplace_impl(key_ref, [&](value_type *slot) { mapped_type m(std::forward<Args>(args)...); ::new ((void *)slot) value_type(std::move(key), std::move(m)); } );
  }

  template <class K, class... Args, std::enable_if_t<cmp_bidir_v<key_compare, key_type, std::decay_t<K>>, int> = 0>
  // Heterogeneous key: comparator supports K vs key_type (transparent compare).
  // Overload #3: hetero K when comparator supports it (no key materialization on miss)
  qpair<iterator, bool> try_emplace(K &&k, Args &&...args)
  {
    using Kdec = std::decay_t<K>;
    Kdec const &key_ref = k; // used both for lookup and lazy construction

    // This uses qtree's heterogeneous lazy_emplace_impl(K const&, ...)
    // Long line because checkstyle
    return tree_.lazy_emplace_impl(key_ref, [&](value_type *slot) { mapped_type m(std::forward<Args>(args)...); ::new ((void *)slot) value_type(key_type(key_ref), std::move(m)); } );
  }

  template <class K, class... Args, std::enable_if_t<std::is_constructible_v<key_type, K const &> && !cmp_bidir_v<key_compare, key_type, std::decay_t<K>>, int> = 0>
  // Convertible key (materialize once) when comparator does *not* support hetero K.
  // Overload #4: fallback for K constructible into key_type when comparator is not transparent
  qpair<iterator, bool> try_emplace(K const &k, Args &&...args)
  {
    key_type kk(k);
    return try_emplace(std::move(kk), std::forward<Args>(args)...);
  }

  template <class M>
  qpair<iterator, bool> insert_or_assign(key_type const &key, M &&mapped)
  {
    auto r = tree_.lazy_emplace_impl(key, [&](value_type *slot)
    {
      mapped_type m(std::forward<M>(mapped));
      ::new ((void *)slot) value_type(key, std::move(m));
    } );
    if ( !r.second )
      r.first->second = std::forward<M>(mapped);
    return r;
  }

  template <class M>
  qpair<iterator, bool> insert_or_assign(key_type &&key, M &&mapped)
  {
    key_type const &key_ref = key; // probe without moving the key yet
    auto r = tree_.lazy_emplace_impl(key_ref, [&](value_type *slot)
    {
      mapped_type m(std::forward<M>(mapped));
      ::new ((void *)slot) value_type(std::move(key), std::move(m));
    } );
    if ( !r.second )
      r.first->second = std::forward<M>(mapped);
    return r;
  }

  // Heterogeneous key insert_or_assign: comparator supports K vs key_type.
  template <class K, class M, std::enable_if_t<cmp_bidir_v<key_compare, key_type, std::decay_t<K>>, int> = 0>
  qpair<iterator, bool> insert_or_assign(K &&k, M &&mapped)
  {
    using Kdec = std::decay_t<K>;
    Kdec const &key_ref = k;
    auto r = tree_.lazy_emplace_impl(key_ref, [&](value_type *slot)
    {
      mapped_type m(std::forward<M>(mapped));
      ::new ((void *)slot) value_type(key_type(key_ref), std::move(m));
    } );
    if ( !r.second )
      r.first->second = std::forward<M>(mapped);
    return r;
  }

  template <class K, class M, std::enable_if_t<std::is_constructible_v<key_type, K const &> && !cmp_bidir_v<key_compare, key_type, std::decay_t<K>>, int> = 0>
  qpair<iterator, bool> insert_or_assign(K const &k, M &&mapped)
  {
    key_type kk(k);  // materialize once
    auto r = tree_.lazy_emplace_impl(kk, [&](value_type *slot)
    {
      mapped_type m(std::forward<M>(mapped));
      ::new ((void *)slot) value_type(std::move(kk), std::move(m));
    } );
    if ( !r.second )
      r.first->second = std::forward<M>(mapped);
    return r;
  }

  // ------------------------ equality ------------------------
  friend bool operator==(qmap const &a, qmap const &b) { return a.tree_ == b.tree_; }
  friend bool operator!=(qmap const &a, qmap const &b) { return !(a == b); }
  friend bool operator< (qmap const &a, qmap const &b) { return a.tree_ < b.tree_; }
  friend bool operator> (qmap const &a, qmap const &b) { return b.tree_ < a.tree_; }
  friend bool operator<=(qmap const &a, qmap const &b) { return !(b < a); }
  friend bool operator>=(qmap const &a, qmap const &b) { return !(a < b); }

private:
  Tree tree_;
  // Really hammer those layout guarantees for qtree inside qmap.
  static_assert(std::is_standard_layout_v<Tree>, "qtree must be standard layout");
  static_assert(alignof(Tree) == alignof(void *), "qtree alignment must match pointer");
  static_assert(offsetof(Tree, header_) == 0, "qtree header_ must be first");
  static_assert(offsetof(Tree, node_count_) == sizeof(void *), "qtree node_count_ follows header_");
  static_assert(sizeof(Tree) == 2 * sizeof(void *), "qtree must be 2x sizeof(void*)");
};

} // namespace qtree_detail
