#pragma once
#include <type_traits>
#include <utility>   // for std::swap (and optional interop)
#include <cstddef>
#include <tuple>

template <class First, class Second>
struct qpair
{
  using first_type = First;
  using second_type = Second;

  First  first;
  Second second;

  // ctors
  constexpr qpair() = default;
  constexpr qpair(First const &a, Second const &b) : first(a), second(b) {}
  constexpr qpair(First const &a, Second &&b) : first(a), second(std::move(b)) {}
  constexpr qpair(First &&a, Second const &b) : first(std::move(a)), second(b) {}
  constexpr qpair(First &&a, Second &&b) : first(std::move(a)), second(std::move(b)) {}

  // converting ctor
  template <class F2, class S2,
    class = std::enable_if_t<std::is_constructible<First, F2 &&>::value && std::is_constructible<Second, S2 &&>::value>>
    constexpr qpair(F2 &&a, S2 &&b) : first(std::forward<F2>(a)), second(std::forward<S2>(b)) {}

  // copy/move
  qpair(qpair const &) = default;
  qpair(qpair &&) = default;
  qpair &operator=(qpair const &) = default;
  qpair &operator=(qpair &&) = default;

  // from std::pair (lvalue)
  template<class F2, class S2,
    class = std::enable_if_t<std::is_constructible<First, F2 const &>::value && std::is_constructible<Second, S2 const &>::value>>
    constexpr qpair(std::pair<F2, S2> const &p)
    : first(p.first), second(p.second)
  {
  }

  // from std::pair (rvalue) - moves
  template<class F2, class S2,
    class = std::enable_if_t<std::is_constructible<First, F2 &&>::value && std::is_constructible<Second, S2 &&>::value>>
    constexpr qpair(std::pair<F2, S2> &&p)
    : first(std::move(p.first)), second(std::move(p.second))
  {
  }

  // qpair <- qpair (lvalue): enabled only if the types differ
  template<class F2, class S2, std::enable_if_t<std::is_constructible<First, F2 const &>::value && std::is_constructible<Second, S2 const &>::value && !(std::is_same<First, F2>::value && std::is_same<Second, S2>::value), int> = 0 >
  constexpr qpair(qpair<F2, S2> const &p)
    : first(p.first), second(p.second)
  {
  }

  // qpair <- qpair (rvalue): enabled only if the types differ
  template<class F2, class S2, std::enable_if_t<std::is_constructible<First, F2 &&>::value && std::is_constructible<Second, S2 &&>::value && !(std::is_same<First, F2>::value && std::is_same<Second, S2>::value), int> = 0 >
  constexpr qpair(qpair<F2, S2> &&p)
    : first(std::forward<F2>(p.first)), second(std::forward<S2>(p.second))
  {
  }

  void swap(qpair &other) noexcept(noexcept(std::swap(first, other.first)) &&
    noexcept(std::swap(second, other.second)))
  {
    using std::swap;
    swap(first, other.first);
    swap(second, other.second);
  }

  // Optional: ease interop without exposing std::pair in signatures
  template<class F2 = First, class S2 = Second>
  explicit operator std::pair<std::decay_t<F2>, std::decay_t<S2>>() const { return { first, second }; }
};

template<class F, class S>
inline void swap(qpair<F, S> &a, qpair<F, S> &b) noexcept(noexcept(a.swap(b)))
{
  a.swap(b);
}

// Helper: like std::make_pair - decays T1/T2 (refs, arrays, functions)
template<class T1, class T2>
constexpr qpair<std::decay_t<T1>, std::decay_t<T2>>
make_qpair(T1 &&a, T2 &&b)
{
  return qpair<std::decay_t<T1>, std::decay_t<T2>>(
    std::forward<T1>(a), std::forward<T2>(b));
}

// C++17 CTAD guide so `qpair{a,b}` deduces to qpair<decay_t<T1>, decay_t<T2>>
template<class T1, class T2>
qpair(T1, T2)->qpair<std::decay_t<T1>, std::decay_t<T2>>;

// relational (lexicographic) - needed for map/set value_compare edge-cases
template<class F, class S>
constexpr bool operator==(qpair<F, S> const &a, qpair<F, S> const &b)
{
  return a.first == b.first && a.second == b.second;
}
template<class F, class S>
constexpr bool operator!=(qpair<F, S> const &a, qpair<F, S> const &b)
{
  return !(a == b);
}
template<class F, class S>
constexpr bool operator<(qpair<F, S> const &a, qpair<F, S> const &b)
{
  return (a.first < b.first) || (!(b.first < a.first) && a.second < b.second);
}
template<class F, class S>
constexpr bool operator>(qpair<F, S> const &a, qpair<F, S> const &b)
{
  return b < a;
}
template<class F, class S>
constexpr bool operator<=(qpair<F, S> const &a, qpair<F, S> const &b)
{
  return !(b < a);
}
template<class F, class S>
constexpr bool operator>=(qpair<F, S> const &a, qpair<F, S> const &b)
{
  return !(a < b);
}

template <class T, class U>
int compare(const qpair<T, U> &a, const qpair<T, U> &b)
{
  int code = compare(a.first, b.first);
  if ( code != 0 )
    return code;
  return compare(a.second, b.second);
}

// get<N> support for structured bindings
template<std::size_t I, class F, class S> constexpr auto &get(qpair<F, S> &p) noexcept
{
  static_assert(I < 2, "");
  if constexpr ( I == 0 )
    return p.first;
  else
    return p.second;
}
template<std::size_t I, class F, class S> constexpr auto const &get(qpair<F, S> const &p) noexcept
{
  static_assert(I < 2, "");
  if constexpr ( I == 0 )
    return p.first;
  else
    return p.second;
}
template<std::size_t I, class F, class S> constexpr auto &&get(qpair<F, S> &&p) noexcept
{
  static_assert(I < 2, "");
  if constexpr ( I == 0 )
    return std::move(p.first);
  else
    return std::move(p.second);
}

// tuple protocol specializations (allowed for user types)
namespace std
{
  template<class F, class S> struct tuple_size<qpair<F, S>> : std::integral_constant<std::size_t, 2> {};
  template<class F, class S> struct tuple_element<0, qpair<F, S>> { using type = F; };
  template<class F, class S> struct tuple_element<1, qpair<F, S>> { using type = S; };
}
