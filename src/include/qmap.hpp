#pragma once

#include "qtree.hpp"
#include "qida_alloc_shim.hpp"

#include <functional> // for std::less

template<typename Key, typename Value, typename Compare = std::less<Key>>
using qmap = qtree_detail::qmap<Key, Value, Compare, ida_alloc_policy, true>;

template <class T, class U, class C>
int compare(const qmap<T, U, C> &a, const qmap<T, U, C> &b)
{
  return compare_containers(a, b);
}

template <class T, class U, class C>
struct ida_movable_type<qmap<T, U, C> >
{
  static constexpr bool value = true;
};
