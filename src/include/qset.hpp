#pragma once

#include "qtree.hpp"
#include "qida_alloc_shim.hpp"

#include <functional> // for std::less

template<typename Value, typename Compare = std::less<>>
using qset = qtree_detail::qset<Value, Compare, ida_alloc_policy, true>;

template <class T, class C>
int compare(const qset<T, C> &a, const qset<T, C> &b)
{
  return compare_containers(a, b);
}

template <class T, class C>
struct ida_movable_type<qset<T, C> >
{
  static constexpr bool value = true;
};
