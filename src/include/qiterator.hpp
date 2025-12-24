#pragma once

#include <iterator>
#include <memory>

namespace qiterator_detail
{

  // A minimal reverse-iterator adapter we own (no STL surface).
  template <class It>
  class qreverse_iterator
  {
  public:
    using iterator_type = It;
    using difference_type = typename std::iterator_traits<It>::difference_type;
    using value_type = typename std::iterator_traits<It>::value_type;
    using pointer = typename std::iterator_traits<It>::pointer;
    using reference = typename std::iterator_traits<It>::reference;
    using iterator_category = typename std::iterator_traits<It>::iterator_category;

    constexpr qreverse_iterator() noexcept = default;
    constexpr explicit qreverse_iterator(It it) noexcept : current_(it) {}

    template <class U,
      class = std::enable_if_t<std::is_convertible<U, It>::value>>
      constexpr qreverse_iterator(qreverse_iterator<U> const &other) noexcept
      : current_(other.base())
    {
    }

    constexpr It base() const noexcept { return current_; }

    constexpr reference operator*() const noexcept
    {
      It tmp = current_;
      --tmp;
      return *tmp;
    }

    constexpr pointer operator->() const noexcept
    {
      return std::addressof(operator*());
    }

    constexpr qreverse_iterator &operator++() noexcept
    {
      --current_;
      return *this;
    }

    constexpr qreverse_iterator operator++(int) noexcept
    {
      qreverse_iterator tmp(*this);
      --current_;
      return tmp;
    }

    constexpr qreverse_iterator &operator--() noexcept
    {
      ++current_;
      return *this;
    }

    constexpr qreverse_iterator operator--(int) noexcept
    {
      qreverse_iterator tmp(*this);
      ++current_;
      return tmp;
    }

    friend constexpr bool operator==(qreverse_iterator a, qreverse_iterator b) noexcept
    {
      return a.current_ == b.current_;
    }

    friend constexpr bool operator!=(qreverse_iterator a, qreverse_iterator b) noexcept
    {
      return !(a == b);
    }

  private:
    It current_ {};
  };

} // namespace qiterator_detail
