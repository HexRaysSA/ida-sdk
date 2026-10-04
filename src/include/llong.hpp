/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2026 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LLONG_HPP
#define _LLONG_HPP

//---------------------------------------------------------------------------
#if defined(IDA_NO_INT_TYPEDEFS)
// int64 and uint64 are supplied by the includer, see pro.h
#elif defined(_MSC_VER)
typedef unsigned __int64 uint64;
typedef          __int64 int64;
#elif defined(__GNUC__)
typedef unsigned long long uint64;
typedef          long long int64;
#endif

//---------------------------------------------------------------------------
#ifdef __cplusplus
inline constexpr int64 make_int64(uint32 ll, int32 hh) { return ll | (int64(hh) << 32); }
inline constexpr uint64 make_uint64(uint32 ll, int32 hh) { return ll | (uint64(hh) << 32); }
inline constexpr uint32 low(const uint64 &x)  { return uint32(x); }
inline constexpr uint32 high(const uint64 &x) { return uint32(x>>32); }
inline constexpr uint32 low(const int64 &x)   { return uint32(x); }
inline constexpr int32  high(const int64 &x)  { return uint32(x>>32); }
#else
#define make_int64(ll,hh)   (ll | (int64(hh) << 32))
#define make_uint64(ll,hh)  (ll | (uint64(hh) << 32))
#endif

#ifndef swap64
   idaman THREAD_SAFE uint64 ida_export swap64(uint64);
#  ifdef __cplusplus
    inline int64 swap64(int64 x)
    {
      return int64(swap64(uint64(x)));
    }
#  endif
#endif

//---------------------------------------------------------------------------
//      128 BIT NUMBERS
//---------------------------------------------------------------------------
#ifndef __HAS_INT128__
#ifdef __SIZEOF_INT128__
#  define __HAS_INT128__ 1
#else
#  define __HAS_INT128__ 0
#endif // __SIZEOF_INT128__
#endif // __HAS_INT128__

#if __HAS_INT128__
typedef unsigned __int128 uint128;
typedef          __int128 int128;

inline int128 make_int128(uint64 ll, int64 hh) { return ll | (int128(hh) << 64); }
inline uint128 make_uint128(uint64 ll, uint64 hh) { return ll | (uint128(hh) << 64); }
inline uint64 low(const uint128 &x)  { return uint64(x); }
inline uint64 high(const uint128 &x) { return uint64(x>>64); }
inline uint64 low(const int128 &x)   { return uint64(x); }
inline int64  high(const int128 &x)  { return uint64(x>>64); }

#else
#ifdef __cplusplus
class int128;

// operator/ and operator% (and the /= and %= built on them) are declared below
// but defined only for uint128, in pro/int128.cpp - they need the _udiv128
// path. Everything else is inline here. Code that divides 128-bit values must
// link libint128; code that only adds, multiplies and shifts need not.
class uint128
{
  uint64 l;
  uint64 h;
  friend class int128;
public:
  uint128(void)  {}
  uint128(uint x) { l = x; h = 0; }
  uint128(int x)  { l = x; h = (x < 0)? -1 : 0; }
  uint128(uint64 x) { l = x; h = 0; }
  uint128(int64 x)  { l = x; h = (x < 0) ? -1 : 0; }
  uint128(uint64 ll, uint64 hh) { l = ll; h = hh; }
  explicit uint128(const int128 &x);   // reinterpret the bits
  friend uint64 low (const uint128 &x) { return x.l; }
  friend uint64 high(const uint128 &x) { return x.h; }
  friend uint128 operator+(const uint128 &x, const uint128 &y);
  friend uint128 operator-(const uint128 &x, const uint128 &y);
  friend uint128 operator/(const uint128 &x, const uint128 &y);
  friend uint128 operator%(const uint128 &x, const uint128 &y);
  friend uint128 operator*(const uint128 &x, const uint128 &y);
  friend uint128 operator|(const uint128 &x, const uint128 &y);
  friend uint128 operator&(const uint128 &x, const uint128 &y);
  friend uint128 operator^(const uint128 &x, const uint128 &y);
  friend uint128 operator>>(const uint128 &x, int cnt);
  friend uint128 operator<<(const uint128 &x, int cnt);
  uint128 &operator+=(const uint128 &y);
  uint128 &operator-=(const uint128 &y);
  uint128 &operator/=(const uint128 &y);
  uint128 &operator%=(const uint128 &y);
  uint128 &operator*=(const uint128 &y);
  uint128 &operator|=(const uint128 &y);
  uint128 &operator&=(const uint128 &y);
  uint128 &operator^=(const uint128 &y);
  uint128 &operator>>=(int cnt);
  uint128 &operator<<=(int cnt);
  uint128 &operator++(void);
  uint128 &operator--(void);
  friend uint128 operator+(const uint128 &x) { return x; }
  friend uint128 operator-(const uint128 &x);
  friend uint128 operator~(const uint128 &x) { return uint128(~x.l,~x.h); }
  friend bool operator==(const uint128 &x, const uint128 &y) { return x.l == y.l && x.h == y.h; }
  friend bool operator!=(const uint128 &x, const uint128 &y) { return x.l != y.l || x.h != y.h; }
  friend bool operator> (const uint128 &x, const uint128 &y) { return x.h > y.h || (x.h == y.h && x.l >  y.l); }
  friend bool operator< (const uint128 &x, const uint128 &y) { return x.h < y.h || (x.h == y.h && x.l <  y.l); }
  friend bool operator>=(const uint128 &x, const uint128 &y) { return x.h > y.h || (x.h == y.h && x.l >= y.l); }
  friend bool operator<=(const uint128 &x, const uint128 &y) { return x.h < y.h || (x.h == y.h && x.l <= y.l); }
};

class int128
{
  uint64 l;
   int64 h;
  friend class uint128;
  // low 128 bits of an unsigned 64x64 product, without intrinsics
  static void umul(uint64 a, uint64 b, uint64 *hi, uint64 *lo)
  {
    uint64 ll = uint64(uint32(a)) * uint32(b);
    uint64 lh = uint64(uint32(a)) * uint32(b >> 32);
    uint64 hl = (a >> 32) * uint32(b);
    uint64 hh = (a >> 32) * (b >> 32);
    uint64 mid = (ll >> 32) + uint32(lh) + uint32(hl);
    *lo = (mid << 32) | uint32(ll);
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
  }
public:
  int128(void)  {}
  int128(uint x) { l = x; h = 0; }
  int128(int x)  { l = x; h = (x < 0) ? -1 : 0; }
  int128(uint64 x) { l = x; h = 0; }
  int128(int64 x)  { l = x; h = (x < 0) ? -1 : 0; }
  int128(uint64 ll, uint64 hh) { l=ll; h=hh; }
  int128(const uint128 &x) { l=x.l; h=x.h; }
  friend uint64 low (const int128 &x) { return x.l; }
  friend int64  high(const int128 &x) { return x.h; }
  friend int128 operator+(const int128 &x, const int128 &y);
  friend int128 operator-(const int128 &x, const int128 &y);
  friend int128 operator/(const int128 &x, const int128 &y);
  friend int128 operator%(const int128 &x, const int128 &y);
  friend int128 operator*(const int128 &x, const int128 &y);
  friend int128 operator|(const int128 &x, const int128 &y);
  friend int128 operator&(const int128 &x, const int128 &y);
  friend int128 operator^(const int128 &x, const int128 &y);
  friend int128 operator>>(const int128 &x, int cnt);
  friend int128 operator<<(const int128 &x, int cnt);
  int128 &operator+=(const int128 &y);
  int128 &operator-=(const int128 &y);
  int128 &operator/=(const int128 &y);
  int128 &operator%=(const int128 &y);
  int128 &operator*=(const int128 &y);
  int128 &operator|=(const int128 &y);
  int128 &operator&=(const int128 &y);
  int128 &operator^=(const int128 &y);
  int128 &operator>>=(int cnt);
  int128 &operator<<=(int cnt);
  int128 &operator++(void);
  int128 &operator--(void);
  friend int128 operator+(const int128 &x) { return x; }
  friend int128 operator-(const int128 &x);
  friend int128 operator~(const int128 &x) { return int128(~x.l,~x.h); }
  friend bool operator==(const int128 &x, const int128 &y) { return x.l == y.l && x.h == y.h; }
  friend bool operator!=(const int128 &x, const int128 &y) { return x.l != y.l || x.h != y.h; }
  friend bool operator> (const int128 &x, const int128 &y) { return x.h > y.h || (x.h == y.h && x.l >  y.l); }
  friend bool operator< (const int128 &x, const int128 &y) { return x.h < y.h || (x.h == y.h && x.l <  y.l); }
  friend bool operator>=(const int128 &x, const int128 &y) { return x.h > y.h || (x.h == y.h && x.l >= y.l); }
  friend bool operator<=(const int128 &x, const int128 &y) { return x.h < y.h || (x.h == y.h && x.l <= y.l); }
};

inline int128  make_int128(uint64 ll, int64 hh) { return int128(ll, hh); }
inline uint128 make_uint128(uint64 ll, int64 hh) { return uint128(ll, hh); }

//---------------------------------------------------------------------------
inline uint128 operator+(const uint128 &x, const uint128 &y)
{
  uint64 h = x.h + y.h;
  uint64 l = x.l + y.l;
  if ( l < x.l )
    h = h + 1;
  return uint128(l,h);
}

//---------------------------------------------------------------------------
inline uint128 operator-(const uint128 &x, const uint128 &y)
{
  uint64 h = x.h - y.h;
  uint64 l = x.l - y.l;
  if ( l > x.l )
    h = h - 1;
  return uint128(l,h);
}

//---------------------------------------------------------------------------
inline uint128 operator|(const uint128 &x, const uint128 &y)
{
  return uint128(x.l | y.l, x.h | y.h);
}

//---------------------------------------------------------------------------
inline uint128 operator&(const uint128 &x, const uint128 &y)
{
  return uint128(x.l & y.l, x.h & y.h);
}

//---------------------------------------------------------------------------
inline uint128 operator^(const uint128 &x, const uint128 &y)
{
  return uint128(x.l ^ y.l, x.h ^ y.h);
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator+=(const uint128 &y)
{
  return *this = *this + y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator-=(const uint128 &y)
{
  return *this = *this - y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator|=(const uint128 &y)
{
  return *this = *this | y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator&=(const uint128 &y)
{
  return *this = *this & y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator^=(const uint128 &y)
{
  return *this = *this ^ y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator/=(const uint128 &y)
{
  return *this = *this / y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator%=(const uint128 &y)
{
  return *this = *this % y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator*=(const uint128 &y)
{
  return *this = *this * y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator<<=(int cnt)
{
  return *this = *this << cnt;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator>>=(int cnt)
{
  return *this = *this >> cnt;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator++(void)
{
  if ( ++l == 0 )
    ++h;
  return *this;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator--(void)
{
  if ( l == 0 )
    --h;
  --l;
  return *this;
}

//---------------------------------------------------------------------------
inline uint128 operator-(const uint128 &x)
{
  return ~x + 1;
}

//---------------------------------------------------------------------------
inline uint128::uint128(const int128 &x)
{
  l = x.l;
  h = x.h;
}

//---------------------------------------------------------------------------
//      int128
// The halves are combined as unsigned throughout: the bit patterns are the
// same as for the signed operation, and signed overflow is undefined.
//---------------------------------------------------------------------------
inline int128 operator+(const int128 &x, const int128 &y)
{
  uint64 l = x.l + y.l;
  uint64 h = uint64(x.h) + uint64(y.h) + (l < x.l ? 1 : 0);
  return int128(l, h);
}

//---------------------------------------------------------------------------
inline int128 operator-(const int128 &x, const int128 &y)
{
  uint64 l = x.l - y.l;
  uint64 h = uint64(x.h) - uint64(y.h) - (x.l < y.l ? 1 : 0);
  return int128(l, h);
}

//---------------------------------------------------------------------------
inline int128 operator-(const int128 &x)
{
  return ~x + 1;
}

//---------------------------------------------------------------------------
inline int128 operator*(const int128 &x, const int128 &y)
{
  // the low 128 bits of a product are the same for signed and unsigned
  // operands, so multiply the raw bit patterns
  uint64 hi;
  uint64 lo;
  int128::umul(x.l, y.l, &hi, &lo);
  hi += x.l * uint64(y.h) + uint64(x.h) * y.l;  // modulo 2^64
  return int128(lo, hi);
}

//---------------------------------------------------------------------------
inline int128 operator|(const int128 &x, const int128 &y)
{
  return int128(x.l | y.l, uint64(x.h) | uint64(y.h));
}

//---------------------------------------------------------------------------
inline int128 operator&(const int128 &x, const int128 &y)
{
  return int128(x.l & y.l, uint64(x.h) & uint64(y.h));
}

//---------------------------------------------------------------------------
inline int128 operator^(const int128 &x, const int128 &y)
{
  return int128(x.l ^ y.l, uint64(x.h) ^ uint64(y.h));
}

//---------------------------------------------------------------------------
inline int128 operator<<(const int128 &x, int cnt)
{
  if ( cnt <= 0 )
    return x;
  if ( cnt >= 128 )
    return int128(uint64(0), uint64(0));
  if ( cnt < 64 )
    return int128(x.l << cnt, (uint64(x.h) << cnt) | (x.l >> (64 - cnt)));
  return int128(uint64(0), x.l << (cnt - 64));
}

//---------------------------------------------------------------------------
inline int128 operator>>(const int128 &x, int cnt)       // arithmetic
{
  if ( cnt <= 0 )
    return x;
  uint64 sign = x.h < 0 ? ~uint64(0) : uint64(0);
  if ( cnt >= 128 )
    return int128(sign, sign);
  if ( cnt < 64 )
    return int128((x.l >> cnt) | (uint64(x.h) << (64 - cnt)), uint64(x.h >> cnt));
  return int128(uint64(x.h >> (cnt - 64)), sign);
}

//---------------------------------------------------------------------------
inline int128 &int128::operator+=(const int128 &y) { return *this = *this + y; }
inline int128 &int128::operator-=(const int128 &y) { return *this = *this - y; }
inline int128 &int128::operator*=(const int128 &y) { return *this = *this * y; }
inline int128 &int128::operator|=(const int128 &y) { return *this = *this | y; }
inline int128 &int128::operator&=(const int128 &y) { return *this = *this & y; }
inline int128 &int128::operator^=(const int128 &y) { return *this = *this ^ y; }
inline int128 &int128::operator<<=(int cnt) { return *this = *this << cnt; }
inline int128 &int128::operator>>=(int cnt) { return *this = *this >> cnt; }

//---------------------------------------------------------------------------
inline int128 &int128::operator++(void)
{
  if ( ++l == 0 )
    ++h;
  return *this;
}

//---------------------------------------------------------------------------
inline int128 &int128::operator--(void)
{
  if ( l == 0 )
    --h;
  --l;
  return *this;
}

#endif // ifdef __cplusplus
#endif // if __HAS_INT128__

idaman THREAD_SAFE void ida_export swap128(uint128 *x);

#ifndef NO_OBSOLETE_FUNCS
idaman IDA_DEPRECATED THREAD_SAFE int64 ida_export llong_scan(
        const char *buf,
        int radix,
        const char **end);
#endif

#endif // define _LLONG_HPP
