#include <pro.h>
#include "findcrypt.hpp"

// Various constants used in crypto algorithms
// They were copied from public domain codes

static const word32 SHA_1[] =
{
  0x67452301,
  0xEFCDAB89,
  0x98BADCFE,
  0x10325476,
  0xC3D2E1F0,
};

static const word32 RC5_RC6[] =
{
  0xb7e15163, // magic constant P for wordsize
  0x9e3779b9, // magic constant Q for wordsize
};

static const word32 MD5[] =
{
  0xd76aa478,
  0xe8c7b756,
  0x242070db,
  0xc1bdceee,
  0xf57c0faf,
  0x4787c62a,
  0xa8304613,
  0xfd469501,
  0x698098d8,
  0x8b44f7af,
  0xffff5bb1,
  0x895cd7be,
  0x6b901122,
  0xfd987193,
  0xa679438e,
  0x49b40821,

  0xf61e2562,
  0xc040b340,
  0x265e5a51,
  0xe9b6c7aa,
  0xd62f105d,
  0x02441453,
  0xd8a1e681,
  0xe7d3fbc8,
  0x21e1cde6,
  0xc33707d6,
  0xf4d50d87,
  0x455a14ed,
  0xa9e3e905,
  0xfcefa3f8,
  0x676f02d9,
  0x8d2a4c8a,

  0xfffa3942,
  0x8771f681,
  0x6d9d6122,
  0xfde5380c,
  0xa4beea44,
  0x4bdecfa9,
  0xf6bb4b60,
  0xbebfbc70,
  0x289b7ec6,
  0xeaa127fa,
  0xd4ef3085,
  0x04881d05,
  0xd9d4d039,
  0xe6db99e5,
  0x1fa27cf8,
  0xc4ac5665,

  0xf4292244,
  0x432aff97,
  0xab9423a7,
  0xfc93a039,
  0x655b59c3,
  0x8f0ccc92,
  0xffeff47d,
  0x85845dd1,
  0x6fa87e4f,
  0xfe2ce6e0,
  0xa3014314,
  0x4e0811a1,
  0xf7537e82,
  0xbd3af235,
  0x2ad7d2bb,
  0xeb86d391,
};

static const word32 MD4[] =
{
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
};

static const word32 HAVAL[] =
{
  0x243F6A88,
  0x85A308D3,
  0x13198A2E,
  0x03707344,
  0xA4093822,
  0x299F31D0,
  0x082EFA98,
  0xEC4E6C89,
};

// NB: all sparse arrays must be word32!
const array_info_t sparse_consts[] =
{
  { ARR(SHA_1),      "SHA-1"     },
  { ARR(RC5_RC6),    "RC5_RC6"   },
  { ARR(MD5),        "MD5"       },
  { ARR(MD4),        "MD4"       },
  { ARR(HAVAL),      "HAVAL"     },
  { nullptr, 0, 0, nullptr, nullptr }
};
