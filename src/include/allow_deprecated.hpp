// this file should be included before calling deprecated functions
// it should be included at the point where the definitions of deprecated
// functions begin in the source file. this way a deprecated function may call
// another deprecated function without raising a warning.

// deprecated functions may call each other

// MSVC
#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(disable:4996)
#endif

// GCC
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

// Clang, Clang-cl
#ifdef __clang__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

