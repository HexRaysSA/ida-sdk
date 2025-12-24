#ifndef __PYTHON_TYPES_H
#define __PYTHON_TYPES_H

#include <stdint.h>
#include <sys/types.h>

/// Signed size_t - used to check for size overflows when the counter becomes
/// negative. Also signed size_t allows us to signal an error condition using
/// a negative value, for example, as a function return value.
#if !defined(_SSIZE_T_DEFINED) && !defined(__ssize_t_defined) && !defined(__GNUC__)
typedef ptrdiff_t ssize_t;
#endif

// Opaque Python Types
struct _typeobject;
typedef struct _typeobject PyTypeObject;
struct _frame;
typedef struct _frame PyFrameObject;
struct _ts;
typedef struct _ts PyThreadState;
struct _longobject;
typedef struct _longobject PyLongObject;
struct PyCompilerFlags;

// Less Opaque Ptyhon Types
typedef ssize_t Py_ssize_t;
typedef enum { PyGILState_LOCKED, PyGILState_UNLOCKED } PyGILState_STATE;
#define PY_LONG_LONG long long

// Part of limited API since forever, making those two members explicit should be safe(tm)
struct _object
{
  union
  {
    Py_ssize_t ob_refcnt;
    uint32_t ob_refcnt_split[2];
  };
  PyTypeObject *ob_type;
};
typedef struct _object PyObject;

typedef int (*Py_tracefunc)(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg);
typedef void (*PyCapsule_Destructor)(PyObject *);

#define _Py_NULL nullptr

#define Py_RETURN_NONE return Py_None
#define Py_RETURN_FALSE return Py_False
#define Py_RETURN_TRUE return Py_True

#define Py_LT 0
#define Py_LE 1
#define Py_EQ 2
#define Py_NE 3
#define Py_GT 4
#define Py_GE 5

#define Py_single_input 256
#define Py_file_input 257
#define Py_eval_input 258
#define Py_func_type_input 345

/* These flags are used to determine if a type is a subclass. */
#define Py_TPFLAGS_LONG_SUBCLASS        (1ULL << 24)
#define Py_TPFLAGS_LIST_SUBCLASS        (1ULL << 25)
#define Py_TPFLAGS_TUPLE_SUBCLASS       (1ULL << 26)
#define Py_TPFLAGS_BYTES_SUBCLASS       (1ULL << 27)
#define Py_TPFLAGS_UNICODE_SUBCLASS     (1ULL << 28)
#define Py_TPFLAGS_DICT_SUBCLASS        (1ULL << 29)
#define Py_TPFLAGS_BASE_EXC_SUBCLASS    (1ULL << 30)
#define Py_TPFLAGS_TYPE_SUBCLASS        (1ULL << 31)

#endif
