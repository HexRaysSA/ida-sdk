#ifndef _PYTHON_HR_H
#define _PYTHON_HR_H

/* This is a version-agnostic drop-in replacement for Python.h, defining a minimum set of types,
 * functions, and global variables, while redirecting everything through `ext_api_t`'s pointer table.
 * This table is runtime resolved on IDAPython startup, which lets us get rid of all load time
 * Python symbols. If you need additional functions or global variables from Python in IDAPython,
 * add them to `gen_extapi.py` and run the script to update the relevant files.
 *
 * If INDIRECT_PYTHON_API is not defined, this header simply includes Python.h .
 */

#ifndef INDIRECT_PYTHON_API
#include <Python.h>
#else
#include "Python_types.h"

#include "extapi.hpp"

// Define this to dump all function calls made through the redirection table to stdout
#define TRACE_REDIRECTED_API 0

#ifdef TRACE_REDIRECTED_API
#include <kernwin.hpp>
#endif

// ----------------------------------------------------------------------------
static inline unsigned long PyType_GetFlags(PyTypeObject *type);
static inline void Py_DecRef(PyObject *o);
static inline void Py_IncRef(PyObject *o);

// ----------------------------------------------------------------------------
extern ext_api_t *get_extapi();
#define PYAPI(X) get_extapi()->X##_ptr

static inline PyTypeObject *Py_TYPE(PyObject *ob) { return ob->ob_type; }
static inline int Py_IS_TYPE(PyObject *ob, PyTypeObject *type) { return Py_TYPE(ob) == type; }
static inline int PyType_HasFeature(PyTypeObject *type, unsigned long feature) { return ((PyType_GetFlags(type) & feature) != 0); }

static inline int PyLong_Check(PyObject *o)    { return PyType_HasFeature(Py_TYPE(o), Py_TPFLAGS_LONG_SUBCLASS); }
static inline int PyList_Check(PyObject *o)    { return PyType_HasFeature(Py_TYPE(o), Py_TPFLAGS_LIST_SUBCLASS); }
static inline int PyTuple_Check(PyObject *o)   { return PyType_HasFeature(Py_TYPE(o), Py_TPFLAGS_TUPLE_SUBCLASS); }
static inline int PyBytes_Check(PyObject *o)   { return PyType_HasFeature(Py_TYPE(o), Py_TPFLAGS_BYTES_SUBCLASS); }
static inline int PyUnicode_Check(PyObject *o) { return PyType_HasFeature(Py_TYPE(o), Py_TPFLAGS_UNICODE_SUBCLASS); }
static inline int PyDict_Check(PyObject *o)    { return PyType_HasFeature(Py_TYPE(o), Py_TPFLAGS_DICT_SUBCLASS); }

static inline void Py_DECREF(PyObject *op) { Py_DecRef(op); }
static inline void Py_INCREF(PyObject *op) { Py_IncRef(op); }

static inline void Py_XDECREF(PyObject *op)
{
  if ( op != _Py_NULL )
    Py_DECREF(op);
}
static inline void Py_XINCREF(PyObject *op)
{
  if ( op != _Py_NULL )
    Py_INCREF(op);
}

// AUTO GENERATED EXTAPI START STUBDEFS ----------------------------------------
static inline char *PyBytes_AsString(PyObject *o)
{
  char * r = PYAPI(PyBytes_AsString)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyBytes_AsString(%p) = \"%s\"\n", o, r);
  return r;
}
static inline int PyBytes_AsStringAndSize(PyObject *obj, char **buffer, Py_ssize_t *length)
{
  int r = PYAPI(PyBytes_AsStringAndSize)(obj, buffer, length);
  if ( TRACE_REDIRECTED_API )
    msg("PyBytes_AsStringAndSize(%p, %p, %p) = %d\n", obj, buffer, length, r);
  return r;
}
static inline PyObject *PyBytes_FromStringAndSize(const char *v, Py_ssize_t len)
{
  PyObject * r = PYAPI(PyBytes_FromStringAndSize)(v, len);
  if ( TRACE_REDIRECTED_API )
    msg("PyBytes_FromStringAndSize(%s, %" FMT_ZS ") = %p\n", v, len, r);
  return r;
}
static inline Py_ssize_t PyBytes_Size(PyObject *o)
{
  Py_ssize_t r = PYAPI(PyBytes_Size)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyBytes_Size(%p) = %" FMT_ZS "\n", o, r);
  return r;
}
static inline int PyCallable_Check(PyObject *o)
{
  int r = PYAPI(PyCallable_Check)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyCallable_Check(%p) = %d\n", o, r);
  return r;
}
static inline void *PyCapsule_GetPointer(PyObject *capsule, const char *name)
{
  void * r = PYAPI(PyCapsule_GetPointer)(capsule, name);
  if ( TRACE_REDIRECTED_API )
    msg("PyCapsule_GetPointer(%p, %s) = %p\n", capsule, name, r);
  return r;
}
static inline int PyCapsule_IsValid(PyObject *capsule, const char *name)
{
  int r = PYAPI(PyCapsule_IsValid)(capsule, name);
  if ( TRACE_REDIRECTED_API )
    msg("PyCapsule_IsValid(%p, %s) = %d\n", capsule, name, r);
  return r;
}
static inline PyObject *PyCapsule_New(void *pointer, const char *name, PyCapsule_Destructor destructor)
{
  PyObject * r = PYAPI(PyCapsule_New)(pointer, name, destructor);
  if ( TRACE_REDIRECTED_API )
    msg("PyCapsule_New(%p, %s, %p) = %p\n", pointer, name, destructor, r);
  return r;
}
static inline int PyDict_Contains(PyObject *p, PyObject *key)
{
  int r = PYAPI(PyDict_Contains)(p, key);
  if ( TRACE_REDIRECTED_API )
    msg("PyDict_Contains(%p, %p) = %d\n", p, key, r);
  return r;
}
static inline PyObject *PyDict_GetItemString(PyObject *p, const char *key)
{
  PyObject * r = PYAPI(PyDict_GetItemString)(p, key);
  if ( TRACE_REDIRECTED_API )
    msg("PyDict_GetItemString(%p, %s) = %p\n", p, key, r);
  return r;
}
static inline PyObject *PyDict_Items(PyObject *p)
{
  PyObject * r = PYAPI(PyDict_Items)(p);
  if ( TRACE_REDIRECTED_API )
    msg("PyDict_Items(%p) = %p\n", p, r);
  return r;
}
static inline int PyDict_SetItem(PyObject *p, PyObject *key, PyObject *val)
{
  int r = PYAPI(PyDict_SetItem)(p, key, val);
  if ( TRACE_REDIRECTED_API )
    msg("PyDict_SetItem(%p, %p, %p) = %d\n", p, key, val, r);
  return r;
}
static inline int PyDict_SetItemString(PyObject *p, const char *key, PyObject *val)
{
  int r = PYAPI(PyDict_SetItemString)(p, key, val);
  if ( TRACE_REDIRECTED_API )
    msg("PyDict_SetItemString(%p, %s, %p) = %d\n", p, key, val, r);
  return r;
}
static inline void PyErr_Clear()
{
  if ( TRACE_REDIRECTED_API )
    msg("PyErr_Clear()\n");
  PYAPI(PyErr_Clear)();
}
static inline void PyErr_Fetch(PyObject **ptype, PyObject **pvalue, PyObject **ptraceback)
{
  if ( TRACE_REDIRECTED_API )
    msg("PyErr_Fetch(%p, %p, %p)\n", ptype, pvalue, ptraceback);
  PYAPI(PyErr_Fetch)(ptype, pvalue, ptraceback);
}
static inline PyObject *PyErr_Occurred()
{
  PyObject * r = PYAPI(PyErr_Occurred)();
  if ( TRACE_REDIRECTED_API )
    msg("PyErr_Occurred() = %p\n", r);
  return r;
}
static inline void PyErr_Print()
{
  if ( TRACE_REDIRECTED_API )
    msg("PyErr_Print()\n");
  PYAPI(PyErr_Print)();
}
static inline void PyErr_Restore(PyObject *type, PyObject *value, PyObject *traceback)
{
  if ( TRACE_REDIRECTED_API )
    msg("PyErr_Restore(%p, %p, %p)\n", type, value, traceback);
  PYAPI(PyErr_Restore)(type, value, traceback);
}
static inline void PyErr_SetString(PyObject *type, const char *message)
{
  if ( TRACE_REDIRECTED_API )
    msg("PyErr_SetString(%p, %s)\n", type, message);
  PYAPI(PyErr_SetString)(type, message);
}
static inline PyObject *PyEval_EvalCode(PyObject *co, PyObject *globals, PyObject *locals)
{
  PyObject * r = PYAPI(PyEval_EvalCode)(co, globals, locals);
  if ( TRACE_REDIRECTED_API )
    msg("PyEval_EvalCode(%p, %p, %p) = %p\n", co, globals, locals, r);
  return r;
}
static inline PyObject *PyEval_EvalCodeEx(PyObject *co, PyObject *globals, PyObject *locals, PyObject *const*args, int argc, PyObject *const*kwds, int kwdc, PyObject *const*defs, int defc, PyObject *kwdefs, PyObject *closure)
{
  PyObject * r = PYAPI(PyEval_EvalCodeEx)(co, globals, locals, args, argc, kwds, kwdc, defs, defc, kwdefs, closure);
  if ( TRACE_REDIRECTED_API )
    msg("PyEval_EvalCodeEx(%p, %p, %p, %p, %d, %p, %d, %p, %d, %p, %p) = %p\n", co, globals, locals, args, argc, kwds, kwdc, defs, defc, kwdefs, closure, r);
  return r;
}
static inline void PyEval_InitThreads()
{
  if ( TRACE_REDIRECTED_API )
    msg("PyEval_InitThreads()\n");
  PYAPI(PyEval_InitThreads)();
}
static inline void PyEval_ReleaseThread(PyThreadState *tstate)
{
  if ( TRACE_REDIRECTED_API )
    msg("PyEval_ReleaseThread(%p)\n", tstate);
  PYAPI(PyEval_ReleaseThread)(tstate);
}
static inline void PyEval_SetTrace(Py_tracefunc func, PyObject *obj)
{
  if ( TRACE_REDIRECTED_API )
    msg("PyEval_SetTrace(%p, %p)\n", func, obj);
  PYAPI(PyEval_SetTrace)(func, obj);
}
static inline int PyEval_ThreadsInitialized()
{
  int r = PYAPI(PyEval_ThreadsInitialized)();
  if ( TRACE_REDIRECTED_API )
    msg("PyEval_ThreadsInitialized() = %d\n", r);
  return r;
}
static inline double PyFloat_AsDouble(PyObject *pyfloat)
{
  double r = PYAPI(PyFloat_AsDouble)(pyfloat);
  if ( TRACE_REDIRECTED_API )
    msg("PyFloat_AsDouble(%p) = %f\n", pyfloat, r);
  return r;
}
static inline PyObject *PyFloat_FromDouble(double v)
{
  PyObject * r = PYAPI(PyFloat_FromDouble)(v);
  if ( TRACE_REDIRECTED_API )
    msg("PyFloat_FromDouble(%f) = %p\n", v, r);
  return r;
}
static inline PyObject *PyFunction_GetCode(PyObject *op)
{
  PyObject * r = PYAPI(PyFunction_GetCode)(op);
  if ( TRACE_REDIRECTED_API )
    msg("PyFunction_GetCode(%p) = %p\n", op, r);
  return r;
}
static inline PyObject *PyFunction_New(PyObject *code, PyObject *globals)
{
  PyObject * r = PYAPI(PyFunction_New)(code, globals);
  if ( TRACE_REDIRECTED_API )
    msg("PyFunction_New(%p, %p) = %p\n", code, globals, r);
  return r;
}
static inline PyGILState_STATE PyGILState_Ensure()
{
  PyGILState_STATE r = PYAPI(PyGILState_Ensure)();
  if ( TRACE_REDIRECTED_API )
    msg("PyGILState_Ensure() = %u\n", r);
  return r;
}
static inline PyThreadState *PyGILState_GetThisThreadState()
{
  PyThreadState * r = PYAPI(PyGILState_GetThisThreadState)();
  if ( TRACE_REDIRECTED_API )
    msg("PyGILState_GetThisThreadState() = %p\n", r);
  return r;
}
static inline void PyGILState_Release(PyGILState_STATE s)
{
  if ( TRACE_REDIRECTED_API )
    msg("PyGILState_Release(%u)\n", s);
  PYAPI(PyGILState_Release)(s);
}
static inline PyObject *PyImport_AddModule(const char *name)
{
  PyObject * r = PYAPI(PyImport_AddModule)(name);
  if ( TRACE_REDIRECTED_API )
    msg("PyImport_AddModule(%s) = %p\n", name, r);
  return r;
}
static inline PyObject *PyImport_ImportModule(const char *name)
{
  PyObject * r = PYAPI(PyImport_ImportModule)(name);
  if ( TRACE_REDIRECTED_API )
    msg("PyImport_ImportModule(%s) = %p\n", name, r);
  return r;
}
static inline int PyList_Append(PyObject *list, PyObject *item)
{
  int r = PYAPI(PyList_Append)(list, item);
  if ( TRACE_REDIRECTED_API )
    msg("PyList_Append(%p, %p) = %d\n", list, item, r);
  return r;
}
static inline PyObject *PyList_GetItem(PyObject *list, Py_ssize_t index)
{
  PyObject * r = PYAPI(PyList_GetItem)(list, index);
  if ( TRACE_REDIRECTED_API )
    msg("PyList_GetItem(%p, %" FMT_ZS ") = %p\n", list, index, r);
  return r;
}
static inline int PyList_Insert(PyObject *list, Py_ssize_t index, PyObject *item)
{
  int r = PYAPI(PyList_Insert)(list, index, item);
  if ( TRACE_REDIRECTED_API )
    msg("PyList_Insert(%p, %" FMT_ZS ", %p) = %d\n", list, index, item, r);
  return r;
}
static inline PyObject *PyList_New(Py_ssize_t len)
{
  PyObject * r = PYAPI(PyList_New)(len);
  if ( TRACE_REDIRECTED_API )
    msg("PyList_New(%" FMT_ZS ") = %p\n", len, r);
  return r;
}
static inline int PyList_SetItem(PyObject *list, Py_ssize_t index, PyObject *item)
{
  int r = PYAPI(PyList_SetItem)(list, index, item);
  if ( TRACE_REDIRECTED_API )
    msg("PyList_SetItem(%p, %" FMT_ZS ", %p) = %d\n", list, index, item, r);
  return r;
}
static inline Py_ssize_t PyList_Size(PyObject *list)
{
  Py_ssize_t r = PYAPI(PyList_Size)(list);
  if ( TRACE_REDIRECTED_API )
    msg("PyList_Size(%p) = %" FMT_ZS "\n", list, r);
  return r;
}
static inline long PyLong_AsLong(PyObject *obj)
{
  long r = PYAPI(PyLong_AsLong)(obj);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_AsLong(%p) = %ld\n", obj, r);
  return r;
}
static inline long long PyLong_AsLongLong(PyObject *obj)
{
  long long r = PYAPI(PyLong_AsLongLong)(obj);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_AsLongLong(%p) = %lld\n", obj, r);
  return r;
}
static inline unsigned long PyLong_AsUnsignedLong(PyObject *pylong)
{
  unsigned long r = PYAPI(PyLong_AsUnsignedLong)(pylong);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_AsUnsignedLong(%p) = %lu\n", pylong, r);
  return r;
}
static inline unsigned long long PyLong_AsUnsignedLongLong(PyObject *pylong)
{
  unsigned long long r = PYAPI(PyLong_AsUnsignedLongLong)(pylong);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_AsUnsignedLongLong(%p) = %llu\n", pylong, r);
  return r;
}
static inline PyObject *PyLong_FromLong(long v)
{
  PyObject * r = PYAPI(PyLong_FromLong)(v);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_FromLong(%ld) = %p\n", v, r);
  return r;
}
static inline PyObject *PyLong_FromLongLong(long long v)
{
  PyObject * r = PYAPI(PyLong_FromLongLong)(v);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_FromLongLong(%lld) = %p\n", v, r);
  return r;
}
static inline PyObject *PyLong_FromSize_t(size_t v)
{
  PyObject * r = PYAPI(PyLong_FromSize_t)(v);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_FromSize_t(%" FMT_Z ") = %p\n", v, r);
  return r;
}
static inline PyObject *PyLong_FromSsize_t(Py_ssize_t v)
{
  PyObject * r = PYAPI(PyLong_FromSsize_t)(v);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_FromSsize_t(%" FMT_ZS ") = %p\n", v, r);
  return r;
}
static inline PyObject *PyLong_FromUnsignedLongLong(unsigned long long v)
{
  PyObject * r = PYAPI(PyLong_FromUnsignedLongLong)(v);
  if ( TRACE_REDIRECTED_API )
    msg("PyLong_FromUnsignedLongLong(%llu) = %p\n", v, r);
  return r;
}
static inline PyObject *PyModule_GetDict(PyObject *module)
{
  PyObject * r = PYAPI(PyModule_GetDict)(module);
  if ( TRACE_REDIRECTED_API )
    msg("PyModule_GetDict(%p) = %p\n", module, r);
  return r;
}
static inline PyObject *PyNumber_And(PyObject *o1, PyObject *o2)
{
  PyObject * r = PYAPI(PyNumber_And)(o1, o2);
  if ( TRACE_REDIRECTED_API )
    msg("PyNumber_And(%p, %p) = %p\n", o1, o2, r);
  return r;
}
static inline int PyNumber_Check(PyObject *o)
{
  int r = PYAPI(PyNumber_Check)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyNumber_Check(%p) = %d\n", o, r);
  return r;
}
static inline PyObject *PyObject_CallObject(PyObject *callable, PyObject *args)
{
  PyObject * r = PYAPI(PyObject_CallObject)(callable, args);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_CallObject(%p, %p) = %p\n", callable, args, r);
  return r;
}
static inline PyObject *PyObject_Dir(PyObject *o)
{
  PyObject * r = PYAPI(PyObject_Dir)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_Dir(%p) = %p\n", o, r);
  return r;
}
static inline PyObject *PyObject_GetAttrString(PyObject *o, const char *attr_name)
{
  PyObject * r = PYAPI(PyObject_GetAttrString)(o, attr_name);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_GetAttrString(%p, %s) = %p\n", o, attr_name, r);
  return r;
}
static inline int PyObject_HasAttrString(PyObject *o, const char *attr_name)
{
  int r = PYAPI(PyObject_HasAttrString)(o, attr_name);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_HasAttrString(%p, %s) = %d\n", o, attr_name, r);
  return r;
}
static inline int PyObject_IsInstance(PyObject *inst, PyObject *cls)
{
  int r = PYAPI(PyObject_IsInstance)(inst, cls);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_IsInstance(%p, %p) = %d\n", inst, cls, r);
  return r;
}
static inline PyObject *PyObject_Repr(PyObject *o)
{
  PyObject * r = PYAPI(PyObject_Repr)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_Repr(%p) = %p\n", o, r);
  return r;
}
static inline int PyObject_RichCompareBool(PyObject *o1, PyObject *o2, int opid)
{
  int r = PYAPI(PyObject_RichCompareBool)(o1, o2, opid);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_RichCompareBool(%p, %p, %d) = %d\n", o1, o2, opid, r);
  return r;
}
static inline int PyObject_SetAttrString(PyObject *o, const char *attr_name, PyObject *v)
{
  int r = PYAPI(PyObject_SetAttrString)(o, attr_name, v);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_SetAttrString(%p, %s, %p) = %d\n", o, attr_name, v, r);
  return r;
}
static inline PyObject *PyObject_Str(PyObject *o)
{
  PyObject * r = PYAPI(PyObject_Str)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PyObject_Str(%p) = %p\n", o, r);
  return r;
}
static inline int PyRun_SimpleStringFlags(const char *command, PyCompilerFlags *flags)
{
  int r = PYAPI(PyRun_SimpleStringFlags)(command, flags);
  if ( TRACE_REDIRECTED_API )
    msg("PyRun_SimpleStringFlags(%s, %p) = %d\n", command, flags, r);
  return r;
}
static inline PyObject *PyRun_StringFlags(const char *str, int start, PyObject *globals, PyObject *locals, PyCompilerFlags *flags)
{
  PyObject * r = PYAPI(PyRun_StringFlags)(str, start, globals, locals, flags);
  if ( TRACE_REDIRECTED_API )
    msg("PyRun_StringFlags(%s, %d, %p, %p, %p) = %p\n", str, start, globals, locals, flags, r);
  return r;
}
static inline int PySequence_Check(PyObject *o)
{
  int r = PYAPI(PySequence_Check)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PySequence_Check(%p) = %d\n", o, r);
  return r;
}
static inline PyObject *PySequence_GetItem(PyObject *o, Py_ssize_t i)
{
  PyObject * r = PYAPI(PySequence_GetItem)(o, i);
  if ( TRACE_REDIRECTED_API )
    msg("PySequence_GetItem(%p, %" FMT_ZS ") = %p\n", o, i, r);
  return r;
}
static inline Py_ssize_t PySequence_Length(PyObject *o)
{
  Py_ssize_t r = PYAPI(PySequence_Length)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PySequence_Length(%p) = %" FMT_ZS "\n", o, r);
  return r;
}
static inline Py_ssize_t PySequence_Size(PyObject *o)
{
  Py_ssize_t r = PYAPI(PySequence_Size)(o);
  if ( TRACE_REDIRECTED_API )
    msg("PySequence_Size(%p) = %" FMT_ZS "\n", o, r);
  return r;
}
static inline PyObject *PySys_GetObject(const char *name)
{
  PyObject * r = PYAPI(PySys_GetObject)(name);
  if ( TRACE_REDIRECTED_API )
    msg("PySys_GetObject(%s) = %p\n", name, r);
  return r;
}
static inline int PySys_SetObject(const char *name, PyObject *v)
{
  int r = PYAPI(PySys_SetObject)(name, v);
  if ( TRACE_REDIRECTED_API )
    msg("PySys_SetObject(%s, %p) = %d\n", name, v, r);
  return r;
}
static inline void PySys_SetPath()
{
  if ( TRACE_REDIRECTED_API )
    msg("PySys_SetPath()\n");
  PYAPI(PySys_SetPath)();
}
static inline PyThreadState *PyThreadState_Get()
{
  PyThreadState * r = PYAPI(PyThreadState_Get)();
  if ( TRACE_REDIRECTED_API )
    msg("PyThreadState_Get() = %p\n", r);
  return r;
}
static inline PyObject *PyTuple_GetItem(PyObject *p, Py_ssize_t pos)
{
  PyObject * r = PYAPI(PyTuple_GetItem)(p, pos);
  if ( TRACE_REDIRECTED_API )
    msg("PyTuple_GetItem(%p, %" FMT_ZS ") = %p\n", p, pos, r);
  return r;
}
static inline PyObject *PyTuple_New(Py_ssize_t len)
{
  PyObject * r = PYAPI(PyTuple_New)(len);
  if ( TRACE_REDIRECTED_API )
    msg("PyTuple_New(%" FMT_ZS ") = %p\n", len, r);
  return r;
}
static inline int PyTuple_SetItem(PyObject *p, Py_ssize_t pos, PyObject *o)
{
  int r = PYAPI(PyTuple_SetItem)(p, pos, o);
  if ( TRACE_REDIRECTED_API )
    msg("PyTuple_SetItem(%p, %" FMT_ZS ", %p) = %d\n", p, pos, o, r);
  return r;
}
static inline Py_ssize_t PyTuple_Size(PyObject *p)
{
  Py_ssize_t r = PYAPI(PyTuple_Size)(p);
  if ( TRACE_REDIRECTED_API )
    msg("PyTuple_Size(%p) = %" FMT_ZS "\n", p, r);
  return r;
}
static inline unsigned long PyType_GetFlags(PyTypeObject *type)
{
  unsigned long r = PYAPI(PyType_GetFlags)(type);
  if ( TRACE_REDIRECTED_API )
    msg("PyType_GetFlags(%p) = %lu\n", type, r);
  return r;
}
static inline int PyType_IsSubtype(PyTypeObject *a, PyTypeObject *b)
{
  int r = PYAPI(PyType_IsSubtype)(a, b);
  if ( TRACE_REDIRECTED_API )
    msg("PyType_IsSubtype(%p, %p) = %d\n", a, b, r);
  return r;
}
static inline PyObject *PyUnicode_AsUTF8String(PyObject *unicode)
{
  PyObject * r = PYAPI(PyUnicode_AsUTF8String)(unicode);
  if ( TRACE_REDIRECTED_API )
    msg("PyUnicode_AsUTF8String(%p) = %p\n", unicode, r);
  return r;
}
static inline PyObject *PyUnicode_FromString(const char *str)
{
  PyObject * r = PYAPI(PyUnicode_FromString)(str);
  if ( TRACE_REDIRECTED_API )
    msg("PyUnicode_FromString(%s) = %p\n", str, r);
  return r;
}
static inline PyObject *PyUnicode_FromStringAndSize(const char *str, Py_ssize_t size)
{
  PyObject * r = PYAPI(PyUnicode_FromStringAndSize)(str, size);
  if ( TRACE_REDIRECTED_API )
    msg("PyUnicode_FromStringAndSize(%s, %" FMT_ZS ") = %p\n", str, size, r);
  return r;
}
static inline PyObject *Py_CompileStringExFlags(const char *str, const char *filename, int start, PyCompilerFlags *flags, int optimize)
{
  PyObject * r = PYAPI(Py_CompileStringExFlags)(str, filename, start, flags, optimize);
  if ( TRACE_REDIRECTED_API )
    msg("Py_CompileStringExFlags(%s, %s, %d, %p, %d) = %p\n", str, filename, start, flags, optimize, r);
  return r;
}
static inline void Py_DecRef(PyObject *o)
{
  if ( TRACE_REDIRECTED_API )
    msg("Py_DecRef(%p)\n", o);
  PYAPI(Py_DecRef)(o);
}
static inline void Py_Finalize()
{
  if ( TRACE_REDIRECTED_API )
    msg("Py_Finalize()\n");
  PYAPI(Py_Finalize)();
}
static inline const char *Py_GetVersion()
{
  const char * r = PYAPI(Py_GetVersion)();
  if ( TRACE_REDIRECTED_API )
    msg("Py_GetVersion() = %s\n", r);
  return r;
}
static inline void Py_IncRef(PyObject *o)
{
  if ( TRACE_REDIRECTED_API )
    msg("Py_IncRef(%p)\n", o);
  PYAPI(Py_IncRef)(o);
}
static inline void Py_InitializeEx(int initsigs)
{
  if ( TRACE_REDIRECTED_API )
    msg("Py_InitializeEx(%d)\n", initsigs);
  PYAPI(Py_InitializeEx)(initsigs);
}
static inline int Py_IsInitialized()
{
  int r = PYAPI(Py_IsInitialized)();
  if ( TRACE_REDIRECTED_API )
    msg("Py_IsInitialized() = %d\n", r);
  return r;
}
static inline int _PyLong_AsByteArray(PyLongObject *v, unsigned char *bytes, size_t n, int little_endian, int is_signed, int with_exceptions)
{
  int r = PYAPI(_PyLong_AsByteArray)(v, bytes, n, little_endian, is_signed, with_exceptions);
  if ( TRACE_REDIRECTED_API )
    msg("_PyLong_AsByteArray(%p, %p, %" FMT_Z ", %d, %d, %d) = %d\n", v, bytes, n, little_endian, is_signed, with_exceptions, r);
  return r;
}
static inline void _Py_Dealloc()
{
  if ( TRACE_REDIRECTED_API )
    msg("_Py_Dealloc()\n");
  PYAPI(_Py_Dealloc)();
}
// AUTO GENERATED EXTAPI END STUBDEFS ----------------------------------------

// Global variables
// AUTO GENERATED EXTAPI START GLOBALDEFS --------------------------------------
#define PyBool_Type (*get_extapi()->PyBool_Type_ptr)
#define PyExc_KeyboardInterrupt (*get_extapi()->PyExc_KeyboardInterrupt_ptr)
#define PyExc_NotImplementedError (*get_extapi()->PyExc_NotImplementedError_ptr)
#define PyExc_TypeError (*get_extapi()->PyExc_TypeError_ptr)
#define PyExc_ValueError (*get_extapi()->PyExc_ValueError_ptr)
#define PyFloat_Type (*get_extapi()->PyFloat_Type_ptr)
#define PyList_Type (*get_extapi()->PyList_Type_ptr)
#define PyLong_Type (*get_extapi()->PyLong_Type_ptr)
#define Py_NoSiteFlag (*get_extapi()->Py_NoSiteFlag_ptr)
#define _Py_FalseStruct (*get_extapi()->_Py_FalseStruct_ptr)
#define _Py_NoneStruct (*get_extapi()->_Py_NoneStruct_ptr)
#define _Py_TrueStruct (*get_extapi()->_Py_TrueStruct_ptr)
// AUTO GENERATED EXTAPI END GLOBALDEFS ----------------------------------------

#define Py_True ((PyObject *)&_Py_TrueStruct)
#define Py_False ((PyObject *)&_Py_FalseStruct)
#define Py_None ((PyObject *)&_Py_NoneStruct)

static inline int PyBool_Check(PyObject *o)      { return Py_IS_TYPE(o, &PyBool_Type); }
static inline int PyFloat_Check(PyObject *o)     { return Py_IS_TYPE(o, &PyFloat_Type); }
static inline int PyLong_CheckExact(PyObject *o) { return Py_IS_TYPE(o, &PyLong_Type); }
static inline int PyList_CheckExact(PyObject *o) { return Py_IS_TYPE(o, &PyList_Type); }

#endif

#endif /* #ifdef _PYTHON_HR_H */
