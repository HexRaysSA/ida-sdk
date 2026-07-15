#ifndef EXTAPI_HPP
#define EXTAPI_HPP

#include <pro.h>

#ifndef INDIRECT_PYTHON_API

#include <Python.h>

#ifdef Py_LIMITED_API
typedef void *Py_tracefunc;
struct PyCompilerFlags;
#  if PY_MAJOR_VERSION < 3 || PY_MINOR_VERSION < 9
struct PyFrameObject;
#  endif
#else
#  include <frameobject.h>
#endif

#else
#include "py-include/Python_types.h"
#endif

// AUTO GENERATED EXTAPI START TYPEDEFS ----------------------------------------
typedef char *PyBytes_AsString_t(PyObject *);
typedef int PyBytes_AsStringAndSize_t(PyObject *, char **, Py_ssize_t *);
typedef PyObject *PyBytes_FromStringAndSize_t(const char *, Py_ssize_t);
typedef Py_ssize_t PyBytes_Size_t(PyObject *);
typedef int PyCallable_Check_t(PyObject *);
typedef void *PyCapsule_GetPointer_t(PyObject *, const char *);
typedef int PyCapsule_IsValid_t(PyObject *, const char *);
typedef PyObject *PyCapsule_New_t(void *, const char *, PyCapsule_Destructor);
typedef int PyDict_Contains_t(PyObject *, PyObject *);
typedef PyObject *PyDict_GetItemString_t(PyObject *, const char *);
typedef PyObject *PyDict_Items_t(PyObject *);
typedef int PyDict_SetItem_t(PyObject *, PyObject *, PyObject *);
typedef int PyDict_SetItemString_t(PyObject *, const char *, PyObject *);
typedef void PyErr_Clear_t();
typedef void PyErr_Fetch_t(PyObject **, PyObject **, PyObject **);
typedef PyObject *PyErr_Format_t(PyObject *, const char *, ...);
typedef PyObject *PyErr_Occurred_t();
typedef void PyErr_Print_t();
typedef void PyErr_Restore_t(PyObject *, PyObject *, PyObject *);
typedef void PyErr_SetString_t(PyObject *, const char *);
typedef PyObject *PyEval_EvalCode_t(PyObject *, PyObject *, PyObject *);
typedef PyObject *PyEval_EvalCodeEx_t(PyObject *, PyObject *, PyObject *, PyObject *const*, int, PyObject *const*, int, PyObject *const*, int, PyObject *, PyObject *);
typedef void PyEval_InitThreads_t();
typedef void PyEval_ReleaseThread_t(PyThreadState *);
typedef void PyEval_SetTrace_t(Py_tracefunc, PyObject *);
typedef int PyEval_ThreadsInitialized_t();
typedef double PyFloat_AsDouble_t(PyObject *);
typedef PyObject *PyFloat_FromDouble_t(double);
typedef PyObject *PyFunction_GetCode_t(PyObject *);
typedef PyObject *PyFunction_New_t(PyObject *, PyObject *);
typedef PyGILState_STATE PyGILState_Ensure_t();
typedef PyThreadState *PyGILState_GetThisThreadState_t();
typedef void PyGILState_Release_t(PyGILState_STATE);
typedef PyObject *PyImport_AddModule_t(const char *);
typedef PyObject *PyImport_ImportModule_t(const char *);
typedef int PyList_Append_t(PyObject *, PyObject *);
typedef PyObject *PyList_GetItem_t(PyObject *, Py_ssize_t);
typedef int PyList_Insert_t(PyObject *, Py_ssize_t, PyObject *);
typedef PyObject *PyList_New_t(Py_ssize_t);
typedef int PyList_SetItem_t(PyObject *, Py_ssize_t, PyObject *);
typedef Py_ssize_t PyList_Size_t(PyObject *);
typedef long PyLong_AsLong_t(PyObject *);
typedef long long PyLong_AsLongLong_t(PyObject *);
typedef unsigned long PyLong_AsUnsignedLong_t(PyObject *);
typedef unsigned long long PyLong_AsUnsignedLongLong_t(PyObject *);
typedef PyObject *PyLong_FromLong_t(long);
typedef PyObject *PyLong_FromLongLong_t(long long);
typedef PyObject *PyLong_FromSize_t_t(size_t);
typedef PyObject *PyLong_FromSsize_t_t(Py_ssize_t);
typedef PyObject *PyLong_FromUnsignedLongLong_t(unsigned long long);
typedef PyObject *PyModule_GetDict_t(PyObject *);
typedef PyObject *PyNumber_And_t(PyObject *, PyObject *);
typedef int PyNumber_Check_t(PyObject *);
typedef PyObject *PyObject_CallFunction_t(PyObject *, const char *, ...);
typedef PyObject *PyObject_CallFunctionObjArgs_t(PyObject *, ...);
typedef PyObject *PyObject_CallMethod_t(PyObject *, const char *, const char *, ...);
typedef PyObject *PyObject_CallObject_t(PyObject *, PyObject *);
typedef PyObject *PyObject_Dir_t(PyObject *);
typedef PyObject *PyObject_GetAttrString_t(PyObject *, const char *);
typedef int PyObject_HasAttrString_t(PyObject *, const char *);
typedef int PyObject_IsInstance_t(PyObject *, PyObject *);
typedef PyObject *PyObject_Repr_t(PyObject *);
typedef int PyObject_RichCompareBool_t(PyObject *, PyObject *, int);
typedef int PyObject_SetAttrString_t(PyObject *, const char *, PyObject *);
typedef PyObject *PyObject_Str_t(PyObject *);
typedef int PyRun_SimpleStringFlags_t(const char *, PyCompilerFlags *);
typedef PyObject *PyRun_StringFlags_t(const char *, int, PyObject *, PyObject *, PyCompilerFlags *);
typedef int PySequence_Check_t(PyObject *);
typedef PyObject *PySequence_GetItem_t(PyObject *, Py_ssize_t);
typedef Py_ssize_t PySequence_Length_t(PyObject *);
typedef Py_ssize_t PySequence_Size_t(PyObject *);
typedef PyObject *PySys_GetObject_t(const char *);
typedef int PySys_SetObject_t(const char *, PyObject *);
typedef PyThreadState *PyThreadState_Get_t();
typedef PyObject *PyTuple_GetItem_t(PyObject *, Py_ssize_t);
typedef PyObject *PyTuple_New_t(Py_ssize_t);
typedef int PyTuple_SetItem_t(PyObject *, Py_ssize_t, PyObject *);
typedef Py_ssize_t PyTuple_Size_t(PyObject *);
typedef unsigned long PyType_GetFlags_t(PyTypeObject *);
typedef int PyType_IsSubtype_t(PyTypeObject *, PyTypeObject *);
typedef PyObject *PyUnicode_AsUTF8String_t(PyObject *);
typedef PyObject *PyUnicode_FromString_t(const char *);
typedef PyObject *PyUnicode_FromStringAndSize_t(const char *, Py_ssize_t);
typedef PyObject *Py_BuildValue_t(const char *, ...);
typedef PyObject *Py_CompileStringExFlags_t(const char *, const char *, int, PyCompilerFlags *, int);
typedef void Py_DecRef_t(PyObject *);
typedef void Py_Finalize_t();
typedef const char *Py_GetVersion_t();
typedef void Py_IncRef_t(PyObject *);
typedef void Py_InitializeEx_t(int);
typedef int Py_IsInitialized_t();
typedef int _PyLong_AsByteArray_t(PyLongObject *, unsigned char *, size_t, int, int, int);
typedef PyObject *_PyLong_FromByteArray_t(const unsigned char *, size_t, int, int);
typedef void _Py_Dealloc_t();
typedef PyTypeObject PyBool_Type_t;
typedef PyObject *PyExc_KeyboardInterrupt_t;
typedef PyObject *PyExc_NotImplementedError_t;
typedef PyObject *PyExc_TypeError_t;
typedef PyObject *PyExc_ValueError_t;
typedef PyTypeObject PyFloat_Type_t;
typedef PyTypeObject PyList_Type_t;
typedef PyTypeObject PyLong_Type_t;
typedef int Py_NoSiteFlag_t;
typedef PyObject *_Py_FalseStruct_t;
typedef PyObject *_Py_NoneStruct_t;
typedef PyObject *_Py_TrueStruct_t;
// AUTO GENERATED EXTAPI END TYPEDEFS ------------------------------------------

struct ext_api_t
{
#ifdef __NT__
  qwstring prev_dll_directory;
#endif
  qstring lib_path;
  void *lib_handle = nullptr;

  // AUTO GENERATED EXTAPI START STRUCTDEFS ------------------------------------
  PyBytes_AsString_t *PyBytes_AsString_ptr = nullptr;
  PyBytes_AsStringAndSize_t *PyBytes_AsStringAndSize_ptr = nullptr;
  PyBytes_FromStringAndSize_t *PyBytes_FromStringAndSize_ptr = nullptr;
  PyBytes_Size_t *PyBytes_Size_ptr = nullptr;
  PyCallable_Check_t *PyCallable_Check_ptr = nullptr;
  PyCapsule_GetPointer_t *PyCapsule_GetPointer_ptr = nullptr;
  PyCapsule_IsValid_t *PyCapsule_IsValid_ptr = nullptr;
  PyCapsule_New_t *PyCapsule_New_ptr = nullptr;
  PyDict_Contains_t *PyDict_Contains_ptr = nullptr;
  PyDict_GetItemString_t *PyDict_GetItemString_ptr = nullptr;
  PyDict_Items_t *PyDict_Items_ptr = nullptr;
  PyDict_SetItem_t *PyDict_SetItem_ptr = nullptr;
  PyDict_SetItemString_t *PyDict_SetItemString_ptr = nullptr;
  PyErr_Clear_t *PyErr_Clear_ptr = nullptr;
  PyErr_Fetch_t *PyErr_Fetch_ptr = nullptr;
  PyErr_Format_t *PyErr_Format_ptr = nullptr;
  PyErr_Occurred_t *PyErr_Occurred_ptr = nullptr;
  PyErr_Print_t *PyErr_Print_ptr = nullptr;
  PyErr_Restore_t *PyErr_Restore_ptr = nullptr;
  PyErr_SetString_t *PyErr_SetString_ptr = nullptr;
  PyEval_EvalCode_t *PyEval_EvalCode_ptr = nullptr;
  PyEval_EvalCodeEx_t *PyEval_EvalCodeEx_ptr = nullptr;
  PyEval_InitThreads_t *PyEval_InitThreads_ptr = nullptr;
  PyEval_ReleaseThread_t *PyEval_ReleaseThread_ptr = nullptr;
  PyEval_SetTrace_t *PyEval_SetTrace_ptr = nullptr;
  PyEval_ThreadsInitialized_t *PyEval_ThreadsInitialized_ptr = nullptr;
  PyFloat_AsDouble_t *PyFloat_AsDouble_ptr = nullptr;
  PyFloat_FromDouble_t *PyFloat_FromDouble_ptr = nullptr;
  PyFunction_GetCode_t *PyFunction_GetCode_ptr = nullptr;
  PyFunction_New_t *PyFunction_New_ptr = nullptr;
  PyGILState_Ensure_t *PyGILState_Ensure_ptr = nullptr;
  PyGILState_GetThisThreadState_t *PyGILState_GetThisThreadState_ptr = nullptr;
  PyGILState_Release_t *PyGILState_Release_ptr = nullptr;
  PyImport_AddModule_t *PyImport_AddModule_ptr = nullptr;
  PyImport_ImportModule_t *PyImport_ImportModule_ptr = nullptr;
  PyList_Append_t *PyList_Append_ptr = nullptr;
  PyList_GetItem_t *PyList_GetItem_ptr = nullptr;
  PyList_Insert_t *PyList_Insert_ptr = nullptr;
  PyList_New_t *PyList_New_ptr = nullptr;
  PyList_SetItem_t *PyList_SetItem_ptr = nullptr;
  PyList_Size_t *PyList_Size_ptr = nullptr;
  PyLong_AsLong_t *PyLong_AsLong_ptr = nullptr;
  PyLong_AsLongLong_t *PyLong_AsLongLong_ptr = nullptr;
  PyLong_AsUnsignedLong_t *PyLong_AsUnsignedLong_ptr = nullptr;
  PyLong_AsUnsignedLongLong_t *PyLong_AsUnsignedLongLong_ptr = nullptr;
  PyLong_FromLong_t *PyLong_FromLong_ptr = nullptr;
  PyLong_FromLongLong_t *PyLong_FromLongLong_ptr = nullptr;
  PyLong_FromSize_t_t *PyLong_FromSize_t_ptr = nullptr;
  PyLong_FromSsize_t_t *PyLong_FromSsize_t_ptr = nullptr;
  PyLong_FromUnsignedLongLong_t *PyLong_FromUnsignedLongLong_ptr = nullptr;
  PyModule_GetDict_t *PyModule_GetDict_ptr = nullptr;
  PyNumber_And_t *PyNumber_And_ptr = nullptr;
  PyNumber_Check_t *PyNumber_Check_ptr = nullptr;
  PyObject_CallFunction_t *PyObject_CallFunction_ptr = nullptr;
  PyObject_CallFunctionObjArgs_t *PyObject_CallFunctionObjArgs_ptr = nullptr;
  PyObject_CallMethod_t *PyObject_CallMethod_ptr = nullptr;
  PyObject_CallObject_t *PyObject_CallObject_ptr = nullptr;
  PyObject_Dir_t *PyObject_Dir_ptr = nullptr;
  PyObject_GetAttrString_t *PyObject_GetAttrString_ptr = nullptr;
  PyObject_HasAttrString_t *PyObject_HasAttrString_ptr = nullptr;
  PyObject_IsInstance_t *PyObject_IsInstance_ptr = nullptr;
  PyObject_Repr_t *PyObject_Repr_ptr = nullptr;
  PyObject_RichCompareBool_t *PyObject_RichCompareBool_ptr = nullptr;
  PyObject_SetAttrString_t *PyObject_SetAttrString_ptr = nullptr;
  PyObject_Str_t *PyObject_Str_ptr = nullptr;
  PyRun_SimpleStringFlags_t *PyRun_SimpleStringFlags_ptr = nullptr;
  PyRun_StringFlags_t *PyRun_StringFlags_ptr = nullptr;
  PySequence_Check_t *PySequence_Check_ptr = nullptr;
  PySequence_GetItem_t *PySequence_GetItem_ptr = nullptr;
  PySequence_Length_t *PySequence_Length_ptr = nullptr;
  PySequence_Size_t *PySequence_Size_ptr = nullptr;
  PySys_GetObject_t *PySys_GetObject_ptr = nullptr;
  PySys_SetObject_t *PySys_SetObject_ptr = nullptr;
  PyThreadState_Get_t *PyThreadState_Get_ptr = nullptr;
  PyTuple_GetItem_t *PyTuple_GetItem_ptr = nullptr;
  PyTuple_New_t *PyTuple_New_ptr = nullptr;
  PyTuple_SetItem_t *PyTuple_SetItem_ptr = nullptr;
  PyTuple_Size_t *PyTuple_Size_ptr = nullptr;
  PyType_GetFlags_t *PyType_GetFlags_ptr = nullptr;
  PyType_IsSubtype_t *PyType_IsSubtype_ptr = nullptr;
  PyUnicode_AsUTF8String_t *PyUnicode_AsUTF8String_ptr = nullptr;
  PyUnicode_FromString_t *PyUnicode_FromString_ptr = nullptr;
  PyUnicode_FromStringAndSize_t *PyUnicode_FromStringAndSize_ptr = nullptr;
  Py_BuildValue_t *Py_BuildValue_ptr = nullptr;
  Py_CompileStringExFlags_t *Py_CompileStringExFlags_ptr = nullptr;
  Py_DecRef_t *Py_DecRef_ptr = nullptr;
  Py_Finalize_t *Py_Finalize_ptr = nullptr;
  Py_GetVersion_t *Py_GetVersion_ptr = nullptr;
  Py_IncRef_t *Py_IncRef_ptr = nullptr;
  Py_InitializeEx_t *Py_InitializeEx_ptr = nullptr;
  Py_IsInitialized_t *Py_IsInitialized_ptr = nullptr;
  _PyLong_AsByteArray_t *_PyLong_AsByteArray_ptr = nullptr;
  _PyLong_FromByteArray_t *_PyLong_FromByteArray_ptr = nullptr;
  _Py_Dealloc_t *_Py_Dealloc_ptr = nullptr;
  PyBool_Type_t *PyBool_Type_ptr = nullptr;
  PyExc_KeyboardInterrupt_t *PyExc_KeyboardInterrupt_ptr = nullptr;
  PyExc_NotImplementedError_t *PyExc_NotImplementedError_ptr = nullptr;
  PyExc_TypeError_t *PyExc_TypeError_ptr = nullptr;
  PyExc_ValueError_t *PyExc_ValueError_ptr = nullptr;
  PyFloat_Type_t *PyFloat_Type_ptr = nullptr;
  PyList_Type_t *PyList_Type_ptr = nullptr;
  PyLong_Type_t *PyLong_Type_ptr = nullptr;
  Py_NoSiteFlag_t *Py_NoSiteFlag_ptr = nullptr;
  _Py_FalseStruct_t *_Py_FalseStruct_ptr = nullptr;
  _Py_NoneStruct_t *_Py_NoneStruct_ptr = nullptr;
  _Py_TrueStruct_t *_Py_TrueStruct_ptr = nullptr;
  // AUTO GENERATED EXTAPI END STRUCTDEFS --------------------------------------

  ~ext_api_t() { clear(); }

  bool load(qstring *errbuf);
  void clear();
  private:
  bool locate_libpython(qstring *errbuf);
  bool load_libpython();
  bool find_libpython_preloaded();
  bool find_libpython_registry();
};

#endif // EXTAPI_HPP
