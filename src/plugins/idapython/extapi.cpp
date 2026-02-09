
#include <pro.h>
#include <kernwin.hpp>
#include <err.h>
#include <registry.hpp>

#if defined(__LINUX__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define DL_ITERATE_BUFSIZE 1024
#include <dlfcn.h>
#include <link.h>
typedef void *HMODULE;
#elif defined(__APPLE__)
#include <dlfcn.h>
#include <mach-o/dyld.h>
typedef void *HMODULE;
#elif defined(__NT__)
#include <windows.h>
#include <psapi.h>
#endif

#include "extapi.hpp"

#ifdef DEBUG_PLUGINS
#define pmsg msg

#define pdeb(ida_debug_bits, ...)           \
  do                                        \
  {                                         \
    deb(ida_debug_bits, __VA_ARGS__);       \
    if ( (debug & (ida_debug_bits)) == 0 )  \
      pmsg(__VA_ARGS__);                    \
  } while ( false )
#else
#define pdeb deb
#define pmsg(format, ...)
#endif

// Function to look for that is exported by libpython.
// NOTE: Pick a symbol outside of the limited API, otherwise
// GetProcAddress on Windows will resolve to a symbol inside
// python3.dll, causing any non-limited API symbols to become
// unresolvable.
#define LIBPYTHON_3Y_CANARY_SYMBOL "PyFunction_New"

#ifdef __LINUX__
//-------------------------------------------------------------------------
static int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *data)
{
  char *found_lib_path = (char *)data;

  if ( !info->dlpi_name || strlen(info->dlpi_name) == 0 )
    return 0;

  void *handle = dlopen(info->dlpi_name, RTLD_LAZY | RTLD_NOLOAD);
  if ( handle == nullptr )
    return 0;

  void *sym = dlsym(handle, LIBPYTHON_3Y_CANARY_SYMBOL);
  if ( sym != nullptr )
  {
    qstrncpy(found_lib_path, info->dlpi_name, DL_ITERATE_BUFSIZE);
    dlclose(handle);
    return 1;
  }
  dlclose(handle);
  return 0;
}
#endif

//-------------------------------------------------------------------------
bool ext_api_t::load_libpython()
{
#ifndef __NT__
  // load and make symbols available
  lib_handle = dlopen(lib_path.c_str(), RTLD_NOW | RTLD_GLOBAL);
  if ( lib_handle == nullptr )
  {
    msg("error loading Python dynamic library %s: %s\n", lib_path.c_str(), dlerror());
    return false;
  }
  pdeb(IDA_DEBUG_PLUGIN, "Python dynamic library handle: %p\n", lib_handle);
  pdeb(IDA_DEBUG_PLUGIN, "Python dynamic library path: %s\n", lib_path.c_str());
  return true;
#else // __NT__
  char dll_dir[QMAXPATH];
  if ( qdirname(dll_dir, sizeof(dll_dir), lib_path.c_str()) )
  {
    if ( qfileexist(lib_path.c_str()) && qisdir(dll_dir) )
    {
      qwstring wlib_path;
      qwstring wdll_dir;

      if ( !utf8_utf16(&wlib_path, lib_path.c_str()) )
        return false;
      if ( !utf8_utf16(&wdll_dir, dll_dir) )
        return false;

      lib_handle = LoadLibraryW(wlib_path.c_str());
      pdeb(IDA_DEBUG_PLUGIN, "IDAPython preload: python3Y.dll handle: %p\n", lib_handle);

      if ( lib_handle != nullptr )
      {
        // Add the directory to the list of loader directories, so
        // python3.dll will be found.
        DWORD nchars = GetDllDirectoryW(0, nullptr);
        if ( nchars > 0 )
        {
          prev_dll_directory.resize(nchars);
          GetDllDirectoryW(prev_dll_directory.length(), prev_dll_directory.begin());
        }
        SetDllDirectoryW(wdll_dir.begin());
        return true;
      }
      else
      {
        pdeb(IDA_DEBUG_PLUGIN,
            "IDAPython preload: failed to load python3Y.dll handle: %s\n",
            winerr(GetLastError()));
        return false;
      }
    }
  }
  return false;
#endif
}

//-------------------------------------------------------------------------
// check if Python APIs are alredy present in the process (e.g. libida hosted by Python)
bool ext_api_t::find_libpython_preloaded()
{
#ifdef __NT__
  // Inspired by https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
  HANDLE hProcess = GetCurrentProcess();
  HMODULE hMods[1024];
  DWORD cbNeeded;
  wchar_t modName[MAX_PATH];
  if ( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded) == 0 )
    return false;

  for ( size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
  {
    if ( GetProcAddress(hMods[i], LIBPYTHON_3Y_CANARY_SYMBOL) != nullptr )
    {
      lib_handle = (void *) hMods[i];
      if ( GetModuleFileNameW(hMods[i], modName, MAX_PATH) != 0 )
      {
        qstring tmp;
        if ( utf16_utf8(&tmp, modName) )
          lib_path.swap(tmp);
      }
      else
      {
        lib_path = "<unknown>";
      }
      return true;
    }
  }
  return false;
#elif defined(__LINUX__)
  char found_library_path[DL_ITERATE_BUFSIZE] = { 0 };
  if ( dl_iterate_phdr(dl_iterate_callback, (void *)found_library_path) )
  {
    lib_path = found_library_path;
    lib_handle = dlopen(found_library_path, RTLD_LAZY | RTLD_NOLOAD);
    return true;
  }
  // check if the canary symbol is available in the main executable
  // applies to statically linked python interpreter, i.e. no shared libpython
  void *handle = dlopen(nullptr, RTLD_LAZY);
  if ( handle == nullptr )
    return false;

  void *sym = dlsym(handle, LIBPYTHON_3Y_CANARY_SYMBOL);
  if ( sym != nullptr )
  {
    Dl_info dl_info;
    if ( dladdr(sym, &dl_info) )
    {
      lib_handle = handle;
      lib_path = dl_info.dli_fname;

      return true;
    }
  }
  return false;
#else
  for ( uint i = 0; i < _dyld_image_count(); i++ )
  {
    const char *image_name = _dyld_get_image_name(i);

    void *handle = dlopen(image_name, RTLD_LAZY | RTLD_NOLOAD | RTLD_FIRST);
    if ( handle == nullptr )
      continue;

    void *sym = dlsym(handle, LIBPYTHON_3Y_CANARY_SYMBOL);
    if ( sym != nullptr )
    {
      lib_handle = handle;
      lib_path = image_name;
      // man dlopen:
      // If the same shared object is opened again with dlopen(), the same
      // object handle is returned. The dynamic linker maintains reference
      // counts for object handles, so a dynamically loaded shared object is
      // not deallocated until dlclose() has been called on it as many times
      // as dlopen() has succeeded on it.
      dlclose(handle);
      return true;
    }
    dlclose(handle);
  }
  return false;
#endif
}

//-------------------------------------------------------------------------
bool ext_api_t::find_libpython_registry()
{
  if ( !reg_read_string(&lib_path, "Python3TargetDLL") )
    return false;

  return load_libpython();
}

//-------------------------------------------------------------------------
bool ext_api_t::locate_libpython(qstring *errbuf)
{
  if ( find_libpython_preloaded() )
  {
    pdeb(IDA_DEBUG_PLUGIN, "IDAPython: found preloaded Python library: \"%s\"\n", lib_path.c_str());
    return true;
  }

  if ( find_libpython_registry() )
  {
    pdeb(IDA_DEBUG_PLUGIN, "IDAPython: loaded registry-specified Python library: \"%s\"\n", lib_path.c_str());
    return true;
  }

  static const char str[] =
    "Python 3 is not configured (Python3TargetDLL value is not set).\n"
    "Please run idapyswitch to select a Python 3 install.";
  if ( errbuf != nullptr )
    *errbuf = str;
  msg("WARNING: %s\n", str);

  return false;
}

//-------------------------------------------------------------------------
bool ext_api_t::load(qstring *errbuf)
{
  QASSERT(30602, lib_path.empty() && lib_handle == nullptr);

  if ( !locate_libpython(errbuf) )
    return false;

  QASSERT(30837, lib_handle != nullptr);

#ifdef __NT__
#define BIND_SYMBOL_x(Name_str, Name_t, Name_ptr, fail)                 \
  do                                                                    \
  {                                                                     \
    * (FARPROC *) &Name_ptr = GetProcAddress(                           \
            (HMODULE) lib_handle, TEXT(Name_str));                      \
    if ( Name_ptr == nullptr )                                          \
    {                                                                   \
      if ( fail )                                                       \
      {                                                                 \
        errbuf->sprnt("GetProcAddress(\"%s\") failed: %s\n",            \
                      Name_str, winerr(GetLastError()));                \
        return false;                                                   \
      }                                                                 \
      else                                                              \
      {                                                                 \
        msg("IDAPython: GetProcAddress(\"%s\") failed: %s\n",           \
            Name_str, winerr(GetLastError()));                          \
      }                                                                 \
    }                                                                   \
  } while ( 0 )
#else
#define BIND_SYMBOL_x(Name_str, Name_t, Name_ptr, fail)                 \
  do                                                                    \
  {                                                                     \
    Name_ptr = (Name_t *) dlsym(lib_handle, Name_str);                  \
    if ( Name_ptr == nullptr )                                          \
    {                                                                   \
      if ( fail )                                                       \
      {                                                                 \
        errbuf->sprnt("dlsym(\"%s\") failed: %s\n", Name_str,           \
                      dlerror());                                       \
        return false;                                                   \
      }                                                                 \
      else                                                              \
      {                                                                 \
        msg("IDAPython: dlsym(\"%s\") failed: %s\n", Name_str,          \
            dlerror());                                                 \
      }                                                                 \
    }                                                                   \
  } while ( 0 )
#endif

#define BIND_SYMBOL(Name_str, Name_t, Name_ptr)      BIND_SYMBOL_x(Name_str, Name_t, Name_ptr, true)
#define BIND_SYMBOL_WEAK(Name_str, Name_t, Name_ptr) BIND_SYMBOL_x(Name_str, Name_t, Name_ptr, false)
// AUTO GENERATED EXTAPI START BINDALL -----------------------------------------
  BIND_SYMBOL_WEAK("PyBytes_AsString", PyBytes_AsString_t, PyBytes_AsString_ptr);
  BIND_SYMBOL_WEAK("PyBytes_AsStringAndSize", PyBytes_AsStringAndSize_t, PyBytes_AsStringAndSize_ptr);
  BIND_SYMBOL_WEAK("PyBytes_FromStringAndSize", PyBytes_FromStringAndSize_t, PyBytes_FromStringAndSize_ptr);
  BIND_SYMBOL_WEAK("PyBytes_Size", PyBytes_Size_t, PyBytes_Size_ptr);
  BIND_SYMBOL_WEAK("PyCallable_Check", PyCallable_Check_t, PyCallable_Check_ptr);
  BIND_SYMBOL_WEAK("PyCapsule_GetPointer", PyCapsule_GetPointer_t, PyCapsule_GetPointer_ptr);
  BIND_SYMBOL_WEAK("PyCapsule_IsValid", PyCapsule_IsValid_t, PyCapsule_IsValid_ptr);
  BIND_SYMBOL_WEAK("PyCapsule_New", PyCapsule_New_t, PyCapsule_New_ptr);
  BIND_SYMBOL_WEAK("PyDict_Contains", PyDict_Contains_t, PyDict_Contains_ptr);
  BIND_SYMBOL_WEAK("PyDict_GetItemString", PyDict_GetItemString_t, PyDict_GetItemString_ptr);
  BIND_SYMBOL_WEAK("PyDict_Items", PyDict_Items_t, PyDict_Items_ptr);
  BIND_SYMBOL_WEAK("PyDict_SetItem", PyDict_SetItem_t, PyDict_SetItem_ptr);
  BIND_SYMBOL_WEAK("PyDict_SetItemString", PyDict_SetItemString_t, PyDict_SetItemString_ptr);
  BIND_SYMBOL_WEAK("PyErr_Clear", PyErr_Clear_t, PyErr_Clear_ptr);
  BIND_SYMBOL_WEAK("PyErr_Fetch", PyErr_Fetch_t, PyErr_Fetch_ptr);
  BIND_SYMBOL_WEAK("PyErr_Format", PyErr_Format_t, PyErr_Format_ptr);
  BIND_SYMBOL_WEAK("PyErr_Occurred", PyErr_Occurred_t, PyErr_Occurred_ptr);
  BIND_SYMBOL_WEAK("PyErr_Print", PyErr_Print_t, PyErr_Print_ptr);
  BIND_SYMBOL_WEAK("PyErr_Restore", PyErr_Restore_t, PyErr_Restore_ptr);
  BIND_SYMBOL_WEAK("PyErr_SetString", PyErr_SetString_t, PyErr_SetString_ptr);
  BIND_SYMBOL_WEAK("PyEval_EvalCode", PyEval_EvalCode_t, PyEval_EvalCode_ptr);
  BIND_SYMBOL_WEAK("PyEval_EvalCodeEx", PyEval_EvalCodeEx_t, PyEval_EvalCodeEx_ptr);
  BIND_SYMBOL_WEAK("PyEval_InitThreads", PyEval_InitThreads_t, PyEval_InitThreads_ptr); /* deprecated in 3.9 */
  BIND_SYMBOL_WEAK("PyEval_ReleaseThread", PyEval_ReleaseThread_t, PyEval_ReleaseThread_ptr);
  BIND_SYMBOL_WEAK("PyEval_SetTrace", PyEval_SetTrace_t, PyEval_SetTrace_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("PyEval_ThreadsInitialized", PyEval_ThreadsInitialized_t, PyEval_ThreadsInitialized_ptr); /* deprecated in 3.9 */
  BIND_SYMBOL_WEAK("PyFloat_AsDouble", PyFloat_AsDouble_t, PyFloat_AsDouble_ptr);
  BIND_SYMBOL_WEAK("PyFloat_FromDouble", PyFloat_FromDouble_t, PyFloat_FromDouble_ptr);
  BIND_SYMBOL_WEAK("PyFunction_GetCode", PyFunction_GetCode_t, PyFunction_GetCode_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("PyFunction_New", PyFunction_New_t, PyFunction_New_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("PyGILState_Ensure", PyGILState_Ensure_t, PyGILState_Ensure_ptr);
  BIND_SYMBOL_WEAK("PyGILState_GetThisThreadState", PyGILState_GetThisThreadState_t, PyGILState_GetThisThreadState_ptr);
  BIND_SYMBOL_WEAK("PyGILState_Release", PyGILState_Release_t, PyGILState_Release_ptr);
  BIND_SYMBOL_WEAK("PyImport_AddModule", PyImport_AddModule_t, PyImport_AddModule_ptr);
  BIND_SYMBOL_WEAK("PyImport_ImportModule", PyImport_ImportModule_t, PyImport_ImportModule_ptr);
  BIND_SYMBOL_WEAK("PyList_Append", PyList_Append_t, PyList_Append_ptr);
  BIND_SYMBOL_WEAK("PyList_GetItem", PyList_GetItem_t, PyList_GetItem_ptr);
  BIND_SYMBOL_WEAK("PyList_Insert", PyList_Insert_t, PyList_Insert_ptr);
  BIND_SYMBOL_WEAK("PyList_New", PyList_New_t, PyList_New_ptr);
  BIND_SYMBOL_WEAK("PyList_SetItem", PyList_SetItem_t, PyList_SetItem_ptr);
  BIND_SYMBOL_WEAK("PyList_Size", PyList_Size_t, PyList_Size_ptr);
  BIND_SYMBOL_WEAK("PyLong_AsLong", PyLong_AsLong_t, PyLong_AsLong_ptr);
  BIND_SYMBOL_WEAK("PyLong_AsLongLong", PyLong_AsLongLong_t, PyLong_AsLongLong_ptr);
  BIND_SYMBOL_WEAK("PyLong_AsUnsignedLong", PyLong_AsUnsignedLong_t, PyLong_AsUnsignedLong_ptr);
  BIND_SYMBOL_WEAK("PyLong_AsUnsignedLongLong", PyLong_AsUnsignedLongLong_t, PyLong_AsUnsignedLongLong_ptr);
  BIND_SYMBOL_WEAK("PyLong_FromLong", PyLong_FromLong_t, PyLong_FromLong_ptr);
  BIND_SYMBOL_WEAK("PyLong_FromLongLong", PyLong_FromLongLong_t, PyLong_FromLongLong_ptr);
  BIND_SYMBOL_WEAK("PyLong_FromSize_t", PyLong_FromSize_t_t, PyLong_FromSize_t_ptr);
  BIND_SYMBOL_WEAK("PyLong_FromSsize_t", PyLong_FromSsize_t_t, PyLong_FromSsize_t_ptr);
  BIND_SYMBOL_WEAK("PyLong_FromUnsignedLongLong", PyLong_FromUnsignedLongLong_t, PyLong_FromUnsignedLongLong_ptr);
  BIND_SYMBOL_WEAK("PyModule_GetDict", PyModule_GetDict_t, PyModule_GetDict_ptr);
  BIND_SYMBOL_WEAK("PyNumber_And", PyNumber_And_t, PyNumber_And_ptr);
  BIND_SYMBOL_WEAK("PyNumber_Check", PyNumber_Check_t, PyNumber_Check_ptr);
  BIND_SYMBOL_WEAK("PyObject_CallFunction", PyObject_CallFunction_t, PyObject_CallFunction_ptr);
  BIND_SYMBOL_WEAK("PyObject_CallFunctionObjArgs", PyObject_CallFunctionObjArgs_t, PyObject_CallFunctionObjArgs_ptr);
  BIND_SYMBOL_WEAK("PyObject_CallMethod", PyObject_CallMethod_t, PyObject_CallMethod_ptr);
  BIND_SYMBOL_WEAK("PyObject_CallObject", PyObject_CallObject_t, PyObject_CallObject_ptr);
  BIND_SYMBOL_WEAK("PyObject_Dir", PyObject_Dir_t, PyObject_Dir_ptr);
  BIND_SYMBOL_WEAK("PyObject_GetAttrString", PyObject_GetAttrString_t, PyObject_GetAttrString_ptr);
  BIND_SYMBOL_WEAK("PyObject_HasAttrString", PyObject_HasAttrString_t, PyObject_HasAttrString_ptr);
  BIND_SYMBOL_WEAK("PyObject_IsInstance", PyObject_IsInstance_t, PyObject_IsInstance_ptr);
  BIND_SYMBOL_WEAK("PyObject_Repr", PyObject_Repr_t, PyObject_Repr_ptr);
  BIND_SYMBOL_WEAK("PyObject_RichCompareBool", PyObject_RichCompareBool_t, PyObject_RichCompareBool_ptr);
  BIND_SYMBOL_WEAK("PyObject_SetAttrString", PyObject_SetAttrString_t, PyObject_SetAttrString_ptr);
  BIND_SYMBOL_WEAK("PyObject_Str", PyObject_Str_t, PyObject_Str_ptr);
  BIND_SYMBOL_WEAK("PyRun_SimpleStringFlags", PyRun_SimpleStringFlags_t, PyRun_SimpleStringFlags_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("PyRun_StringFlags", PyRun_StringFlags_t, PyRun_StringFlags_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("PySequence_Check", PySequence_Check_t, PySequence_Check_ptr);
  BIND_SYMBOL_WEAK("PySequence_GetItem", PySequence_GetItem_t, PySequence_GetItem_ptr);
  BIND_SYMBOL_WEAK("PySequence_Length", PySequence_Length_t, PySequence_Length_ptr);
  BIND_SYMBOL_WEAK("PySequence_Size", PySequence_Size_t, PySequence_Size_ptr);
  BIND_SYMBOL_WEAK("PySys_GetObject", PySys_GetObject_t, PySys_GetObject_ptr);
  BIND_SYMBOL_WEAK("PySys_SetObject", PySys_SetObject_t, PySys_SetObject_ptr);
  BIND_SYMBOL_WEAK("PySys_SetPath", PySys_SetPath_t, PySys_SetPath_ptr); /* deprecated in 3.11 */
  BIND_SYMBOL_WEAK("PyThreadState_Get", PyThreadState_Get_t, PyThreadState_Get_ptr);
  BIND_SYMBOL_WEAK("PyTuple_GetItem", PyTuple_GetItem_t, PyTuple_GetItem_ptr);
  BIND_SYMBOL_WEAK("PyTuple_New", PyTuple_New_t, PyTuple_New_ptr);
  BIND_SYMBOL_WEAK("PyTuple_SetItem", PyTuple_SetItem_t, PyTuple_SetItem_ptr);
  BIND_SYMBOL_WEAK("PyTuple_Size", PyTuple_Size_t, PyTuple_Size_ptr);
  BIND_SYMBOL_WEAK("PyType_GetFlags", PyType_GetFlags_t, PyType_GetFlags_ptr);
  BIND_SYMBOL_WEAK("PyType_IsSubtype", PyType_IsSubtype_t, PyType_IsSubtype_ptr);
  BIND_SYMBOL_WEAK("PyUnicode_AsUTF8String", PyUnicode_AsUTF8String_t, PyUnicode_AsUTF8String_ptr);
  BIND_SYMBOL_WEAK("PyUnicode_FromString", PyUnicode_FromString_t, PyUnicode_FromString_ptr);
  BIND_SYMBOL_WEAK("PyUnicode_FromStringAndSize", PyUnicode_FromStringAndSize_t, PyUnicode_FromStringAndSize_ptr);
  BIND_SYMBOL_WEAK("Py_BuildValue", Py_BuildValue_t, Py_BuildValue_ptr);
  BIND_SYMBOL_WEAK("Py_CompileStringExFlags", Py_CompileStringExFlags_t, Py_CompileStringExFlags_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("Py_DecRef", Py_DecRef_t, Py_DecRef_ptr);
  BIND_SYMBOL_WEAK("Py_Finalize", Py_Finalize_t, Py_Finalize_ptr);
  BIND_SYMBOL_WEAK("Py_GetVersion", Py_GetVersion_t, Py_GetVersion_ptr);
  BIND_SYMBOL_WEAK("Py_IncRef", Py_IncRef_t, Py_IncRef_ptr);
  BIND_SYMBOL_WEAK("Py_InitializeEx", Py_InitializeEx_t, Py_InitializeEx_ptr);
  BIND_SYMBOL_WEAK("Py_IsInitialized", Py_IsInitialized_t, Py_IsInitialized_ptr);
  BIND_SYMBOL_WEAK("_PyLong_AsByteArray", _PyLong_AsByteArray_t, _PyLong_AsByteArray_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("_PyLong_FromByteArray", _PyLong_FromByteArray_t, _PyLong_FromByteArray_ptr); /* not in limited API */
  BIND_SYMBOL_WEAK("_Py_Dealloc", _Py_Dealloc_t, _Py_Dealloc_ptr);
  BIND_SYMBOL_WEAK("PyBool_Type", PyBool_Type_t, PyBool_Type_ptr);
  BIND_SYMBOL_WEAK("PyExc_KeyboardInterrupt", PyExc_KeyboardInterrupt_t, PyExc_KeyboardInterrupt_ptr);
  BIND_SYMBOL_WEAK("PyExc_NotImplementedError", PyExc_NotImplementedError_t, PyExc_NotImplementedError_ptr);
  BIND_SYMBOL_WEAK("PyExc_TypeError", PyExc_TypeError_t, PyExc_TypeError_ptr);
  BIND_SYMBOL_WEAK("PyExc_ValueError", PyExc_ValueError_t, PyExc_ValueError_ptr);
  BIND_SYMBOL_WEAK("PyFloat_Type", PyFloat_Type_t, PyFloat_Type_ptr);
  BIND_SYMBOL_WEAK("PyList_Type", PyList_Type_t, PyList_Type_ptr);
  BIND_SYMBOL_WEAK("PyLong_Type", PyLong_Type_t, PyLong_Type_ptr);
  BIND_SYMBOL_WEAK("Py_NoSiteFlag", Py_NoSiteFlag_t, Py_NoSiteFlag_ptr); /* not in limited API, deprecated in 3.12 */
  BIND_SYMBOL_WEAK("_Py_FalseStruct", _Py_FalseStruct_t, _Py_FalseStruct_ptr);
  BIND_SYMBOL_WEAK("_Py_NoneStruct", _Py_NoneStruct_t, _Py_NoneStruct_ptr);
  BIND_SYMBOL_WEAK("_Py_TrueStruct", _Py_TrueStruct_t, _Py_TrueStruct_ptr);
// AUTO GENERATED EXTAPI END BINDALL -----------------------------------------
#undef BIND_SYMBOL

  return true;
}

//-------------------------------------------------------------------------
void ext_api_t::clear()
{
  if ( lib_handle != nullptr )
  {
#ifndef __NT__
    if ( lib_handle )
      dlclose(lib_handle);
#else
    if ( lib_handle )
      FreeLibrary((HMODULE)lib_handle);
    if ( !prev_dll_directory.empty() )
      SetDllDirectoryW(prev_dll_directory.c_str());
#endif
    lib_handle = nullptr;
    lib_path = "";
  }
}
