%{
#include <undo.hpp>
%}  

%include "typemaps.i"  

// Typemap to convert Python bytes to `const unsigned char*` and `size_t` for create_undo_point
%typemap(in) (const unsigned char *bytes, size_t size) {
    Py_ssize_t length;
    const char *temp;
    if (PyBytes_Check($input)) {
        if (PyBytes_AsStringAndSize($input, (char**)&temp, &length) == -1) {
            SWIG_fail;
        }
    } else {
        SWIG_exception_fail(SWIG_TypeError, "Expected a bytes object");
    }

    $1 = (const unsigned char *)temp;  // Cast to const unsigned char* from const char*
    $2 = (size_t)length;
}

%inline %{
    bool create_undo_point(PyObject *input_bytes) {
        const unsigned char *bytes;
        size_t size;
        if (!PyBytes_Check(input_bytes)) {
            PyErr_SetString(PyExc_TypeError, "Expected a bytes object");
            return false;
        }
        // Perform the conversion from python bytes to unsigned char *
        bytes = (const unsigned char *)PyBytes_AsString(input_bytes);
        size = (size_t)PyBytes_Size(input_bytes);

        // Call the original C++ function
        return ::create_undo_point(bytes, size);
    }
%}

%include "undo.hpp"
