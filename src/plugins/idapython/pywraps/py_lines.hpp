#ifndef __PYWRAPS__LINES__
#define __PYWRAPS__LINES__

//------------------------------------------------------------------------

//<inline(py_lines)>

//-------------------------------------------------------------------------
qstring py_tag_remove(const char *str)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring qbuf;
  tag_remove(&qbuf, str);
  return qbuf;
}

//-------------------------------------------------------------------------
qstring py_tag_addr(ea_t ea)
{
  qstring tag;
  tag_addr(&tag, ea);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return tag;
}

//-------------------------------------------------------------------------
qstring py_tag_semspan(color_t kind=COLOR_DEFAULT)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring tag;
  tag_semspan(&tag, kind);
  return tag;
}

//-------------------------------------------------------------------------
qstring py_tag_semspan_off()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring tag;
  tag_semspan_off(&tag);
  return tag;
}

//-------------------------------------------------------------------------
int py_tag_skipcode(const char *line)
{
  return tag_skipcode(line)-line;
}

//-------------------------------------------------------------------------
int py_tag_skipcodes(const char *line)
{
  return tag_skipcodes(line)-line;
}

//-------------------------------------------------------------------------
int py_tag_advance(const char *line, int cnt)
{
  return tag_advance(line, cnt)-line;
}

//-------------------------------------------------------------------------
PyObject *py_generate_disassembly(
        ea_t ea,
        int max_lines,
        bool as_stack,
        bool notag,
        bool include_hidden)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( max_lines <= 0 )
    Py_RETURN_NONE;

  qstring qbuf;
  qstrvec_t lines;
  int lnnum;
  int gdismf_flags = (as_stack ? GDISMF_AS_STACK : 0)
                   | (notag ? GDISMF_REMOVE_TAGS : 0)
                   | (include_hidden ? GDISMF_UNHIDE : 0);
  int nlines = generate_disassembly(&lines, &lnnum, ea, max_lines, gdismf_flags);

  newref_t py_list(PyList_New(nlines));
  for ( int i=0; i < nlines; i++ )
    PyList_SetItem(py_list.o, i, PyUnicode_FromString(lines[i].c_str()));
  return Py_BuildValue("(iO)", lnnum, py_list.o);
}

//-------------------------------------------------------------------------
// Wrap a borrowed listing_lines_t* (built by the UI, e.g. handed to an HTML-
// export template's run()) as a NON-owning proxy: returning a raw pointer makes
// SWIG build it with own=0, so Python never deletes the C++-owned generator.
static listing_lines_t *listing_lines_t__from_ptrval__(size_t ptrval)
{
  return (listing_lines_t *) ptrval;
}

//-------------------------------------------------------------------------
// Wrap a borrowed export_listing_t* (built by the exporter, handed to an
// HTML-export template's run() next to the generator) as a NON-owning proxy
// (own=0).
static export_listing_t *export_listing_t__from_ptrval__(size_t ptrval)
{
  return (export_listing_t *) ptrval;
}
//</inline(py_lines)>
#endif
