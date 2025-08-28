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
//</inline(py_lines)>
#endif
