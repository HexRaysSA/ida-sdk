#ifndef __PYWRAPS__LINES__
#define __PYWRAPS__LINES__

//------------------------------------------------------------------------

//<inline(py_lines)>

//-------------------------------------------------------------------------
PyObject *py_tag_remove(const char *str)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring qbuf;
  tag_remove(&qbuf, str);
  return PyUnicode_FromString(qbuf.c_str());
}

//-------------------------------------------------------------------------
PyObject *py_tag_addr(ea_t ea)
{
  qstring tag;
  tag_addr(&tag, ea);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyUnicode_FromString(tag.begin());
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
/*
#<pydoc>
def generate_disassembly(ea, max_lines, as_stack, notags):
    """
    Generate disassembly lines (many lines) and put them into a buffer

    @param ea: address to generate disassembly for
    @param max_lines: how many lines max to generate
    @param as_stack: Display undefined items as 2/4/8 bytes
    @return:
        - None on failure
        - tuple(most_important_line_number, list(lines)) : Returns a tuple containing
          the most important line number and a list of generated lines
    """
    pass
#</pydoc>
*/
PyObject *py_generate_disassembly(
        ea_t ea,
        int max_lines,
        bool as_stack,
        bool notags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( max_lines <= 0 )
    Py_RETURN_NONE;

  qstring qbuf;
  qstrvec_t lines;
  int lnnum;
  int nlines = generate_disassembly(&lines, &lnnum, ea, max_lines, as_stack);

  newref_t py_list(PyList_New(nlines));
  for ( int i=0; i < nlines; i++ )
  {
    const qstring &l = lines[i];
    const char *s = l.c_str();
    if ( notags )
    {
      tag_remove(&qbuf, l);
      s = qbuf.c_str();
    }
    PyList_SetItem(py_list.o, i, PyUnicode_FromString(s));
  }
  return Py_BuildValue("(iO)", lnnum, py_list.o);
}
//</inline(py_lines)>
#endif
