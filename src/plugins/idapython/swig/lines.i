// FIXME: These should be fixed
%ignore requires_color_esc;
// Ignore va_list versions
%ignore vadd_extra_line;
// Kernel-only and unexported symbols
%ignore get_last_pfxlen;
%ignore closing_comment;
%ignore close_comment;
%ignore init_lines;
%ignore save_lines;
%ignore align_down_to_stack;
%ignore align_up_to_stack;
%ignore encoder_t;
%ignore file_producer_t;

%feature("pythonappend") user_defined_prefix_t::user_defined_prefix_t %{
self.thisown = False
%}
%feature("pythonappend") install_user_defined_prefix %{
if val:
    pfx, instance, *rest = args
    if pfx == 0:
        instance.thisown = True
    else:
        instance.thisown = False
%}

%typemap(default) const void *owner {
  $1 = nullptr;
}

%ignore generate_disassembly;
%rename (generate_disassembly) py_generate_disassembly;

%ignore tag_remove;
%rename (tag_remove) py_tag_remove;

%ignore tag_addr;
%rename (tag_addr) py_tag_addr;

%ignore tag_skipcodes;
%rename (tag_skipcodes) py_tag_skipcodes;

%ignore tag_skipcode;
%rename (tag_skipcode) py_tag_skipcode;

%ignore tag_advance;
%rename (tag_advance) py_tag_advance;

// tag_semspan()/tag_semspan_off() append to a qstring out-param and return
// void, which SWIG cannot auto-wrap (like tag_addr above); expose py_ variants
// that return the bytes instead.
%ignore tag_semspan;
%rename (tag_semspan) py_tag_semspan;
%ignore tag_semspan_off;
%rename (tag_semspan_off) py_tag_semspan_off;

%typemap(argout) (qstring *buf, ea_t ea, int what)
{
  // typemap(argout) (qstring *buf, ea_t ea, int what)
  Py_XDECREF(resultobj);
  if (result >= 0)
  {
    resultobj = PyUnicode_FromStringAndSize((const char *) $1->c_str(), $1->length());
  }
  else
  {
    Py_INCREF(Py_None);
    resultobj = Py_None;
  }
}

//<typemaps(lines)>
//</typemaps(lines)>

%template(sourcefilevec_t) qvector<sourcefile_t>;

// The streaming listing-line generator. A script never creates one: it receives
// a BORROWED instance (e.g. an HTML-export template's run() argument, wrapped by
// listing_lines_t__from_ptrval__) and must not delete it. Hide the ABI-only size
// stamp; it has virtuals but must NOT be a director -- Python consumes it, never
// subclasses it.
%{
#include <kernwin.hpp>   // place_t & friends, referenced by the wrapped API
%}

%ignore listing_line_t::cb;
%feature("nodirector") listing_lines_t;
// Scripts never construct a generator (it is engine-built and borrowed), and
// its stream state is read-only from Python.
%nodefaultctor listing_lines_t;
%immutable listing_lines_t::flags;
%immutable listing_lines_t::title;
%immutable listing_lines_t::cancelled;
// A listing line's navigational endpoints.
%template(link_anchors_t) qvector<link_anchor_t>;

// The export config: scope with the add_* builder methods (they ACCUMULATE;
// clear_ranges() starts over). The borrowed origin context is read-only (the
// place) or hidden; the raw dispatcher and its codes are implementation details.
%ignore export_listing_t::cb;
%ignore export_listing_t::current_ud;
%ignore export_listing_t::current_disp;
%ignore export_listing_reserved_holder_t;
%ignore export_listing_t::reserved;
%immutable export_listing_t::current_place;
%ignore export_listing_ctl;
%ignore export_listing_ctl_code_t;

// create_lines() returns an OWNED generator: Python deletes it.
%newobject export_listing_t::create_lines;
%apply int *OUTPUT { int *out_lines };
// out_lines is an OUTPUT argument, so it does not appear in the Python
// signature: without compactdefaultargs the overload generated for the
// out_lines=nullptr default would be indistinguishable from the full one,
// and SWIG would drop it.
%feature("compactdefaultargs") export_listing_to_file;
// export_listing_to_file explains a failure in `errbuf`; surface it as a
// RuntimeError rather than losing the text to the out-string convention
// (which returns None on failure).
%make_argout_errbuf_raise_exception_when_non_empty(errbuf);

%include "lines.hpp"

%extend export_listing_t
{
  /// Drop every accumulated range: the next add_* call starts a new scope.
  void clear_ranges()
  {
    $self->ranges.qclear();
  }

  %pythoncode {
    def add_decompilation(self, cfunc):
        r"""Append a decompilation: a snapshot of `cfunc`'s pseudocode, taken
        now (add_pseudocode copies the lines into the config) -- the export
        depends neither on the cfunc staying alive nor on its text staying
        unchanged (the decompiler cache may drop or regenerate it at any
        time). Returns False if the decompiler is not available."""
        return self.add_pseudocode(cfunc.get_pseudocode(), cfunc.entry_ea)
  }
}

// The palette's per-tag tables, as fixed-size indexable arrays.
%template (listing_palette_entries_array) wrapped_array_t<listing_palette_entry_t,COLOR_FG_MAX>;
%extend listing_palette_t
{
  wrapped_array_t<listing_palette_entry_t,COLOR_FG_MAX> __get_fg__()
  {
    return wrapped_array_t<listing_palette_entry_t,COLOR_FG_MAX>($self->fg);
  }
  wrapped_array_t<listing_palette_entry_t,COLOR_FG_MAX> __get_pfx__()
  {
    return wrapped_array_t<listing_palette_entry_t,COLOR_FG_MAX>($self->pfx);
  }
  %pythoncode {
    fg = property(__get_fg__)
    pfx = property(__get_pfx__)
  }
}

%pywraps_nonnul_argument_prototype(
        qstring py_tag_remove(const char *nonnul_instr),
        const char *nonnul_instr);

%inline %{
//<inline(py_lines)>
//</inline(py_lines)>
%}

%pythoncode %{
#<pycode(py_lines)>
#</pycode(py_lines)>
%}
