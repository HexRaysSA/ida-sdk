%{
#include <frame.hpp>
%}

%ignore add_frame_spec_member;
%ignore del_stkvars;
%ignore set_llabel;
%ignore get_llabel_ea;
%ignore get_llabel;

%ignore add_stkvar;

%ignore delete_wrong_frame_info;
%ignore get_func_frame(tinfo_t *tif, ea_t ea);

%template(stkpnts_template_t) qvector<stkpnt_t>;
%template(xreflist_t) qvector<xreflist_entry_t>;
%template(regvars_t) qvector<regvar_t>;
%template(llabels_t) qvector<llabel_t>;

//<typemaps(frame)>
//</typemaps(frame)>

%inline %{
//<inline(py_frame)>
//</inline(py_frame)>
%}

%include "frame.hpp"

%pythoncode %{
#<pycode(py_frame)>
#</pycode(py_frame)>
%}
