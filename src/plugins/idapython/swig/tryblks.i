%{
#include <tryblks.hpp>
%}

%ignore tryblk_t::reserve;
%ignore tryblk_t::cpp() const;
%ignore tryblk_t::seh() const;

%constant ea_t SEH_CONTINUE = ea_t(0-1);
%constant ea_t SEH_SEARCH   = ea_t(0);
%constant ea_t SEH_HANDLE   = ea_t(1);

%template(tryblks_t) qvector<tryblk_t>;
%template(catchvec_t) qvector<catch_t>;

%include "tryblks.hpp"
