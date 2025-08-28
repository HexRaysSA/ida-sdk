
%{
#include <indexer.hpp>
%}

%ignore init_indexer;
%ignore term_indexer;
%ignore indexer_register_subindex;
%ignore indexer_unregister_subindex;
%ignore indexer_get_subindex;

%include "indexer.hpp"

%template(search_result_vec_t) qvector<search_result_t*>;
