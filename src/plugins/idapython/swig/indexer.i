%include "std_string_view.i"

%{
#include <indexer.hpp>
%}

// Python owns the returned search_result_data_t* and will call delete on it.
%newobject indexer_match_all;
%newobject indexer_match;

// Warning 473: Returning a reference, pointer or pointer wrapper in a director method is not recommended.
%warnfilter(473) search_result_data_t::get_name;

%ignore search_result_data_t::get_name_str;

%include <indexer.hpp>
