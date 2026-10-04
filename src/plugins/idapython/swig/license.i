%{
#include <license.hpp>
%}

%typemap(out) qstrvec_t
{
  $result = qstrvec2pylist($1);
}

// python uses the C++ view of license.hpp, not the exported entry points
%ignore get_valid_add_ons_buf;
%ignore get_valid_features_buf;
%ignore get_license_id_buf;
%ignore get_license_ids_buf;
%ignore unpack_str_list;

%include "license_seam.hpp"
%include "license.hpp"

%extend License
{
  %pythoncode %{
    valid = property(valid)
    add_ons = property(add_ons)
    features = property(features)
    id = property(id)
    source_ids = property(source_ids)
    decompiler_available = property(decompiler_available)
    product = property(product)
    edition = property(edition)
    description = property(description)
    product_version = property(product_version)
    start = property(start)
    end = property(end)
    issued_on = property(issued_on)
    floating = property(floating)
  %}
}
