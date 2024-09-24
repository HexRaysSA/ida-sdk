#ifndef MAKE_NS_SCRIPT_H
#define MAKE_NS_SCRIPT_H

#include <pro.h>

//--------------------------------------------------------------------------
idaman void ida_export plugin_name_from_path_or_name(
        qstring *out_plg_name,
        const char *path);

//--------------------------------------------------------------------------
idaman void ida_export make_script_ns(
        qstring *out,
        const char *module_type,
        const char *name);

#endif /* MAKE_NS_SCRIPT_H */
