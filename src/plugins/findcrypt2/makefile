PROC=findcrypt
O1=consts
O2=sparse

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)consts$(O)  : $(I)llong.hpp $(I)pro.h consts.cpp findcrypt.hpp
$(F)findcrypt$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp              \
                  $(I)config.hpp $(I)dirtree.hpp $(I)fpro.h $(I)funcs.hpp   \
                  $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)moves.hpp  \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)pro.h       \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp      \
                  $(I)xref.hpp findcrypt.cpp findcrypt.hpp
$(F)sparse$(O)  : $(I)llong.hpp $(I)pro.h findcrypt.hpp sparse.cpp
