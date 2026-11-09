PROC=uunp
O1=resext
O2=win9x
O3=merge

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)merge$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h   \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  merge.cpp uunp.hpp
$(F)resext$(O)  : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ieee.h          \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
                  $(I)prodir.h $(I)range.hpp $(I)segment.hpp $(I)ua.hpp     \
                  $(I)xref.hpp resext.cpp uunp.hpp
$(F)uunp$(O)    : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)dbg.hpp $(I)diff3.hpp $(I)entry.hpp    \
                  $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp          \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h $(I)range.hpp    \
                  $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp uunp.cpp          \
                  uunp.hpp
$(F)win9x$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)dbg.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp          \
                  $(I)idd.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp uunp.hpp win9x.cpp
