PROC=callgraph
O1=merge

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)callgraph$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp            \
                  $(I)cvt64.hpp $(I)demangle.hpp $(I)diff3.hpp $(I)fpro.h   \
                  $(I)funcs.hpp $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp       \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp callgraph.cpp callgraph.h
$(F)merge$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)demangle.hpp $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp   \
                  $(I)gdl.hpp $(I)graph.hpp $(I)ida.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)merge.hpp $(I)mergemod.hpp             \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)pro.h       \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  callgraph.h merge.cpp
