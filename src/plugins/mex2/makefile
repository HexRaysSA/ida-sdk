# Merge example number
CFLAGS += -DMEX_N=2
PROC=mex2
O1=merge

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)merge$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)merge.hpp $(I)mergemod.hpp              \
                  $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h $(I)range.hpp      \
                  $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp ../mex1/mex.hpp   \
                  merge.cpp
$(F)mex2$(O)    : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h   \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  ../mex1/mex.hpp ../mex1/mex_impl.cpp mex2.cpp
