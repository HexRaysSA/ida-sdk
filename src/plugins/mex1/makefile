# Merge example number
CFLAGS += -DMEX_N=1
PROC=mex1
O1=merge

include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)merge$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)merge.hpp $(I)mergemod.hpp              \
                  $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h $(I)range.hpp      \
                  $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp merge.cpp         \
                  mex.hpp
$(F)mex1$(O)    : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h   \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  mex.hpp mex1.cpp mex_impl.cpp
