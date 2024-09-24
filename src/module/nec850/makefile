PROC=nec850
O1=regfinder
O2=merge

include ../module.mak

# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp     \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)ieee.h            \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)merge.hpp $(I)mergemod.hpp             \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp  \
                  $(I)pro.h $(I)problems.hpp $(I)range.hpp                  \
                  $(I)regfinder.hpp $(I)segment.hpp $(I)ua.hpp              \
                  $(I)xref.hpp ../idaidp.hpp ana.cpp ins.hpp necv850.hpp
$(F)emu$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)fpro.h $(I)frame.hpp     \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)jumptable.hpp $(I)kernwin.hpp              \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp  \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)regfinder.hpp          \
                  $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp     \
                  emu.cpp ins.hpp necv850.hpp
$(F)ins$(O)     : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ieee.h          \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp ins.cpp ins.hpp
$(F)merge$(O)   : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp     \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)ieee.h            \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)merge.hpp $(I)mergemod.hpp             \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp  \
                  $(I)pro.h $(I)problems.hpp $(I)range.hpp                  \
                  $(I)regfinder.hpp $(I)segment.hpp $(I)ua.hpp              \
                  $(I)xref.hpp ../idaidp.hpp ../mergecmn.cpp ins.hpp        \
                  merge.cpp necv850.hpp
$(F)out$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)fpro.h $(I)funcs.hpp     \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)ieee.h            \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)merge.hpp $(I)mergemod.hpp             \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp  \
                  $(I)pro.h $(I)problems.hpp $(I)range.hpp                  \
                  $(I)regfinder.hpp $(I)segment.hpp $(I)ua.hpp              \
                  $(I)xref.hpp ../idaidp.hpp ins.hpp necv850.hpp out.cpp
$(F)reg$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)cvt64.hpp $(I)diff3.hpp $(I)fpro.h     \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)merge.hpp $(I)mergemod.hpp             \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp  \
                  $(I)pro.h $(I)problems.hpp $(I)range.hpp                  \
                  $(I)regfinder.hpp $(I)segment.hpp $(I)segregs.hpp         \
                  $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ins.hpp             \
                  necv850.hpp reg.cpp
$(F)regfinder$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp              \
                  $(I)config.hpp $(I)diff3.hpp $(I)fpro.h $(I)frame.hpp     \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)merge.hpp $(I)mergemod.hpp             \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp  \
                  $(I)pro.h $(I)problems.hpp $(I)range.hpp                  \
                  $(I)regfinder.hpp $(I)segment.hpp $(I)ua.hpp              \
                  $(I)xref.hpp ../idaidp.hpp ins.hpp necv850.hpp            \
                  regfinder.cpp
