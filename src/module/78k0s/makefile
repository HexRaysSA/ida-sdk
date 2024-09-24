PROC=78k0s
CONFIGS=78k0s.cfg
O1=merge

include ../module.mak

# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)diskio.hpp               \
                  $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ../iohandler.hpp    \
                  78k_0s.hpp ana.cpp ins.hpp
$(F)emu$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)diskio.hpp               \
                  $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ../iohandler.hpp    \
                  78k_0s.hpp emu.cpp ins.hpp
$(F)ins$(O)     : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ieee.h          \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp ins.cpp ins.hpp
$(F)merge$(O)   : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)diskio.hpp               \
                  $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ../iohandler.hpp    \
                  ../mergecmn.cpp 78k_0s.hpp ins.hpp merge.cpp
$(F)out$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diff3.hpp $(I)diskio.hpp               \
                  $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp                \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ../iohandler.hpp    \
                  78k_0s.hpp ins.hpp out.cpp
$(F)reg$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)cvt64.hpp $(I)diff3.hpp                \
                  $(I)diskio.hpp $(I)entry.hpp $(I)fpro.h $(I)funcs.hpp     \
                  $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)merge.hpp  \
                  $(I)mergemod.hpp $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)segregs.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp     \
                  ../iohandler.hpp 78k_0s.hpp ins.hpp reg.cpp
