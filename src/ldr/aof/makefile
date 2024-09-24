PROC=aof

include ../loader.mak

#----------------------------------------------------------------------
# the 'unlib' target must be called explicitly
.PHONY:
unlib: $(F)unlib$(B)
$(F)unlib$(B): $(call dumb_target, pro, $(F)unlib$(O))

# MAKEDEP dependency list ------------------
$(F)aof$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diskio.hpp $(I)entry.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp                    \
                  $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
                  $(I)range.hpp $(I)segment.hpp $(I)segregs.hpp $(I)ua.hpp  \
                  $(I)xref.hpp ../idaldr.h aof.cpp aof.h
$(F)unlib$(O)   : $(I)fpro.h $(I)llong.hpp $(I)pro.h aof.h unlib.cpp
