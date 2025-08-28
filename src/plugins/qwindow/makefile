PROC=qwindow
O1=moc_myactions

include ../qtplugin.mak

ifdef __NT__
CFLAGS += /wd5219 # implicit conversion from 'const int' to 'float', possible loss of data
CFLAGS += /wd5249 # has named enumerators with values that cannot be represented in the given bit field width of '2'.
CFLAGS += /wd5266 # 'const' qualifier on return type has no effect
endif

# MAKEDEP dependency list ------------------
$(F)moc_myactions$(O): $(F)moc_myactions.cpp myactions.h
$(F)qwindow$(O) : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ieee.h          \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  qwindow.cpp
