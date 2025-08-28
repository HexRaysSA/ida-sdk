PROC=qproject
O1=moc_graphwidget
O2=graphwidget
O3=node
O4=edge

include ../qtplugin.mak

ifdef __NT__
CFLAGS += /wd5219 # implicit conversion from 'const int' to 'float', possible loss of data
CFLAGS += /wd5249 # has named enumerators with values that cannot be represented in the given bit field width of '2'.
CFLAGS += /wd5266 # 'const' qualifier on return type has no effect
endif

# MAKEDEP dependency list ------------------
$(F)edge$(O)    : edge.cpp edge.h node.h
$(F)graphwidget$(O): edge.h graphwidget.cpp graphwidget.h node.h
$(F)moc_graphwidget$(O): $(F)moc_graphwidget.cpp graphwidget.h
$(F)node$(O)    : edge.h graphwidget.h node.cpp node.h
$(F)qproject$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp graphwidget.h qproject.cpp
