PROC=qwindow
O1=moc_myactions

include ../qtplugin.mak

# MAKEDEP dependency list ------------------
$(F)moc_myactions$(O): $(F)moc_myactions.cpp myactions.h
$(F)qwindow$(O) : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ieee.h          \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  qwindow.cpp
