PROC=hello

include ../plugin.mak

all: scripts

SCRIPTS := $(addprefix $(BIN_PATH),idchello.idc pyhello.py)

.PHONY: scripts
scripts: $(SCRIPTS)

$(BIN_PATH)%.idc: %.idc
	$(CP) $? $@
$(BIN_PATH)%.py: %.py
	$(CP) $? $@

uninstall::
	rm -rf $(SCRIPTS)

# MAKEDEP dependency list ------------------
$(F)hello$(O)   : $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp $(I)fpro.h  \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)ieee.h          \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  hello.cpp
