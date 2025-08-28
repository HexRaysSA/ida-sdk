ifeq (,$(wildcard ../../../allmake.mak))
    include ../../allmake.mak
else
    include ../../../allmake.mak
endif

#.PHONY: configs help html bins testreg
#all: configs help html bins # testreg

#----------------------------------------------------------------------
BINS += $(R)idacli$(B)
bins: $(BINS)

ifdef __LINUX__
  LDFLAGS += -Wl,-rpath='$$ORIGIN'
endif

ifdef __MAC__
  LDFLAGS += -Wl,-rpath,@executable_path/
endif

ifdef __NT__
  # reserve 4MB of stack on windows. the default 1MB stack is too small in some cases.
  LDFLAGS += /STACK:0x400000
  LDFLAGS += /MANIFEST
  CC_DEFS += NOMINMAX
  CC_DEFS += _CRT_SECURE_NO_WARNINGS
  CC_DEFS += UNICODE
  CC_DEFS += _UNICODE
endif

OBJS += $(F)idacli$(O)
$(R)idacli$(B): $(OBJS) $(IDALIBRARY) $(IDALIB)
	$(call link_exe, $(OBJS), $(LINKIDA) $(LINKIDALIBRARY))

$(F)idacli$(O): CC_INCP-$(__LINUX__) += $(BREAKPAD_INCLUDES)

include $(IDA)objdir.mak

# MAKEDEP dependency list ------------------
$(F)idacli$(O)  : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)dirtree.hpp $(I)diskio.hpp             \
                  $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
                  $(I)idalib.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp     \
                  $(I)lex.hpp $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp    \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp                 \
                  $(I)parsejson.hpp $(I)pro.h $(I)prodir.h $(I)range.hpp    \
                  $(I)segment.hpp $(I)ua.hpp $(I)undo.hpp $(I)xref.hpp      \
                  idacli.cpp
