
ifneq ($(wildcard ../../parse),)
  CC_DEFS += ENABLE_LOWCNDS
endif
CC_INCP += ..

include ../../plugins/plugin.mak

PLUGIN_LIBS += $(L)dbg_plugin$(A)
PLUGIN_LIBS += $(L)dbg_rpc$(A)
PLUGIN_LIBS += $(L)dbg_proc$(A)
PLUGIN_LIBS += $(L)network$(A)
$(MODULES): LIBS += $(PLUGIN_LIBS)
$(MODULES): $(PLUGIN_LIBS)

ifeq ($(or $(__LINUX__),$(__MAC__)),1)
  $(MODULES): STDLIBS += -ldl
endif
