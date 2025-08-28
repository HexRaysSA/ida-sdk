include ../allmake.mak

# the following platforms only build the servers, and not the plugins.
ifneq ($(or $(__ANDROID__),$(__ANDROID_X86__),$(__ARMLINUX__),$(USE_STATIC_RUNTIME)),1)
  DBG_PLUGIN = $(L)dbg_plugin$(A)
  CONFIGS += exceptions.cfg
endif

BASE_LIBS += $(L)dbg_rpc$(A)
BASE_LIBS += $(L)dbg_server$(A)
BASE_LIBS += $(DBG_PLUGIN)
BASE_LIBS += $(L)dbg_proc$(A)
GOALS += $(addprefix $(C),$(CONFIGS))

ALLDIRS += linux
# ALLDIRS += mac
ALLDIRS += win32

# default target
all: $(ALLDIRS) $(GOALS)

# dependencies
$(ALLDIRS): $(BASE_LIBS)

# recipes for subdirs
.PHONY: $(ALLDIRS)
$(sort $(ALLDIRS)):
	$(Q)$(MAKE) -C $@

clean::
	$(foreach dir,$(ALLDIRS),$(MAKE) -C $(dir) clean;)

#----------------------------------------------------------------------
RPC_OBJS += $(F)dbg_rpc_engine$(O)
RPC_OBJS += $(F)dbg_rpc_hlp$(O)
$(L)dbg_rpc$(A): $(call lib, $(RPC_OBJS))
$(RPC_OBJS): CLPDB = /Zi /FS /Fd$(L)dbg_rpc.pdb

#----------------------------------------------------------------------
SERVER_OBJS += $(F)bin_search$(O)
SERVER_OBJS += $(F)dbg_rpc_handler$(O)
SERVER_OBJS += $(F)debmod$(O)
SERVER_OBJS += $(F)server$(O)
$(L)dbg_server$(A): $(call lib, $(SERVER_OBJS))

#----------------------------------------------------------------------
PLUGIN_OBJS += $(F)bin_search$(O)
PLUGIN_OBJS += $(F)dbg_rpc_client$(O)
PLUGIN_OBJS += $(F)debmod$(O)
PLUGIN_OBJS += $(F)rpc_debmod$(O)
$(L)dbg_plugin$(A): $(call lib, $(PLUGIN_OBJS))

#----------------------------------------------------------------------
PROC_OBJS += $(F)arm_debmod$(O)
PROC_OBJS += $(F)arm_regs$(O)
PROC_OBJS += $(F)pc_debmod$(O)
PROC_OBJS += $(F)pc_regs$(O)
$(L)dbg_proc$(A): $(call lib, $(PROC_OBJS))

include $(IDA)objdir.mak

