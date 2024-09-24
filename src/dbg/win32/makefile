include ../../allmake.mak

GOALS-$(BUILD_IDA) += modules # target in $(IDA)module.mak
GOALS-$(BUILD_DBGSRV) += server # target in $(IDA)dbg/server.mak
.PHONY: $(GOALS-1)
all: $(GOALS-1)

#----------------------------------------------------------------------
ifdef __NT__
  ifndef __X86__
    SERVER = win64_remote$(B)
  else
    SERVER = win32_remote$(B)
  endif
endif
ifdef SERVER
  SERVERS += $(call server_exe,$(SERVER))
endif

#----------------------------------------------------------------------
STUB = $(call module_dll,win32_stub)
ifdef BUILD_IDA
  ifeq ($(or $(IDAHOME),$(DEMO_OR_FREE)),)
    MODULES += $(STUB)
  endif
endif

#----------------------------------------------------------------------
USER = $(call module_dll,win32_user)
ifeq ($(and $(BUILD_IDA),$(__NT__)),1)
  MODULES += $(USER)
endif

#----------------------------------------------------------------------
# we explicitly added our module targets
NO_DEFAULT_TARGETS = 1

# NOTE: all MODULES must be defined before including plugin.mak.
include ../plugin.mak
# NOTE: target-specific rules and dependencies that use variable
#       expansion to name the target (such as "$(MODULE): [...]") must
#       come after including plugin.mak

#----------------------------------------------------------------------
# select OBJS common to user plugin and debugger server
BASE_OBJS-$(__NT__) += $(F)win32_debmod$(O)
BASE_OBJS-$(__NT__) += $(F)win32_util$(O)
BASE_OBJS-$(__NT__) += $(F)winbase_debmod$(O)
BASE_OBJS += $(BASE_OBJS-1)

#----------------------------------------------------------------------
SERVER_OBJS += $(F)win32_server$(O)
SERVER_OBJS += $(F)tilfuncs$(O)
SERVER_OBJS += $(BASE_OBJS)

SERVER_STDLIBS += ole32.lib
SERVER_STDLIBS += oleaut32.lib

include ../server.mak

#----------------------------------------------------------------------
STUB_OBJS += $(F)win32_stub$(O)
STUB_OBJS += $(F)w32sehch$(O)
$(STUB): MODULE_OBJS += $(STUB_OBJS)
$(STUB): $(STUB_OBJS)

#----------------------------------------------------------------------
USER_OBJS += $(F)win32_user$(O)
USER_OBJS += $(F)w32sehch$(O)
USER_OBJS += $(BASE_OBJS)
$(USER): MODULE_OBJS += $(USER_OBJS)
$(USER): $(USER_OBJS)
$(USER): STDLIBS += user32.lib

#----------------------------------------------------------------------
include $(IDA)objdir.mak

