include ../../allmake.mak

GOALS-$(BUILD_IDA) += modules # target in $(IDA)module.mak
GOALS-$(BUILD_DBGSRV) += server # target in $(IDA)dbg/server.mak
.PHONY: $(GOALS-1)
all: $(GOALS-1)

#----------------------------------------------------------------------
ifdef __LINUX__
  SERVER = linux_server$(SUFF32)
endif
ifdef SERVER
  SERVERS += $(call server_exe,$(SERVER))
endif

#----------------------------------------------------------------------
USER = $(call module_dll,linux_user)
ifeq ($(and $(BUILD_IDA),$(__LINUX__)),1)
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
ifeq ($(or $(__LINUX__),$(__ANDROID__),$(__ANDROID_X86__),$(__ARMLINUX__)),1)
  BUILD_LINUX:=1
endif

BASE_OBJS-$(BUILD_LINUX) += $(F)linuxbase_debmod$(O)
BASE_OBJS-$(BUILD_LINUX) += $(F)linux_debmod$(O)
BASE_OBJS-$(BUILD_LINUX) += $(F)linux_wait$(O)

BASE_OBJS += $(BASE_OBJS-1) $(F)symelf$(O)

#----------------------------------------------------------------------
ifdef __LINUX__
  SERVER_LDFLAGS += -Wl,--version-script=linux_debmod.script
  SERVER_LDFLAGS += $(OUTMAP)$(F)$(@F).map
  SERVER_STDLIBS += -lthread_db -lrt -lc -lpthread -ldl
endif
SERVER_OBJS += $(BASE_OBJS)

# suppress warnings for libthread_db.c
$(F)libthread_db$(O): WARNS = $(NOWARNS)

# load libthread_db.so manually on ARMLinux
$(F)linux_debmod$(O): CC_DEFS-$(__ARMLINUX__)+= MANUALLY_LOAD_THREAD_DB

# include should not refer to third party in the code
$(F)linux_debmod$(O): CC_INCP += $(LIBUNWIND)
# libunwind should be expurged from the code if necessary (see default.mk)
CC_DEFS-$(USE_LIBUNWIND) += USE_LIBUNWIND

include ../server.mak

#----------------------------------------------------------------------
STUB_OBJS += $(F)linux_stub$(O)
$(STUB): MODULE_OBJS += $(STUB_OBJS)
$(STUB): $(STUB_OBJS)

#----------------------------------------------------------------------
USER_OBJS += $(F)linux_user$(O)
USER_OBJS += $(BASE_OBJS)
$(USER): MODULE_OBJS += $(USER_OBJS)
$(USER): $(USER_OBJS)
$(USER): DEFFILE = linux_debmod.script
$(USER): STDLIBS += -ldl
$(USER): STDLIBS += -lthread_db

ifeq ($(COMPILER_NAME),gcc)
  $(USER): LDFLAGS += -Wl,--export-dynamic
endif

#----------------------------------------------------------------------
include $(IDA)objdir.mak

# MAKEDEP dependency list ------------------
$(F)armlinux_stub$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp        \
                  $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)md5.h $(I)nalt.hpp $(I)name.hpp        \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)range.hpp   \
                  $(I)segment.hpp $(I)segregs.hpp $(I)typeinf.hpp           \
                  $(I)ua.hpp $(I)xref.hpp ../arm_local_impl.cpp             \
                  ../arm_regs.cpp ../arm_regs.hpp ../common_local_impl.cpp  \
                  ../common_stub_impl.cpp ../dbg_rpc_client.h               \
                  ../dbg_rpc_engine.h ../deb_arm.hpp ../debmod.h            \
                  ../rpc_debmod.h armlinux_stub.cpp linux_local_impl.cpp
$(F)libthread_db$(O): libthread_db.c
$(F)linux_debmod$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp         \
                  $(I)diskio.hpp $(I)err.h $(I)fpro.h $(I)funcs.hpp         \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)ieee.h            \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)md5.h $(I)nalt.hpp $(I)name.hpp        \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)prodir.h    \
                  $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
                  ../../plugins/dwarf/look_for_debug_file.cpp               \
                  ../arm_debmod.h ../arm_regs.hpp ../dbg_rpc_engine.h       \
                  ../dbg_rpc_handler.h ../dbg_rpc_handler_ioctls.h          \
                  ../deb_arm.hpp ../deb_pc.hpp ../debmod.h ../pc_debmod.h   \
                  ../pc_regs.hpp android.cpp android.hpp linux_debmod.cpp   \
                  linux_debmod.h linux_rpc.h linux_threads.cpp              \
                  linuxbase_debmod.h symelf.hpp
$(F)linux_stub$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp           \
                  $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)md5.h $(I)nalt.hpp $(I)name.hpp        \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)range.hpp   \
                  $(I)segment.hpp $(I)segregs.hpp $(I)typeinf.hpp           \
                  $(I)ua.hpp $(I)xref.hpp ../common_local_impl.cpp          \
                  ../common_stub_impl.cpp ../dbg_rpc_client.h               \
                  ../dbg_rpc_engine.h ../deb_pc.hpp ../debmod.h             \
                  ../pc_local_impl.cpp ../pc_regs.hpp ../rpc_debmod.h       \
                  linux_local_impl.cpp linux_rpc.h linux_stub.cpp
$(F)linux_user$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp           \
                  $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp    \
                  $(I)loader.hpp $(I)md5.h $(I)nalt.hpp $(I)name.hpp        \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)range.hpp   \
                  $(I)segment.hpp $(I)segregs.hpp $(I)typeinf.hpp           \
                  $(I)ua.hpp $(I)xref.hpp ../arm_debmod.h ../arm_regs.hpp   \
                  ../common_local_impl.cpp ../common_stub_impl.cpp          \
                  ../deb_arm.hpp ../deb_pc.hpp ../debmod.h ../pc_debmod.h   \
                  ../pc_local_impl.cpp ../pc_regs.hpp linux_debmod.h        \
                  linux_local_impl.cpp linux_user.cpp linuxbase_debmod.h
$(F)linux_wait$(O): $(I)bytes.hpp $(I)ida.hpp $(I)idd.hpp $(I)ieee.h        \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)md5.h     \
                  $(I)nalt.hpp $(I)netnode.hpp $(I)network.hpp $(I)pro.h    \
                  $(I)range.hpp $(I)ua.hpp $(I)xref.hpp ../arm_debmod.h     \
                  ../arm_regs.hpp ../deb_arm.hpp ../deb_pc.hpp ../debmod.h  \
                  ../pc_debmod.h ../pc_regs.hpp linux_debmod.h              \
                  linux_wait.cpp linuxbase_debmod.h
$(F)linuxbase_debmod$(O): $(I)bytes.hpp $(I)diskio.hpp $(I)fpro.h           \
                  $(I)ida.hpp $(I)idd.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)md5.h $(I)nalt.hpp        \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)prodir.h    \
                  $(I)range.hpp $(I)ua.hpp $(I)xref.hpp ../arm_debmod.h     \
                  ../arm_regs.hpp ../deb_arm.hpp ../deb_pc.hpp ../debmod.h  \
                  ../pc_debmod.h ../pc_regs.hpp linuxbase_debmod.cpp        \
                  linuxbase_debmod.h
$(F)symelf$(O)  : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp $(I)diskio.hpp $(I)entry.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp                    \
                  $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)ieee.h            \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)md5.h $(I)nalt.hpp $(I)name.hpp        \
                  $(I)netnode.hpp $(I)network.hpp $(I)offset.hpp $(I)pro.h  \
                  $(I)range.hpp $(I)segment.hpp $(I)segregs.hpp $(I)ua.hpp  \
                  $(I)xref.hpp ../../ldr/elf/../idaldr.h                    \
                  ../../ldr/elf/common.cpp ../../ldr/elf/elf.h              \
                  ../../ldr/elf/elfbase.h         \
                            \
                           \
                              \
                          \
                          \
                       \
                          \
                             \
                          \
                            \
                           \
                        \
                           \
                   ../../ldr/elf/reader.cpp      \
                  ../debmod.h symelf.cpp symelf.hpp
