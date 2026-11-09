
# This file is included by:
#   - ldr/loader.mak
#   - module/module.mak
#   - plugins/plugin.mak

ifdef __LINT__
  # Info 785 Too few initializers for aggregate
  CFLAGS += -e785
endif

#----------------------------------------------------------------------
# include allmake.mak and prepare default goal if needed
ifndef NO_DEFAULT_TARGETS
  include $(RD)../../allmake.mak

  # prepare targets
  GOALS += modules
  GOALS += $(addprefix $(RI),$(IDCS))
  GOALS += configs
  all: $(GOALS)

  # create default target and add it to the list of targets
  ifdef BUILD_STATIC_LIBRARY
    DEFAULT_TARGET = $(L)$(PROC)$(A)
    STATIC_LIBS += $(DEFAULT_TARGET)
  else
    DEFAULT_TARGET = $(call module_dll,$(PROC))
    MODULES += $(DEFAULT_TARGET)
  endif

  # create lists of object files for default target (shared or static)
  OBJS += $(BASE_OBJS)
  OBJS += $(call objs,$(foreach n,1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16,$(O$(n))))
  $(DEFAULT_TARGET): MODULE_OBJS += $(OBJS)
  # object file dependencies must be explicitly added to each module
  $(DEFAULT_TARGET): $(OBJS)
endif

#----------------------------------------------------------------------
# prepare ldflags for all modules
MODULE_LDFLAGS += $(OUTMAP)$(F)$(@F).map
ifdef __LINUX__
  DEFFILE ?= $(SRC_PATH)exports.def
  MODULE_LDFLAGS += -Wl,--version-script=$(DEFFILE) -Wl,-rpath='$$ORIGIN/..' -z origin
else ifdef __MAC__
  INSTALL_NAME ?= $(@F)
  MODULE_LDFLAGS += -Wl,-install_name,$(INSTALL_NAME)
endif

#----------------------------------------------------------------------
# main rule for modules
.PHONY: modules
modules: $(MODULES) $(STATIC_LIBS)

# shared libraries
$(MODULES): LDFLAGS += $(MODULE_LDFLAGS)
$(MODULES): $(LIBS) $(IDALIB) $(MAKEFILE_DEP) $(DEFFILE)
	$(call link_dll, $(MODULE_OBJS), $(LIBS) $(LINKIDA))
ifdef __NT__
  ifndef DONT_ERASE_LIB
	$(Q)$(RM) $(@:$(DLLEXT)=.exp) $(@:$(DLLEXT)=.lib)
  endif
endif
	$(CHECKSYMS_CMD)
	$(POSTACTION)

# static libraries
$(STATIC_LIBS): $(call lib, $(MODULE_OBJS))

#----------------------------------------------------------------------
# auxiliary rules
CFG_CONFIGS = $(addprefix $(C),$(CONFIGS))
configs: $(CFG_CONFIGS)

$(RI)%.idc: %.idc
	$(CP) $? $@

#----------------------------------------------------------------------
# removes installed binaries from the $(BIN_PATH)/ directory
.PHONY: uninstall
uninstall::
	rm -rf $(MODULES) $(STATIC_LIBS)

#----------------------------------------------------------------------
include $(IDA)objdir.mak
