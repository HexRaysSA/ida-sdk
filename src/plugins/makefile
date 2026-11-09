include ../allmake.mak

GOALS += plugins
GOALS += samples
ifeq ($(or $(IDAHOME),$(DEMO_OR_FREE)),)
  GOALS += examples
endif
GOALS += training_subdir # -*
.PHONY: $(GOALS)
all: $(GOALS)

#----------------------------------------------------------------------
PLUGINS += callee
PLUGINS += callgraph
PLUGINS += choose
PLUGINS += findcrypt2
PLUGINS += ht_output
PLUGINS += ht_view
PLUGINS += pdb
PLUGINS += tracing_api
PLUGINS += uiswitch
PLUGINS-$(__NT__) += uunp
ifeq ($(or $(IDAHOME),$(DEMO_OR_FREE)),)
  PLUGINS += mex1
  PLUGINS += mex2
  PLUGINS += mex3
  PLUGINS += mex4
  PLUGINS += cvt64_sample
endif
PLUGINS += $(PLUGINS-1)
plugins: $(PLUGINS)

#----------------------------------------------------------------------
SAMPLES += custdata
SAMPLES += custview
SAMPLES += formchooser
SAMPLES += formsample
SAMPLES += funclist
SAMPLES += getlines
SAMPLES += hexview
SAMPLES += mtsample
SAMPLES += openform
SAMPLES += procext
SAMPLES += ugraph
SAMPLES += ugraph3
SAMPLES += vcsample
samples: $(SAMPLES)

#----------------------------------------------------------------------
# Note: examples are not installed in the plugins/ directory by default.
#       to install them there, run 'make' from the plugin subdirectory.
#       to uninstall the plugin afterwards, run 'make uninstall' from
#       the plugin subdirectory or 'make examples_uninstall' from the
#       'plugins' directory.
HAS_QT := $(call ls,$(QTDIR))
EXAMPLES += ex_debidc
EXAMPLES += ex_events1
EXAMPLES += script_plg
EXAMPLES-$(HAS_QT) += qproject
EXAMPLES-$(HAS_QT) += qwindow
# do not include ugraph2 in the samples because it is buggy:
# in some cases it combines blocks in such a way that switching to
# graph view becomes impossible
EXAMPLES += ugraph2
# the z80dbg plugin will conflict with functionality already submitted
# to the z80 processor module, so we don't install it
EXAMPLES += z80dbg
EXAMPLES += $(EXAMPLES-1)
examples: $(EXAMPLES)

#----------------------------------------------------------------------

#----------------------------------------------------------------------
.PHONY: $(PLUGINS) $(SAMPLES) $(EXAMPLES)
$(PLUGINS) $(SAMPLES) $(EXAMPLES):
	$(Q)$(MAKE) -C $@

#----------------------------------------------------------------------
clean::
	$(foreach dir,$(PLUGINS) $(SAMPLES) $(EXAMPLES),$(MAKE) -C $(dir) clean;)
