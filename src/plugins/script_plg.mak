
ifdef EXAMPLE
  BIN_PATH = $(R)plugins-examples/
else
  BIN_PATH = $(R)plugins/
endif

INSTALLED_SCRIPTS = $(addprefix $(BIN_PATH), $(SCRIPTS))

all: $(INSTALLED_SCRIPTS)

$(BIN_PATH)%.py: %.py
	$(Q)$(CP) $? $@
$(BIN_PATH)%.idc: %.idc
	$(Q)$(CP) $? $@

.PHONY: uninstall
uninstall::
	rm -rf $(INSTALLED_SCRIPTS)

