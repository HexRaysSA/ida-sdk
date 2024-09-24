include ../../allmake.mak

SCRIPTS += ebc.py
SCRIPTS += msp430.py
SCRIPTS += proctemplate.py

BIN_PATH = $(R)procs/
GOALS += $(addprefix $(BIN_PATH),$(SCRIPTS))
all: $(GOALS)


$(BIN_PATH)%: %
	$(CP) $? $@

