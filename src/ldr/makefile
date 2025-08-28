include ../allmake.mak

GOALS += loaders
.PHONY: $(GOALS)
all: $(GOALS)

#----------------------------------------------------------------------
ALLDIRS += aif
ALLDIRS += amiga
ALLDIRS += aof
ALLDIRS += aout
ALLDIRS += dos
ALLDIRS += dump
ALLDIRS += geos
ALLDIRS += hex
ALLDIRS += intelomf
ALLDIRS += mas
ALLDIRS += nlm
ALLDIRS += pef
ALLDIRS += pilot
ALLDIRS += qnx
ALLDIRS += script_ldrs
ALLDIRS += w32run
ALLDIRS-$(IDAADV) += hpsom
ALLDIRS-$(IDAADV) += javaldr
ALLDIRS-$(IDAADV) += os9
ALLDIRS-$(IDAADV) += rt11
ALLDIRS-$(IDAADV) += snes
ALLDIRS += $(ALLDIRS-1)
loaders: $(ALLDIRS)

#----------------------------------------------------------------------
.PHONY: $(ALLDIRS)
$(ALLDIRS):
	$(Q)$(MAKE) -C $@

#----------------------------------------------------------------------
clean::
	$(foreach dir,$(ALLDIRS),$(MAKE) -C $(dir) clean;)
