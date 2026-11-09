include ../allmake.mak

GOALS += modules
.PHONY: $(GOALS)
all: $(GOALS)

#----------------------------------------------------------------------
ALLDIRS += 6502
ALLDIRS += 65816
ALLDIRS += 78k0
ALLDIRS += 78k0s
ALLDIRS += 80196
ALLDIRS += avr
ALLDIRS += c39
ALLDIRS += cr16
ALLDIRS += dsp56k
ALLDIRS += f2mc
ALLDIRS += fr
ALLDIRS += h8
ALLDIRS += h8500
ALLDIRS += hppa
ALLDIRS += i51
ALLDIRS += i860
ALLDIRS += i960
ALLDIRS += java
ALLDIRS += kr1878
ALLDIRS += m32r
ALLDIRS += m740
ALLDIRS += m7700
ALLDIRS += m7900
ALLDIRS += mn102
ALLDIRS += nec850
ALLDIRS += oakdsp
ALLDIRS += pdp11
ALLDIRS += pic
ALLDIRS += sam8
ALLDIRS += script
ALLDIRS += st20
ALLDIRS += st7
ALLDIRS += st9
ALLDIRS += tlcs900
ALLDIRS += tms320c1
ALLDIRS += tms320c3
ALLDIRS += tms320c5
ALLDIRS += tms320c54
ALLDIRS += tms320c55
ALLDIRS += xa
ALLDIRS += z8
ALLDIRS += z80
modules: $(ALLDIRS)

#----------------------------------------------------------------------
.PHONY: $(ALLDIRS)
$(ALLDIRS):
	$(Q)$(MAKE) -C $@

#----------------------------------------------------------------------
clean::
	$(foreach dir,$(ALLDIRS),$(MAKE) -C $(dir) clean;)
