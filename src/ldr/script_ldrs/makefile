
include ../../allmake.mak

LDRDIR = $(R)loaders

LOADERS += archldr_tar.py
LOADERS += bios_image.py
LOADERS += esp.py
LOADERS += pdfldr.py
LOADERS += uimage.py
LOADERS += wince.py
LOADERS += md1img.py
LOADERS-$(IDAADV) += hppacore.idc

LOADERS += $(LOADERS-1)

SUPPS += esp

all: $(addprefix $(LDRDIR)/, $(LOADERS)) supps

$(LDRDIR)/%.idc: %.idc
	$(CP) $? $@

$(LDRDIR)/%.py: %.py
	$(CP) $? $@

supps: $(SUPPS)
	$(CP) -r $^ $(LDRDIR)

clean::
	rm -f $(addprefix $(LDRDIR)/, $(LOADERS))
	rm -rf $(addprefix $(LDRDIR)/, $(SUPPS))
