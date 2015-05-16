
!include ..\..\allmake.mak

LDRDIR=$(R)loaders

all: $(LDRDIR)\bios_image.idc $(LDRDIR)\hppacore.idc $(LDRDIR)\wince.py $(LDRDIR)\pdfldr.py $(LDRDIR)\gas_d.py

$(LDRDIR)\bios_image.idc: bios_image.idc
	$(CP) $? $@

$(LDRDIR)\hppacore.idc: hppacore.idc
	$(CP) $? $@

$(LDRDIR)\wince.py: wince.py
	$(CP) $? $@

$(LDRDIR)\pdfldr.py: pdfldr.py
	$(CP) $? $@

$(LDRDIR)\gas_d.py: gas_d.py
	$(CP) $? $@
