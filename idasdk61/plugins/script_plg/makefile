
!include ..\..\allmake.mak

PLGDIR=$(R)plugins

all: $(PLGDIR)\idcplugin.idc $(PLGDIR)\pyplugin.py

$(PLGDIR)\idcplugin.idc: idcplugin.idc
	$(CP) $? $@

$(PLGDIR)\pyplugin.py: pyplugin.py
	$(CP) $? $@

