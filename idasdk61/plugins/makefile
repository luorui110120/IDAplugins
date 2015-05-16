!include ../allmake.mak

ALLDIRS=choose2 getlines funclist procext vcsample uunp pdb subwindow ugraph \
        custdata custview extlang formsample hello mtsample script_plg ugraph2 \
        ugraph3 uiswitch callee debugger findcrypt2 highlighter callgraph

!if !$d(__X64__)
!if $d(__NT__) && !$d(NO_KERNEL)
ALLDIRS=$(ALLDIRS) chart
!endif
!endif


.PHONY: $(ALLDIRS)

all:    $(ALLDIRS)

!include ../alldirs.mk

$(R)plugins\plugins.cfg: plugins.cfg
        @if not exist "$(R)plugins$(CHKDIR)" mkdir $(R)plugins
        $(CP) $? $@
