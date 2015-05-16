call cl32 -c -GX -D__NT__ -D__IDP__ -I../../include ugraph2.cpp
call cl32 -LD -Fe../../bin/plugins/mgraph.plw ugraph2.obj ../../libvc.w32/ida.lib /link /export:PLUGIN