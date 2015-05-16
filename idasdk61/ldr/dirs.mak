_CFLAGS=-Ipe

ALLDIRS=w32run aout hex nlm aif aof \
        pilot dos pef qnx javaldr rt11 os9 amiga \
        hpsom geos dump intelomf mas \
        script_ldrs $(ADDITIONAL_LOADERS)

.PHONY: $(ALLDIRS)

all:    $(ALLDIRS)