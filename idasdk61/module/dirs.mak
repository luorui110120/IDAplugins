
DIRS32=6502 78k0 78k0s 80196                                                   \
       avr                                                                     \
       c39 cr16                                                       \
       dsp56k                                                                  \
       f2mc                                                                    \
       fr h8 h8500 hppa                                                        \
       i51 i860 i960                                                           \
       java                                                                    \
       kr1878                                                                  \
       m32r m740 m7700 m7900 mn102                                             \
       oakdsp								       \
       pdp11 pic                                                               \
       sam8 st7 st9 st20                                                       \
       tlcs900                                                                 \
       tms320c3 tms320c5 tms320c54 tms320c55 tms320c6                          \
       xa                                                                      \
       z8 z80 nec850

# We continue to compile 32-bit versions of the modules for 64-bit processors
# at least for MS Windows because of the existing old databases.

ALLDIRS=$(DIRS32)

.PHONY: $(ALLDIRS)

all:    $(ALLDIRS)

