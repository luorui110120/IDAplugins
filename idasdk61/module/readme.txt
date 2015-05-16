
The following processor modules are present in the SDK:

6502
78k0            Thanks to Sergey Miklin <miklin@diakom.ru>
78k0s           Thanks to Sergey Miklin <miklin@diakom.ru>
80196           Thanks to
avr
c39             Thanks to Konstantin Norvatoff, <konnor@bk.ru>
cr16            Thanks to Konstantin Norvatoff, <konnor@bk.ru>
dsp56k          Thanks to Datarescue/Miloslaw Smyk/Ivan Litvin <ltv@microset.ru>
f2mc
fr
h8
h8500
hppa
i51
i860
i960
java            Thanks to Yury Haron <yjh@styx.cabel.net>
kr1878          Thanks to Ivan Litvin <ltv@microset.ru>
m32r
m740
m7700
m7900           Thanks to Sergey Miklin <miklin@diakom.ru>
mn102           Thanks to Konstantin Norvatoff, <konnor@bk.ru>
pdp11           Thanks to Yury Haron <yjh@styx.cabel.net>
pic
sam8            Thanks to Andrew de Quincey <adq@lidskialf.net>
st20
st7
st9
tlcs900         Thanks to Konstantin Norvatoff, <konnor@bk.ru>
tms320c3        Thanks to Ivan Litvin <ltv@microset.ru>
tms320c5
tms320c54
tms320c55
tms320c6
xa              Thanks to Petr Novak <Petr.Novak@i.cz>
z8              Thanks to
z80

To compile them, just start make:

        make -D__NT__

or undef linux:

        idamake.pl

The 64-bit versions are compiled as usual: you have to define the __EA64__
environment symbol for make.