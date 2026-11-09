
The following processor modules are present in the SDK:

6502
78k0            Thanks to Sergey Miklin
78k0s           Thanks to Sergey Miklin
80196
avr
c39             Thanks to Konstantin Norvatoff
cr16            Thanks to Konstantin Norvatoff
dsp56k          Thanks to Datarescue/Miloslaw Smyk/Ivan Litvin
f2mc
fr
h8
h8500
hppa
i51
i860
i960
java            Thanks to Yury Haron
kr1878          Thanks to Ivan Litvin
m32r
m740
m7700
m7900           Thanks to Sergey Miklin
mn102           Thanks to Konstantin Norvatoff
pdp11           Thanks to Yury Haron
pic
sam8            Thanks to Andrew de Quincey
st20
st7
st9
tlcs900         Thanks to Konstantin Norvatoff
tms320c1        Thanks to Jeremy Cooper
tms320c3        Thanks to Ivan Litvin
tms320c5
tms320c54
tms320c55
tms320c6
xa              Thanks to Petr Novak
z8
z80

To compile them, just start make:

        make -D__NT__

or under linux:

        idamake.pl

The 64-bit versions are compiled as usual: you have to define the __EA64__
environment symbol for make.
