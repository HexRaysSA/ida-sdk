
This directory contains the source of code a few file loaders:

aif     ARM Image File
amiga   Amige Hunk File
aof     ARM Object File
aout    a.out
dos     MS DOS File
dump    Memory Dump File
geos    GEOS File
hex     Intel/Motorola HEX File
hpsom   HP SOM
intelomf Intel Object File
javaldr  Java Class Loader
mas     Macro Assembler
nlm     Netware Loader Module
os9     FLEX/9
pef     Portable Executable Format (MAC)
pilot   Palm Pilot
qnx     Qnx
rt11    RT/11
w32run  Watcom RUN32

Compile them as usual (see how to compile processor modules, for example)

A note about 32-bit loaders for ida64: since ida64 assumes
64-bit applications by default, the loaders for 32-bit applications
should explicitly set the application bitness using inf_set_64bit(false).