IDA Processor module: SAM8

This is a processor module for Samsung SAM8-based microcontrollers

It supports the SAMA assembler available from http://www.cnatech.com/. 
The SAM8 has certain features that require extra support when generating 
ASM files. The accompanying "samaout" plugin should be used to generate 
valid ASM files for the SAMA assembler.

The module will create two segments, "cmem" and "emem". 

The cmem segment contains "code memory", and will occupy addresses 
0 -> 0x10000. 

The emem segment contains "external data memory", and will occupy addresses
0x800000->0x810000. Since external data memory occupies the same address 
range as code memory, the module will remap external data accesses into the 
emem segment. The samaout plugin will convert any names in the emem 
segment into EQU definitions at the start of the outputted file.

test.asm contains (hopefully) all possible instructions supported by this 
processor, for unit testing purposes.

Andrew de Quincey
adq@tardis.ed.ac.uk



Release history
---------------

0.1	Initial release
