
        IDA SDK - Interactive Disassembler Module SDK
        =============================================

        This SDK should be used with IDA kernel version 9.0

        This package allows you to write:
                - processor modules
                - input file loader modules
                - plugin modules
                  (including the processor module extension plugins)

        Please read through the entire file before continuing!

        Check also the IDA Pro book by Chris Eagle:

        http://www.idabook.com/

------------------------------------------------------------------------------


SUPPORTED COMPILERS
-------------------

  A compiler that fully supports C++11 is a requirement for this SDK.

  MS Windows:
    - Visual C++ 2019 (16.0) or later

  Linux:
    - GNU C++ compiler
    - LLVM/Clang C++ compiler

  Mac OS X (SDK 10.14 or later):
    - GNU C++ compiler
    - LLVM/Clang C++ compiler

  Other compilers might work but are not supported officially.


HEADERS
-------

        A quick tour on IDA's header files:

pro.h           This is the first header included in the IDA project.
                It defines the most common types, functions, and data.
                It also contains compiler- and platform-related definitions.

ida.hpp         In this file the 'inf' structure is defined: it keeps all
                parameters of the disassembled file.

idp.hpp         The 'main' header file for IDP modules.
                Contains definition of the interface to IDP modules.
                The interface consists of 2 structures:
                  processor_t - description of processor
                  asm_t       - description of assembler
                Each IDP has one processor_t and several asm_t structures.

loader.hpp      Definitions of IDP, LDR, and PLUGIN module interfaces.
                This file also contains:
                  - functions to load files into the database
                  - functions to generate output files
                  - high level functions to work with the database
                    (open, save, close)

ua.hpp          Functions that deal with the disassembling of program
                instructions.
                Disassembly of an instruction is made in three steps:
                  - analysis
                  - emulation
                  - conversion to text

kernwin.hpp     Defines the interface between the kernel and the UI.
                Some string processing functions are also kept in this header.

idd.hpp         Debugger plugin API for debugger module writers.
                Contains definition of the interface to IDD modules.

bytes.hpp       Functions and definitions used to describe and manipulate each
                byte of the disassembled program.
                Information about the byte includes associated features
                (comments, names, references, etc), data types (dword, qword,
                string literal, etc), instruction operands, status (mapped,
                loaded, patched, etc), among others.

netnode.hpp     Functions that provide the lowest level public interface to
                the database. Modules can use this to keep some private
                information in the database. A description of the concept is
                available in the header file itself.

allins.hpp      List of instructions available from all processor modules.

auto.hpp        Auto-analysis related functions.

compress.hpp    Data compression functions.

config.hpp      Functions that deal with configuration options and files.

dbg.hpp         Contains functions to control the debugging of a process.

diskio.hpp      File I/O functions for IDA.
                You should not use standard C file I/O functions in modules.
                Use functions from this header, pro.h, and fpro.h instead.

entry.hpp       Functions that deal with entry points to the program being
                disassembled.

err.h           Thread safe functions that deal with error codes.

expr.hpp        Functions that deal with C-like expressions, external
                languages, and the built-in IDC language.

fixup.hpp       Functions that deal with fixup (relocation) information.

fpro.h          System independent counterparts of file I/O functions.
                These functions do check errors but never exit even if an
                error occurs.
                They return extended error code in qerrno variable.

                NOTE: You must use these functions instead of the C standard
                      I/O functions.

frame.hpp       Routines to manipulate function stack frames, stack variables,
                register variables and local labels.

funcs.hpp       Routines for working with functions within the disassembled
                program. This file also contains routines for working with
                library signatures (e.g. FLIRT).

gdl.hpp         Low level graph drawing operations.

graph.hpp       Graph view management.

help.h          Help subsystem. This subsystem is not used in IDP files.
                We put it just in case.

idalib.hpp      Functions that allow you to use with IDA as a library

ieee.h          IEEE floating point functions.

intel.hpp       Header file from the IBM PC module. For information only.
                It will not compile because it contains references to
                internal files!

lex.hpp         Tools for parsing C-like input.

lines.hpp       High level functions that deal with the generation of the
                disassembled text lines.

nalt.hpp        Definitions of various information kept in netnodes.
                These functions should not be used directly since they are
                very low level.

moves.hpp       Functions and classes related to location history.

name.hpp        Functions that deal with names (setting, deleting, getting,
                validating, etc).

offset.hpp      Functions that deal with offsets.

problems.hpp    Functions that deal with the list of problems.

prodir.h        Low level functions to find files in the file system.
                It is better to use enumerate_files2() from diskio.hpp.

pronet.h        Network related functions.

range.hpp       Contains the definition of the 'range_t' class.
                This is a base class used by many parts of IDA, such as the
                'segment_t' and 'segreg_range_t' (segment register) classes.

registry.hpp    Registry related functions.
                IDA uses the registry to store global configuration options
                that must persist after IDA has been closed.

segment.hpp     Functions that deal with program segmentation.

segregs.hpp     Functions that deal with the segment registers.
                If your processor doesn't use segment registers, then you
                don't need this file.

strlist.hpp     Functions that deal with the strings list.

typeinf.hpp     Describes the type information records in IDA.

xref.hpp        Functions that deal with cross-references.


All functions usable in the modules are marked by the "ida_export" keyword.
There are some exported functions that should be not used except very cautiously.
For example, set_nalt_cmt() and many functions from nalt.hpp should be avoided.
In general, try to find a high-level counterpart of the function in these cases.

Naturally, all inline functions from the header files can be used too.


LIBRARIES
---------

  This SDK provides import and stub libraries to link against the IDA kernel.

  For MS Windows targets, import libraries are provided in:
    x64_win_vc_32/ida.lib               Visual C++ import libraries for IDA32
    x64_win_vc_64/ida.lib               Visual C++ import libraries for IDA64

  For Linux and Mac OS X targets, you may link directly to the shared library
  of the IDA kernel (libida[_64].so or libida[_64].dylib), but stub libraries
  are also provided to simplify building of the SDK.

  For Linux targets, stub libraries are provided in:
    x64_linux_gcc_32/libida.so          LLVM/GCC stub libraries for IDA32
    x64_linux_gcc_64/libida64.so        LLVM/GCC stub libraries for IDA64

  For Mac OS X targets, stub libraries are provided in:
    x64_mac_gcc_32/libida.dylib         LLVM/GCC stub libraries for IDA32
    x64_mac_gcc_64/libida64.dylib       LLVM/GCC stub libraries for IDA64

  To build the debugger servers, the 'dumb' object are needed. These files are
  provided for the following architectures:

    x86_win_vc_32     Visual C++ libraries for building 32-bit Windows debugger server
    x86_win_vc_64     Visual C++ libraries for building 64-bit Windows debugger server
    x86_linux_gcc_32  GCC libraries for building 32-bit Linux debugger server
    x86_linux_gcc_64  GCC libraries for building 64-bit Linux debugger server
    x86_mac_gcc_32    GCC libraries for building 32-bit Mac debugger server
    x86_mac_gcc_64    GCC libraries for building 64-bit Mac debugger server

  NOTE: To build the debug servers for MS Windows targets, Microsoft Windows
        SDK v7.1A must be used.

  If you want to compile the Qt plugin sample, you will also need the libQt*
  libraries. For MS Windows targets, the import libraries for Qt are available
  in the x64_win_qt directory. For Linux and Mac OS X targets, you should link
  against the Qt libraries from the IDA directory.


DESCRIPTION OF PROCESSOR MODULES
--------------------------------

    The module disassembles an instruction in several steps:
       - analysis (decoding)           file ana.cpp
       - emulation                     file emu.cpp
       - output                        file out.cpp

    The analyser (ana.cpp) should be fast and simple: just decode an
    instruction into an 'insn' structure. The analyser will always be called
    before calling emulator and output functions. If the current address
    can't contain an instruction, it should return 0. Otherwise, it returns
    the length of the instruction in bytes.

    The emulator performs the following tasks:
      - creates cross-references
      - plans to disassemble subsequent instructions
      - creates stack variables (optional)
      - tries to keep track of register contents (optional)
      - provides better analysis method for the kernel (optional)
      - etc

    The outputter produces a line (or lines) that will be displayed on the
    screen.
    It generates only essential parts of the line: line prefix, comments, and
    cross-references will be generated by the kernel itself.
    To generate lines, you should subclass the outctx_t structure from ua.hpp.

makefile        - makefile for a processor module
stub            - MSDOS stub for the module
ana.cpp         - analysis of an instruction: fills the insn structure.
emu.cpp         - emulation: creates xrefs, plans to analyse subsequent
                  instructions
ins.cpp         - table of instructions.
out.cpp         - generate source lines.
reg.cpp         - description of processor, assemblers, and notify() function.
                  This function is called when certain events occur. You may
                  want to have some additional processing of those events.
idp.def         - the module description for the linker.
i51.hpp         - local header file. you may have another header file for
                  you module.
ins.hpp         - list of instructions.


SDK BUILD INSTRUCTIONS
----------------------

  To build the SDK using the command line on all systems (MS Windows, Linux,
  and Mac OS X), refer to:
    - install_make.txt

  For explanations on how to use the Visual C++ IDE with the SDK, refer to:
    - install_visual.txt


------------------------------------------------------------------------------

        And finally:

  We recommend to study the samples, compile and run them.
  The SDK comes with many samples and the source code for MS Windows,
  Mac OS X, and Linux debugger modules.

  Limitations on the modules:

        - for the dynamic memory allocation: please use qalloc/qfree()
          while you are free to use any other means, these functions
          are provided by the kernel and everything allocated by the
          kernel should be deleted using qfree()

        - for the file I/O: never use functions from stdio.h.
          Use functions from fpro.h instead.
          If you still want to use the standard functions, never pass
          FILE* pointer obtained from the standard functions to the kernel
          and vice versa.

        - the exported descriptor names are fixed:
                processor module        LPH
                loader module           LDSC
                plugin module           PLUGIN

  Usually a new processor module is written in the following way:

        - copy the sample module files to a new directory
        - edit ins.cpp and ins.hpp files
        - write the analyser ana.cpp
        - then outputter
        - and emulator (you can start with an almost empty emulator)
        - and describe the processor & assembler, write the notify() function

  Naturally, it is easier to copy and to modify example files than to write
  your own files from scratch.

  Debugging:

  You can use the following debug print functions:
        deb() - display a line in the messages window if -z command
                line switch is specified. You may use debug one of:
                IDA_DEBUG_IDP, IDA_DEBUG_LDR, IDA_DEBUG_PLUGIN
        msg() - display a line in the messages window
        warning() - display a dialog box with the message

  To stop in the debugger when the module is loaded, you may use the
  BPT macro construct in the module initialization code.

  BTW, you can save all lines appearing in the messages window to a file.
  Just set an enviroment variable:

        set IDALOG=ida.log

  We always have this variable set, it is very helpful.

  Support for the SDK is not included in the IDA Pro purchase but
  you can subscribe for the extended SDK support:

        http://www.hex-rays.com/products/ida/order.shtml
