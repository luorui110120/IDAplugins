        IDA SDK - Interactive Disassembler Module SDK
        =============================================

        This SDK should be used with IDA kernel version 6.1

        This package allows you to write:
                - processor modules
                - input file loader modules
                - plugin modules (including the
                   processor module extension plugins)

        Please read read through whole file before continuing!

        A nice tutorial on IDA SDK is available on this site:

        http://www.binarypool.com/idapluginwriting

-----------------------------------------------

        What you need:

To create 32bit or 64bit Win32 modules:    Borland C++ Builder >= 5.0
                                        or free BCC v5.5
                                        or Visual C++ >= v6.0
                                        or GNU C++ compiler

To create 32bit or 64bit Linux modules:    GNU C++ compiler
To create 32bit or 64bit Mac OS X modules: GNU C++ compiler

The Visual C++ users should refer to install_visual.txt for the explanations on
how to install.

The C++ Builder visual environment users should refer to install_cb.txt for the
explanations on how to install (Note: plugins that use VCL are deprecated and
their support will be removed in future versions).

For installation under Linux or OS X, please refer to install_linux.txt

All others should refer to install_make.txt.

-----------------------------------------------

        A quick tour on header files:


ida.hpp                 the 'main' header file of IDA project.
                        This file should be included in all source files.
                        In this file the 'inf' structure is
                        defined: it keeps all parameters of the disassembled
                        file.

kernwin.hpp             various functions to interact with the user.
                        Also, some functions to process strings are kept in
                        this header.

ua.hpp                  This header file describes insn_t structure called
                        cmd: this structure keeps a disassembled instruction
                        in the internal form. Also, you will find here
                        helper functions to create output lines etc.

idp.hpp                 the 'main' header file of IDP modules.
                        2 structures are described here:
                          processor_t - description of processor
                          asm_t       - description of assembler
                        Each IDP has one processor_t and several asm_t structures

area.hpp                class 'area'. This class is a base class for
                        'segment_t' and 'srarea_t' (segment register) classes.
                        This class keeps information about various areas
                        of the disassembled file.

auto.hpp                auto-analysis related functions

bytes.hpp               Functions and definitions which describe each byte
                        of the disassembled program: is it an instruction,
                        data, operand types etc.

dbg.hpp                 Debugger API for debugger users

diskio.hpp              file i/o functions
                        See file pro.h and fpro.h for additional system functions

entry.hpp               List of entry points to the program being
                        disassembled.

enum.hpp                Enumeration types in the disassembled program

expr.hpp                IDC language functions.

fixup.hpp               information about relocation table of the program.

fpro.h                  Alternative set of system-indenendent file i/o
                        functions. These functions do check errors but never
                        exit even if an error occurs. They return extended
                        error code in qerrno variable.
                        You must use these functions, not functions from
                        stdio.h

frame.hpp               Local variables, stack pointer related stuff

funcs.hpp               Functions in the disassembled program

help.h                  Help subsystem. This subsystem is not used in
                        IDP files. We put it just in case.

idd.hpp                 Debugger plugin API for debugger module writers

ieee.h                  IEEE floating point functions

intel.hpp               header file from the ibm pc module.
                        for information only, it will not compile
                        because it contains references to internal files!

ints.hpp                predefined comments

lines.hpp               generation of source (assembler) lines and long
                        comment lines. variables controlling the exact time
                        and place to generate xrefs, indented comments etc.
                        shouldn't be used in simple IDP modules.
                        You must use these function instead of functions
                        from stdlib.h


nalt.hpp                some predefined netnode array indexes used by the
                        kernel. these functions should not be used directly
                        since they are very low level.

name.hpp                names: rename, unname bytes etc.

netnode.hpp             the lowest level of access to the database. Modules
                        can use this level to keep some private inforation
                        in the database. Here is a short description of
                        the concept:
                          the database consists of 'netnodes'.
                          The netnodes are numbered by 32-bit integers
                          and may have:
                            - a name (max length is MAXNAMESIZE-1)
                            - a value (a string)
                            - sparse arrays of values:
                              Each sparse array has a 8-bit tag. Therefore,
                              we can have 256 sparse arrays in one netnode.
                              Only non-zero elements of the arrays are stored in
                              the database. Arrays are indexed by 32-bit or 8-bit
                              indexes. You can keep any type of information in
                              an array element. The size of an element is limited
                              by MAXSPECSIZE. For example, you could have an
                              array of addresses that have been patched by the user:

                              <address> : <old_value_of_byte>

                              The array is empty at the start and will
                              grow as the user patches the input file.

                              There are 2 predefined arrays:

                                - strings       (supval)
                                - longs         (altval)

                              The arrays don't need to be declared or created
                              specially. They implicitly exist at each node.
                              To save something into an array simply write
                              to the array element (altset or supset functions)
                        There are no limitations on the size or number of
                        netnode arrays.
offset.hpp              functions that work with offsets.

pro.h                   compiler related stuff and some system-independent functions

queue.hpp               queue of problems.

segment.hpp             program segmentation
srarea.hpp              segment registers. If your processor doesn't have
                        segment registers, you don't need this file.
struct.hpp              Structure types in the disassembled program

typeinf.hpp             Type information

va.hpp                  Virtual array. Used by other parts of IDA.
                        IDP module don't use it directly.
vm.hpp                  Virtual memory. Used by other parts of IDA.
                        IDP module don't use it directly.
xref.hpp                cross-references.


All functions usable in the modules are marked by the "ida_export" keyword.
There are some exported functions that should be not used except very cautiously.
For example, setFlags() and many functions from nalt.hpp should be avoided.
In general, try to find a high-level counterpart of the function in these cases.

Naturally, all inline functions from the header files can be used too.

LIBRARIES
-----------------------------------------------

ida.lib  - import library with all exported functions (MS Windows: bcc,vs)
ida.a    - import library with all exported functions (GNU C++)

  There are several different versions of this file, one for each platform.
  The following subdirectories with library files exist under "lib":

  x86_win_bcc_32   Borland libraries for IDA32 under MS Windows
  x86_win_bcc_64   Borland libraries for IDA64 under MS Windows
  x86_win_gcc_32   GCC libraries for IDA32 under MS Windows
  x86_win_gcc_64   GCC libraries for IDA64 under MS Windows
  x86_linux_gcc_32 GCC libraries for IDA32 under Linux
  x86_mac_gcc_32   GCC libraries for IDA32 under Mac OS X
  x86_linux_gcc_64 GCC libraries for IDA64 under Linux
  x86_mac_gcc_64   GCC libraries for IDA64 under Mac OS X
  x86_win_vc_32    Visual Studio libraries for IDA32 under MS Windows
  x86_win_vc_64    Visual Studio libraries for IDA64 under MS Windows

  x64_win_vc_64     Visual Studio libraries for building 64-bit Windows debugger serber
  x64_linux_gcc_64  GCC libraries for building 64-bit Linux debugger serber
  x64_mac_gcc_64    GCC libraries for building 64-bit Mac debugger serber

  There are no ida.a libraries for Linux or OS X, since you can link directly
  to the shared library of the IDA kernel (libida.so or libida.dylib).
  This shared library comes with IDA itself (not with the SDK). Copy it
  into the bin directory of the SDK or the corresponding lib subdirectory.
  If you want to compile the Qt plugin sample, you will also need
  libQt* libraries from IDA directory. For Windows they are in x86_win_qt.


DESCRIPTION OF PROCESSOR MODULES
--------------------------------

     The module disassembles an instruction in several steps:
        - analysis (decoding)           file ana.cpp
        - emulation                     file amu.cpp
        - output                        file out.cpp

     The analyser (ana.cpp) should be fast and simple: just decode an
     instruction and fill the 'cmd' structure. The analyser will always be called
     before calling emulator and output functions. If the current address
     can't contain an instruction, it should return 0. Otherwise, it returns
     the length of the instruction in bytes.

     The emulator and outputter should use the contents of the 'cmd' array.
     The emulator performs the following tasks:
        - creates cross-references
        - plans to disassemble subsequent instructions
        - create stack variables (optional)
        - tries to keep track of register contents (optional)
        - provides better analysis method for the kernel (optional)
        - etc

     The outputter produces a line (or lines) that will be displayed on
     the screen.
     It generates only essential part of the line: line prefix, comments,
     cross-references will be generated by the kernel itself.
     To generate a line, MakeLine() or printf_line() should be used.

makefile        - makefile for a processor module
                  The DESCRIPTION line
                  should contain names of processors handled by this IDP
                  module, separated by colons. The first name is description
                  of whole module (not a processor name).
stub            - MSDOS stub for the module
ana.cpp         - analysis of an instruction: fills the cmd structure.
emu.cpp         - emulation: creates xrefs, plans to analyse subsequent
                  instructions
ins.cpp         - table of instructions.
out.cpp         - generate source lines.
reg.cpp         - description of processor, assemblers, and notify() function.
                  This function is called when certain events occur. You
                  may want to have some additional processing of those events.
idp.def         - the module description for the linker.
i51.hpp         - local header file. you may have another header file for
                  you module.
ins.hpp         - list of instructions.

-----------------------------------------------

        And finally:

  We recommend to study the samples, compile and run them.
  The SDK comes with many sample and the source code for Mac OS X and
  Linux debugger modules.

  Limitations on the modules:

        - for the dynamic memory allocation: please use qalloc/qfree()
          while you are free to use any other means, these functions
          are provided by the kernel and everything allocated by the
          kernel should be deleted using qfree()

        - for the file i/o: never use functions from stdio.h.
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
        - edit INS.CPP and INS.HPP files
        - write the analyser ana.cpp
        - then outputter
        - and emulator (you can start with an almost empty emulator)
        - and describe the processor & assembler, write the notify() function

  Naturally, it is easier to copy and to modify example files than to write
  your own files from the scratch.

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

  The SDK support is not included in the IDA Pro purchase but
  you can subscribe for the extended SDK support:

        http://www.hex-rays.com/idapro/idaorder.htm

-----------------------------------------------------
Information on the compilers
-----------------------------------------------------

Microsoft:
----------
.NET framework SDK (free, for CL.EXE, LINK.EXE)
  + .NET framework (free, only to install .NET framework SDK)
  + Platform SDK (free, for NMAKE.EXE):
      Core SDK - build environment (for NMAKE.EXE and C headers)
  downloads at:
    www.microsoft.com/italy/msdn/download/frameworksdk.asp
    www.microsoft.com/msdownload/platformsdk/sdkupdate/

Visual Studio Express (free)
  downloadable from Microsoft


Borland:
--------
BCC 5.5 (free)
  download from www.borland.com/bcppbuilder/freecompiler/

Borland C++ Builder v4.0, v5.0, v6.0 (commercial)
  unfortunately, more recent versions are too buggy to be used


GNU:
----
MinGW (free) + MSYS (free, needed for GNU MAKE)
  download at http://www.mingw.org/

CYGWIN (free)
  download at http://www.cygwin.com/


