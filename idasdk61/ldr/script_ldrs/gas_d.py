# GAS dump loader

import idaapi
from idc import *
import struct, string

"""
handle the following format:
# name: OFFSET_IMM regression
# as:
# objdump: -dr --prefix-addresses --show-raw-insn

.*: +file format .*arm.*

Disassembly of section .text:
0+0 <[^>]+> e51f0004 ?  ldr r0, \[pc, #-4\] ; 0+4 <[^>]+>
00000004 <.text\+0x4> f3ef 8000         mrs     r0, CPSR
"""

FormatName = "GAS test dump"

# -----------------------------------------------------------------------
def gets(li):
    s = ""
    while True:
        if len(s) > 10240:
            return None     # too long strings indicate failure
        c = li.get_char()
        if c == None or c == '\n':
            break
        s += c
    if s == "" and c != '\n':
        return None
    return s

# -----------------------------------------------------------------------
def ishex(s):
    for c in s:
       if not c in string.hexdigits: return False
    return True

# -----------------------------------------------------------------------
def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # we support only one format per file
    if n > 0:
        return 0

    while True:
        s = gets(li)
        if s == None:
            break
        s = s.strip()
        if len(s) == 0 or s.startswith("#") or s.startswith(".*: ") or s.startswith(" "):
            continue
        if s.startswith("Disassembly of "):
            idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
            return FormatName
        else:
            break

    # unrecognized format
    return 0

# -----------------------------------------------------------------------
def load_file(li, neflags, format):

    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if format == FormatName:
        idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
        chunk = ""
        while True:
            s = gets(li)
            if s == None:
                break
            # warning(s)
            if s.startswith("#") or s.startswith(" ") or s.startswith(".*: "):
                continue
            words = s.split()
            if len(words) > 2 and words[1].startswith('<') and words[1].endswith('>'):
                hex = words[2].decode('hex')
                chunk +=  hex[::-1]
                if ishex(words[3]) and len(words[3]) == len(words[2]):
                    hex = words[3].decode('hex')
                    chunk += hex[::-1]

        if len(chunk) == 0:
            return 0

        size = len(chunk)
        AddSeg(0, size, 0, 1, idaapi.saRelByte, idaapi.scPub)
        idaapi.put_many_bytes(0, chunk)
        print "Load OK"
        return 1

    Warning("Unknown format name: '%s'" % format)
    return 0

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    Warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0
